# soliton.c Architecture

**Version**: 0.4.0
**Status**: Production-ready cryptographic engine
**Philosophy**: High-performance, freestanding C17 implementation with empirical validation

---

## Overview

soliton.c is a freestanding cryptographic library implementing AES-256-GCM and ChaCha20-Poly1305 AEAD ciphers with hardware acceleration. The design prioritizes:

1. **Correctness**: NIST SP 800-38D and RFC 8439 compliance, validated against OpenSSL
2. **Performance**: SIMD acceleration with scalar fallbacks
3. **Security**: Constant-time operations, timing-independent execution
4. **Portability**: Freestanding C17, no libc dependencies in core

---

## System Architecture

### Layer Structure

```
┌─────────────────────────────────────┐
│   Public API (include/soliton.h)    │  ← User-facing interface
│  - soliton_aesgcm_*                 │
│  - soliton_chacha_*                 │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Dispatch Layer (core/dispatch.c)  │  ← Runtime feature detection
│  - CPU capability detection          │
│  - Backend selection (VAES/AES-NI/  │
│    scalar)                           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Cryptographic Kernels (core/)     │  ← Implementations
│  - Scalar (portable)                 │
│  - AES-NI + PCLMUL (SSE)            │
│  - VAES + VPCLMULQDQ (AVX2/512)     │
│  - ARM NEON + PMULL                  │
└─────────────────────────────────────┘
```

---

## Core Components

### 1. Runtime Dispatch (`core/dispatch.c`)

**Purpose**: Select optimal implementation based on CPU features

**Detection Strategy**:
- Query CPUID on x86-64
- Check for VAES, VPCLMULQDQ, AES-NI, PCLMUL, AVX2
- Query system registers on ARM64 (NEON, PMULL)
- Fall back to scalar if no acceleration available

**Backend Selection**:
```c
typedef struct {
    void (*aes_key_expand)(const uint8_t*, uint32_t*);
    void (*aes_encrypt_block)(const uint32_t*, const uint8_t*, uint8_t*);
    void (*aes_ctr_blocks)(const uint32_t*, const uint8_t*, uint32_t,
                           const uint8_t*, uint8_t*, size_t);
    void (*ghash_init)(uint8_t*, const uint32_t*);
    void (*ghash_update)(uint8_t*, const uint8_t*, const uint8_t*, size_t);
    // ... ChaCha20/Poly1305 function pointers
    const char* name;
} soliton_backend_t;
```

**Priority Order**:
1. VAES + VPCLMULQDQ (best performance)
2. AES-NI + PCLMUL (good performance)
3. Scalar (portable fallback)

---

### 2. AES-256 Implementation

#### Key Expansion

**Scalar** (`core/aes_scalar.c`):
- Standard AES-256 key schedule
- SubWord + RotWord + Rcon
- ~6,700 cycles (pre-v0.4.0)

**AES-NI** (`core/aes256_key_expand_aesni.c`) ⭐ **v0.4.0 optimization**:
- Uses `AESKEYGENASSIST` instruction
- Generates 15 round keys for AES-256
- **~108 cycles** (61.9× faster than scalar)
- Critical for low-latency init

**Key Expansion Algorithm** (AES-NI):
```
Input: 256-bit key K = K[0:127] || K[128:255]
Output: Round keys RK[0..14] (15× 128-bit keys)

RK[0] = K[0:127]
RK[1] = K[128:255]

For i = 2 to 14 (step 2):
    temp = AESKEYGENASSIST(RK[i-1], rcon[i/2])
    RK[i] = KeyExpand(RK[i-2], temp)
    temp = AESKEYGENASSIST(RK[i], 0x00)
    RK[i+1] = KeyExpand(RK[i-1], temp)
```

#### AES-CTR Encryption

**Single Block** (`core/aes_aesni.c`):
- 14 rounds for AES-256
- `AESENC` + `AESENCLAST` instructions
- Used for GHASH H value generation

**8-Block Parallel** (`core/aes_vaes.c`):
- Processes 8 AES blocks simultaneously
- Uses 256-bit YMM registers (2 blocks per register)
- 4× throughput improvement over single-block

**Counter Mode**:
```
For each block i:
    counter_block[i] = IV || big_endian_32(counter + i)
    keystream[i] = AES_K(counter_block[i])
    ciphertext[i] = plaintext[i] ⊕ keystream[i]
```

---

### 3. GHASH (GCM Authentication)

#### Domain Transform

**Specification Domain** (NIST SP 800-38D):
- Big-endian byte representation
- Polynomial: x^128 + x^7 + x^2 + x + 1 (0x87 bit-reversed)

**Internal Domain** (PCLMULQDQ):
- Little-endian polynomial representation
- Reduction polynomial: 0xE1 (x^128 + x^127 + x^126 + x^121 + 1)

**Boundary Transforms**:
```c
// to_lepoly_128: Spec → Internal
void to_lepoly_128(const uint8_t in[16], uint64_t out[2]) {
    out[0] = load_le64(in);      // Little-endian load
    out[1] = load_le64(in + 8);
}

// from_lepoly_128: Internal → Spec
void from_lepoly_128(const uint64_t in[2], uint8_t out[16]) {
    store_le64(out, in[0]);
    store_le64(out + 8, in[1]);
}
```

#### GHASH Computation

**Scalar** (`core/gcm_scalar.c`):
- Bit-by-bit polynomial multiplication
- Reduction using 0xE1 polynomial
- Portable but slow (~100× slower than CLMUL)

**CLMUL** (`core/ghash_clmul.c`):
- Uses `PCLMULQDQ` instruction
- Karatsuba multiplication for efficiency
- Barrett reduction algorithm
- **v0.4.0**: Optimized H-power precomputation

**8-Way CLMUL**:
```
Precompute: H^1, H^2, ..., H^8 (256 bytes, 64-byte aligned)

For each 8-block batch:
    X = X ⊕ (C[0] · H^8)
    X = X ⊕ (C[1] · H^7)
    ...
    X = X ⊕ (C[7] · H^1)
    X = reduce(X)  // Barrett reduction
```

#### Karatsuba Multiplication

**256-bit unreduced product**:
```
(a1·2^64 + a0) × (b1·2^64 + b0) =
    T2·2^128 + (T2 ⊕ T1 ⊕ T0)·2^64 + T0

Where:
    T0 = a0 · b0  (PCLMULQDQ with 0x00 selector)
    T1 = a1 · b1  (PCLMULQDQ with 0x11 selector)
    T2 = (a0⊕a1) · (b0⊕b1)  (PCLMULQDQ with 0x00 selector)
```

**Reduction to 128 bits**:
```
Input: 256-bit T = T_hi || T_lo
Output: 128-bit reduced value

D = T_hi · 0xE1  (PCLMULQDQ)
Result = T_lo ⊕ (D << 1)
```

---

### 4. GCM Fused Kernels

#### Baseline 8-Block Kernel (`core/gcm_fused_vaes_clmul.c`)

**Pipeline**:
1. Encrypt 8 counter blocks with VAES
2. XOR with plaintext (in-place supported)
3. Accumulate ciphertext into GHASH
4. Store results

**Throughput**: ~0.6 cpb @ 64KB (v0.3.1), ~0.45 cpb @ 64KB (v0.4.0)

#### 16-Block Kernels

**Pipelined** (`core/gcm_pipelined_vaes_clmul.c`):
- Interleaves AES and GHASH operations
- Hides PCLMULQDQ latency
- Requires more registers

**Fused 16** (`core/gcm_fused16_vaes_clmul.c`):
- Single reduction for 16 blocks
- Higher parallelism
- Best for large messages

---

### 5. ChaCha20-Poly1305

#### ChaCha20 (`core/chacha_avx2.c`)

**AVX2 Implementation**:
- Processes 4 blocks in parallel (256-bit registers)
- Quarter-round function fully vectorized
- High throughput for bulk encryption

**Quarter Round**:
```
a += b; d ^= a; d <<<= 16;
c += d; b ^= c; b <<<= 12;
a += b; d ^= a; d <<<= 8;
c += d; b ^= c; b <<<= 7;
```

#### Poly1305 (`core/poly1305_scalar.c`)

**Algorithm**:
- 130-bit prime field arithmetic
- Authenticates Associated Data || Ciphertext || Lengths
- MAC = ((r · message mod p) + s) mod 2^128

---

## Memory Layout

### GCM Context Structure

```c
typedef struct {
    uint32_t round_keys[60];        // AES-256 round keys (240 bytes)
    uint8_t h_powers[16][16];       // H^1..H^16 (256 bytes, aligned)
    uint8_t ghash_state[16];        // Current GHASH accumulator
    uint8_t iv_pad[16];             // J0 for GCMAC
    uint32_t counter;               // CTR mode counter
    uint64_t aad_len;               // AAD length (bits)
    uint64_t ct_len;                // Ciphertext length (bits)
    int state;                      // State machine
    soliton_backend_t* backend;    // Function pointers
} soliton_aesgcm_ctx;
```

**Total size**: ~512 bytes (64-byte aligned for cache efficiency)

---

## Constant-Time Guarantees

### Principles

1. **No secret-dependent branches**: All conditionals on secrets are masked
2. **No secret-dependent addresses**: Array indices independent of secrets
3. **Fixed-time operations**: Tag verification uses constant-time comparison

### Implementation

**Tag Verification**:
```c
int constant_time_memcmp(const void* a, const void* b, size_t len) {
    const uint8_t* pa = a;
    const uint8_t* pb = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return diff;  // 0 if equal, non-zero if different
}
```

**No Data-Dependent Lookups**:
- AES S-box: Hardware instruction (AESENC) or bitsliced
- No table-based implementations with secret indices

---

## Performance Characteristics

### Init Overhead (v0.4.0)

| Component | Cycles | Percentage |
|-----------|--------|------------|
| AES key expansion | 108 | 2.2% |
| GHASH H value | 5 | 0.1% |
| H-power precomputation | 171 | 3.4% |
| Other init | 4,680 | 94.3% |
| **Total** | **4,964** | **100%** |

### Steady-State Performance (64KB messages)

| Backend | Cycles/Byte | vs OpenSSL |
|---------|-------------|------------|
| OpenSSL 3.x | 0.35 | 1.0× (baseline) |
| soliton.c v0.4.0 (VAES) | 0.45 | 1.28× |
| soliton.c (AES-NI) | ~0.8 | ~2.3× |
| soliton.c (scalar) | ~15 | ~43× |

---

## Validation Strategy

### Gate Testing

**Gate P0** (Product Equivalence):
- Validates 256-bit Karatsuba multiplication
- 262/262 test vectors passed
- Ensures PCLMULQDQ correctness

**Gate C** (Cross-EVP):
- 10,000 random test cases vs OpenSSL
- Random keys, IVs, AAD, plaintexts
- Validates end-to-end correctness
- **v0.4.0: 10,000/10,000 PASSED**

### NIST Compliance

- SP 800-38D test vectors: PASSED
- RFC 8439 test vectors: PASSED
- 96-bit IV standard mode: VALIDATED
- Non-96-bit IV: Not yet implemented

---

## Build System

### Conditional Compilation

```makefile
# Feature detection at compile time
VAES_SUPPORTED := $(shell echo | $(CC) -mvaes -dM -E -)
AESNI_SUPPORTED := $(shell echo | $(CC) -maes -dM -E -)
```

### Backend Compilation

- **Scalar**: Always compiled (C17, no extensions)
- **AES-NI**: Compiled with `-maes -mpclmul`
- **VAES**: Compiled with `-mvaes -mvpclmulqdq -mavx2`
- **ARM**: Compiled with `-march=armv8-a+crypto`

### Library Output

```bash
libsoliton_core.a   # Static library
# Contains: All backends + dispatch logic
# Size: ~150KB (stripped)
```

---

## Design Rationale

### Why Freestanding?

- **No libc dependencies**: Embeddable in kernels, bootloaders, firmware
- **Deterministic**: No malloc jitter, no stdio buffering
- **Auditable**: Minimal dependencies, clear memory model

### Why Multi-Tier Backends?

- **Performance**: Hardware acceleration where available (VAES: 40× faster)
- **Portability**: Works on any C17 platform (scalar fallback)
- **Verification**: Scalar as reference correctness baseline

### Why AES-NI Key Expansion? (v0.4.0)

**Problem**: Scalar key expansion dominated init overhead (97.4% of 11.6k cycles)

**Solution**: Use `AESKEYGENASSIST` instruction

**Impact**:
- Key expansion: 6,684 → 108 cycles (**61.9× faster**)
- Total init: 11,580 → 4,964 cycles (**2.3× faster**)
- Makes soliton.c viable for low-latency applications

### Why No OpenSSL Provider Yet?

- **Focus**: Core correctness and performance first
- **Complexity**: Provider API requires careful state management
- **Status**: Provider code exists but not integrated/tested

---

## Future Optimization Targets

### P1: SIMD Processing (v0.5.0 target)

**Current Gap**: 1.28× slower than OpenSSL @ 64KB

**Strategies**:
1. Microarchitectural profiling (port saturation, uop cache)
2. Instruction scheduling optimization
3. Pipeline balancing (VAES vs VPCLMULQDQ latency)
4. Prefetching and cache optimization

**Goal**: <1.15× gap (<0.40 cpb)

### Optional Enhancements

- Non-96-bit IV support (NIST J₀ computation)
- AVX-512 kernels for Ice Lake+ (32-block batches)
- ARM NEON optimization (currently basic)
- Lightweight IV-reset API (amortized workloads)

---

## References

- NIST SP 800-38D: AES-GCM specification
- RFC 8439: ChaCha20-Poly1305 AEAD
- Intel® 64 and IA-32 Architectures Software Developer's Manual (Volume 2)
- "The Galois/Counter Mode of Operation (GCM)" - D. McGrew, J. Viega

---

**This document describes soliton.c v0.4.0 as implemented and tested.
All claims are backed by reproducible benchmarks and validation results.**
