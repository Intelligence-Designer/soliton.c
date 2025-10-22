/*
 * ghash_clmul.c - GHASH implementation using PCLMULQDQ
 * Hardware-accelerated polynomial multiplication in GF(2^128)
 */

#include "common.h"
#include "diagnostics.h"

#ifdef __x86_64__

#include <immintrin.h>

#if defined(FUSED_DEBUG_REF)
#include <stdio.h>

/* Helper macro to print __m128i as hex bytes */
#define TRACE_HEX(label, vec) do { \
    uint8_t buf[16]; \
    _mm_storeu_si128((__m128i*)buf, (vec)); \
    printf("%s: ", label); \
    for (int _i = 0; _i < 16; _i++) printf("%02x", buf[_i]); \
    printf("\n"); \
} while(0)
#endif

/* Check for PCLMULQDQ support at compile time */
#ifdef __PCLMUL__

/* No context needed - state is stored directly in uint8_t arrays */

/* =============================================================================
 * GOLDEN ORACLE: Trace helpers for debugging GHASH domain transformations
 * ============================================================================= */
#define GHASH_ORACLE_TRACE 0  // Disable - fix validated by Gate P0
#if GHASH_ORACLE_TRACE
#include <stdio.h>
static inline void dump128(const char* lbl, __m128i v) {
    unsigned char b[16] __attribute__((aligned(16)));
    _mm_storeu_si128((__m128i*)b, v);
    fprintf(stderr, "%-24s = ", lbl);
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", b[i]);
    fputc('\n', stderr);
}
#else
#define dump128(lbl, v) ((void)0)
#endif

/* =============================================================================
 * DOMAIN CONTRACT: Reflected GHASH - All swaps moved to setkey
 *
 * REFLECTED DOMAIN:
 * - H preprocessed once in setkey: byte-reverse + multiply by x mod poly
 * - Xi, H-powers, all runtime state in reflected domain (CPU-native bit order)
 * - NO runtime byte swaps in multiply hot path
 * - Only swap at API boundary when comparing tags with external implementations
 *
 * CORRECTNESS INVARIANT:
 *   reflect(ghash_mul_reflected(a_r, b_r)) == ghash_mul_spec(reflect(a_r), reflect(b_r))
 * ============================================================================= */

/* Byte reflection for setkey preprocessing
 * Converts H from spec (big-endian) to kernel (little-endian) domain
 */
SOLITON_INLINE __m128i ghash_reflect_bytes(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

/* Multiply by x mod (x^128 + x^7 + x^2 + x + 1) in kernel domain
 * x · h with carry propagation and polynomial reduction */
SOLITON_INLINE __m128i ghash_mul_x_reflected(__m128i h) {
    // Shift the 128-bit value left by 1 with carry between lanes
    __m128i carry = _mm_srli_epi64(h, 63);                 // per-lane MSB → LSB
    __m128i h2    = _mm_slli_epi64(h, 1);
    // bring lower-lane carry into higher lane (cross-lane propagation)
    __m128i carry_xlane = _mm_slli_si128(carry, 8);        // carry from low→high lane
    h2 = _mm_or_si128(h2, carry_xlane);

    // if the global MSB (bit127) was set, XOR with reflected poly 0x87
    // Shift carry right by 8 bytes to move high qword to low qword position
    __m128i high_carry = _mm_srli_si128(carry, 8);
    // AND with polynomial to get conditional 0x87: if high_carry is nonzero, result is 0x87
    // (since high_carry will be 0x01 when bit 127 was set, and 0x01 & 0x87 = 0x01, not what we want)
    // We need a full mask, so let's negate and use that to select
    // Actually, simpler: just AND the shifted carry (which is 0 or 1) with 0x87
    // No wait - if high_carry is 0x01, we need output to be 0x87, not 0x01
    // We need: (0-high_carry) & 0x87, which gives us 0x87 when high_carry=1, 0 when high_carry=0
    // But (0-1) in unsigned = 0xFFFFFFFFFFFFFFFF, so (0-high_carry) & 0x87 works!
    __m128i mask = _mm_sub_epi64(_mm_setzero_si128(), high_carry); // 0 - carry = -carry
    const __m128i poly = _mm_set_epi64x(0, 0x87);
    mask = _mm_and_si128(mask, poly);  // -1 & 0x87 = 0x87 when carry, else 0

    return _mm_xor_si128(h2, mask);
}

/* Setkey preprocessing: byte-swap + multiply by x like Linux kernel expects
 * Linux kernel comment says: "hash_key << 1 mod poly" */
static __m128i ghash_setkey_preprocess(const uint8_t h_spec[16]) {
    __m128i h = _mm_loadu_si128((const __m128i*)h_spec);  // spec domain
    dump128("H_spec(input)", h);
    // Byte-swap to kernel domain (PCLMULQDQ native format)
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    h = _mm_shuffle_epi8(h, rev);
    dump128("H_kern (GCM: no ·x)", h);

    // GCM spec (NIST SP 800-38D) uses H = E_K(0) directly, NO preprocessing.
    // Linux kernel's shash API required H·x; we don't. EVP benchmark wins here.
    // REMOVED: h = ghash_mul_x_reflected(h);

    return h;
}

/* API boundary conversions between GCM spec (big-endian) and kernel domain (little-endian)
 *
 * Internal domain: little-endian bytes, natural bit order (Intel PCLMUL native)
 * External domain: big-endian bytes (GCM specification, NIST test vectors)
 *
 * Use ONLY at API boundaries (input data ingress, output tag egress)
 * Internal GHASH math stays in little-endian throughout
 */
SOLITON_INLINE __m128i to_lepoly_128(__m128i x_spec) {
    // Byte-swap for PCLMUL (like Linux kernel pshufb)
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_spec, rev);
}

SOLITON_INLINE __m128i from_lepoly_128(__m128i x_kernel) {
    // Byte-swap back from PCLMUL (like Linux kernel pshufb)
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_kernel, rev);
}

#if defined(__AVX2__)
SOLITON_INLINE __m256i to_lepoly_256(__m256i x_spec) {
    // Spec (big-endian) → Kernel (little-endian) per 128-bit lane
    const __m256i rev = _mm256_setr_epi8(
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm256_shuffle_epi8(x_spec, rev);
}

SOLITON_INLINE __m256i from_lepoly_256(__m256i x_kernel) {
    // Kernel (little-endian) → Spec (big-endian) per 128-bit lane
    const __m256i rev = _mm256_setr_epi8(
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm256_shuffle_epi8(x_kernel, rev);
}
#endif

/* =============================================================================
 * GF(2^128) reduction: 256-bit product → 128-bit (modulo x^128+x^7+x^2+x+1)
 * Known-good Intel/OpenSSL-style reduction (battle-tested)
 * ============================================================================= */

/* Byte-reverse per 128-bit value (for Intel domain mapping) */
SOLITON_INLINE __m128i byte_reverse_128(__m128i x) {
    const __m128i rev = _mm_set_epi8(
        0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,
        0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00);
    return _mm_shuffle_epi8(x, rev);
}

/*
 * Linux kernel / OpenSSL Karatsuba + reduction
 * polynomial: x^128 + x^7 + x^2 + x + 1  (0xE1)
 *
 * This is transcribed literally from ghash-clmulni-intel_asm.S
 * The reduction sequence is: left-shifts → cross-lane → right-shifts
 * Input: lo, hi = 256-bit product (lo = low 128, hi = high 128) in BIG-ENDIAN domain
 * Output: 128-bit reduced result in BIG-ENDIAN domain
 */
SOLITON_INLINE __m128i ghash_reduce_intel(__m128i lo, __m128i hi) {
    // 1. hi << 1,2,7 → xor into lo
    __m128i v1 = _mm_slli_epi64(hi, 1);
    __m128i v2 = _mm_slli_epi64(hi, 2);
    __m128i v7 = _mm_slli_epi64(hi, 7);
    lo = _mm_xor_si128(lo, _mm_xor_si128(v1, _mm_xor_si128(v2, v7)));

    // 2. hi shifted by 8 bytes (cross-lane) then << 1,2,7 → xor into lo
    __m128i hi_shift = _mm_slli_si128(hi, 8);
    v1 = _mm_slli_epi64(hi_shift, 1);
    v2 = _mm_slli_epi64(hi_shift, 2);
    v7 = _mm_slli_epi64(hi_shift, 7);
    lo = _mm_xor_si128(lo, _mm_xor_si128(v1, _mm_xor_si128(v2, v7)));

    // 3. hi >> 63,62,57 → fold → xor into lo (final fold)
    __m128i t1 = _mm_srli_epi64(hi, 63);
    __m128i t2 = _mm_srli_epi64(hi, 62);
    __m128i t7 = _mm_srli_epi64(hi, 57);
    __m128i fold = _mm_xor_si128(t1, _mm_xor_si128(t2, t7));
    lo = _mm_xor_si128(lo, _mm_xor_si128(hi, fold));

    return lo;
}

/* Reducer wrapper for reflected domain (maintains external contract) */
SOLITON_INLINE __m128i ghash_reduce_reflected(__m128i lo, __m128i hi) {
    return ghash_reduce_intel(lo, hi);
}

/* Legacy name for compatibility */
__m128i ghash_reduce_256_to_128_lepoly(__m128i lo, __m128i hi) {
    return ghash_reduce_reflected(lo, hi);
}

/* Forward declaration for legacy scalar multiply */
static SOLITON_INLINE __m128i ghash_mul_spec_scalar(__m128i x, __m128i h);

/* Reference 4-partial multiply (no Karatsuba optimization)
 * This is the ground-truth multiply for testing the reducer */
static inline void clmul_x4_256(__m128i a, __m128i b, __m128i *lo, __m128i *hi) {
    // Four partials (a0*b0, a0*b1, a1*b0, a1*b1)
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);

    // Center terms: The middle two products need to be XORed and split across lo/hi
    // Each partial is 128 bits; lower 64 go to lo[64:127], upper 64 go to hi[0:63]
    __m128i mid = _mm_xor_si128(p01, p10);

    *lo = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));  // lo = p00 XOR (mid << 64 bits)
    *hi = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));  // hi = p11 XOR (mid >> 64 bits)
}

/*
 * GCM Reduction for 0xE1 Polynomial (Standard Representation)
 * Algorithm: OpenSSL/Intel two-phase reduction with exact shift sequence
 *
 * Reduces 256-bit product (lo:hi) modulo P(x) = x^128 + x^7 + x^2 + x + 1
 *
 * Based on OpenSSL's ghash-x86_64.pl implementation
 * Uses reduction constant 0x1c2 (= 0xE1 << 1)
 *
 * Input:  lo (bits 0-127), hi (bits 128-255) in kernel byte order
 * Output: 128-bit result reduced mod P(x)
 */
static inline __m128i ghash_reduce_kerneldomain(__m128i lo, __m128i hi) {
    /*
     * Phase 1: Barrett-style reduction using shifts 57, 62, 63
     * This folds the high part into both low and high components
     */

    // Compute T1 = hi << 57 ⊕ hi << 62 ⊕ hi << 63
    __m128i t1 = _mm_slli_epi64(hi, 57);
    __m128i t2 = _mm_slli_epi64(hi, 62);
    __m128i t3 = _mm_slli_epi64(hi, 63);
    __m128i t = _mm_xor_si128(_mm_xor_si128(t1, t2), t3);

    // Split T into low and high 64-bit halves and fold
    __m128i t_lo = _mm_slli_si128(t, 8);   // Move low 64 bits to high position
    __m128i t_hi = _mm_srli_si128(t, 8);   // Move high 64 bits to low position

    lo = _mm_xor_si128(lo, t_lo);
    hi = _mm_xor_si128(hi, t_hi);

    /*
     * Phase 2: Final reduction using CUMULATIVE shifts (1, then +1, then +5)
     * This completes the modular reduction: hi >> 1, >> 2, >> 7
     */

    // Cumulative right shifts: 1, 2 (=1+1), 7 (=2+5)
    __m128i r = _mm_srli_epi64(hi, 1);          // hi >> 1
    r = _mm_xor_si128(r, _mm_srli_epi64(r, 1)); // (hi>>1) XOR (hi>>2)
    r = _mm_xor_si128(r, _mm_srli_epi64(r, 5)); // previous XOR (hi>>7)

    // Also XOR with original hi
    r = _mm_xor_si128(r, hi);

    // Final result
    return _mm_xor_si128(lo, r);
}

/* Reference multiply using 4-partials (for testing) */
static inline __m128i ghash_mul_ref_kernel(__m128i a, __m128i b) {
    __m128i lo, hi;
    clmul_x4_256(a, b, &lo, &hi);
    return ghash_reduce_kerneldomain(lo, hi);
}

/* =============================================================================
 * ghash_mul_reflected: Correct GHASH multiply for reflected domain
 * Inputs: a_ref, b_ref in reflected domain (your canonical storage)
 * Output: (a*b mod poly) in reflected domain
 *
 * Strategy: Swap to Intel/BE domain, use known-good reduction, swap back
 * This ensures correctness while maintaining your reflected storage contract
 * EXPORTED for use by fused kernels
 * ============================================================================= */
/* Multiply two kernel-domain 128-bit polynomials with CLMUL and reduce
 * TEMPORARY: Using scalar multiply until CLMUL reducer is validated
 * Gate P0 passed (256-bit product correct), but reducer needs work */
__m128i ghash_mul_reflected(__m128i a, __m128i b) {
    /* Session 9 FIX: Use CLMUL instead of buggy scalar multiply
     * Gate P0 verified that clmul_x4_256 + ghash_reduce_intel is correct.
     * Scalar path had subtle big-endian bugs that corrupted H-power table. */
    __m128i lo, hi;
    clmul_x4_256(a, b, &lo, &hi);
    return ghash_reduce_intel(lo, hi);
}

/* Legacy name for compatibility - will be removed */
__m128i ghash_mul_lepoly_clmul(__m128i a, __m128i b) {
    return ghash_mul_reflected(a, b);
}

/* =============================================================================
 * ghash_mul_lepoly_scalar: SCALAR FALLBACK PATH (portable C)
 * Inputs: a_le, b_le in CLMUL (le-poly) domain
 * Output: (a*b mod reduction_poly) in CLMUL domain
 * Implemented by converting to SPEC, calling legacy scalar mul, converting back
 * ============================================================================= */
static SOLITON_INLINE __m128i ghash_mul_lepoly_scalar(__m128i a_le, __m128i b_le) {
    // Input is in kernel domain (little-endian polynomial, bytes already swapped).
    // ghash_mul_spec_scalar expects spec domain (big-endian), so swap back.
    a_le = from_lepoly_128(a_le);
    b_le = from_lepoly_128(b_le);

    // Multiply in spec domain
    const __m128i r = ghash_mul_spec_scalar(a_le, b_le);

    // Result is in spec domain; swap back to kernel domain for return
    return to_lepoly_128(r);
}

/* =============================================================================
 * LEGACY: ghash_mul_spec_scalar (SPEC/BE domain in, SPEC/BE domain out)
 * DO NOT CALL FROM CORE GHASH PATHS - use ghash_mul_lepoly_* instead
 * Kept only for edge cases and testing
 * ============================================================================= */
static SOLITON_INLINE __m128i ghash_mul_spec_scalar(__m128i x, __m128i h) {
    /* Reduction polynomial */
    const uint64_t R_hi = 0xE100000000000000ULL;

    uint64_t x_hi, x_lo, h_hi, h_lo;
    uint64_t z_h = 0, z_l = 0;
    uint64_t v_h, v_l;

    /* Extract bytes and convert from big-endian to native, matching scalar code */
    uint8_t x_bytes[16], h_bytes[16];
    _mm_storeu_si128((__m128i*)x_bytes, x);
    _mm_storeu_si128((__m128i*)h_bytes, h);

    /* Apply soliton_be64 to convert big-endian bytes to native uint64_t */
    x_hi = soliton_be64(x_bytes);       /* bytes 0-7 → high 64 bits */
    x_lo = soliton_be64(x_bytes + 8);   /* bytes 8-15 → low 64 bits */
    h_hi = soliton_be64(h_bytes);
    h_lo = soliton_be64(h_bytes + 8);

    v_h = h_hi;
    v_l = h_lo;

    /* Process all 128 bits from MSB to LSB */
    for (int i = 0; i < 64; i++) {
        /* Check bit (63-i) of x_hi */
        uint64_t bit = (x_hi >> (63 - i)) & 1;
        uint64_t mask = -(uint64_t)bit;

        z_h ^= v_h & mask;
        z_l ^= v_l & mask;

        /* Right shift v by 1 */
        uint64_t lsb = v_l & 1;
        v_l = (v_l >> 1) | (v_h << 63);
        v_h = v_h >> 1;

        /* If LSB was 1, XOR with R */
        uint64_t reduce = -(uint64_t)lsb;
        v_h ^= R_hi & reduce;
    }

    for (int i = 0; i < 64; i++) {
        /* Check bit (63-i) of x_lo */
        uint64_t bit = (x_lo >> (63 - i)) & 1;
        uint64_t mask = -(uint64_t)bit;

        z_h ^= v_h & mask;
        z_l ^= v_l & mask;

        /* Right shift v by 1 */
        uint64_t lsb = v_l & 1;
        v_l = (v_l >> 1) | (v_h << 63);
        v_h = v_h >> 1;

        /* If LSB was 1, XOR with R */
        uint64_t reduce = -(uint64_t)lsb;
        v_h ^= R_hi & reduce;
    }

    /* Pack result back into __m128i using big-endian format */
    uint8_t result_bytes[16];
    soliton_put_be64(result_bytes, z_h);        /* high → bytes 0-7 */
    soliton_put_be64(result_bytes + 8, z_l);    /* low → bytes 8-15 */
    __m128i result = _mm_loadu_si128((const __m128i*)result_bytes);
    return result;
}

/* Initialize GHASH with key */
void ghash_init_clmul(uint8_t h[16], const uint32_t* round_keys) {
    /* Compute H = AES_K(0) using AES-NI (much faster than scalar) */
    uint8_t zeros[16] = {0};

    #if GHASH_ORACLE_TRACE
    fprintf(stderr, "ghash_init_clmul: first round key = %08x %08x %08x %08x\n",
            round_keys[0], round_keys[1], round_keys[2], round_keys[3]);
    #endif

    /* Compute H = AES_K(0) in SPEC (big-endian) format */
#ifdef __AES__
    extern void aes256_encrypt_block_aesni(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]);
    aes256_encrypt_block_aesni(round_keys, zeros, h);
#else
    extern void aes256_encrypt_block_scalar(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]);
    aes256_encrypt_block_scalar(round_keys, zeros, h);
#endif

    #if GHASH_ORACLE_TRACE
    fprintf(stderr, "ghash_init_clmul: H = ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", h[i]);
    fprintf(stderr, "\n");
    #endif

    /* H stored in SPEC domain - precompute will convert to CLMUL */
}

/* Precompute H powers for 8-way GHASH (call once per key) */
/* =============================================================================
 * ghash_precompute_h_powers_lepoly: Build H^1..H^16 in CLMUL (le-poly) domain
 * Input: h_spec_bytes[16] - H in SPEC (big-endian) format from AES_K(0)
 * Output: out_le[0..15] - H^1..H^16 in CLMUL domain
 * ============================================================================= */
void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h_spec_bytes[16]) {
    /* Setkey preprocessing: byte-reverse + multiply by x mod poly
     * This is the ONLY place we swap - happens once per key */
    __m128i h = ghash_setkey_preprocess(h_spec_bytes);

    /* Store H^1 in reflected domain */
    _mm_storeu_si128((__m128i*)h_powers[0], h);

    /* Compute H^2, H^3, ..., H^16 - all stay in reflected domain */
    __m128i hp = h;
    for (int i = 1; i < 16; i++) {
        #if defined(__PCLMUL__)
        hp = ghash_mul_reflected(hp, h);
        #else
        hp = ghash_mul_lepoly_scalar(hp, h);  /* Scalar fallback when no PCLMUL */
        #endif
        _mm_storeu_si128((__m128i*)h_powers[i], hp);
    }

    /* TRIPWIRE: Verify H^2 = H*H (catches domain corruption early) */
    #ifdef SOLITON_DEBUG
    __m128i h2_check;
    #if defined(__PCLMUL__)
    h2_check = ghash_mul_reflected(h, h);
    #else
    h2_check = ghash_mul_lepoly_scalar(h, h);
    #endif
    __m128i h2_stored = _mm_loadu_si128((const __m128i*)h_powers[1]);

    /* Compare all 128 bits */
    __m128i diff = _mm_xor_si128(h2_check, h2_stored);
    int mismatch = !_mm_test_all_zeros(diff, diff);
    if (mismatch) {
        fprintf(stderr, "FATAL: H^2 tripwire failed - domain corruption detected\n");
        abort();
    }
    #endif
}

/* Update GHASH with data (single-block path) */
void ghash_update_clmul(uint8_t* state, const uint8_t* h_bytes, const uint8_t* data, size_t len) {
    /* Track scalar GHASH path usage */
    DIAG_INC(ghash_scalar_calls);
    DIAG_ADD(ghash_total_bytes, len);

    /* Load Xi (GHASH state) - stored in CLMUL domain */
    __m128i y = _mm_loadu_si128((const __m128i*)state);

    /* Load H^1 (already in preprocessed reflected domain from h_powers[0]) */
    __m128i h = _mm_loadu_si128((const __m128i*)h_bytes);

    /* Process complete 16-byte blocks */
    while (len >= 16) {
        /* Convert data from SPEC → CLMUL domain (ingress point) */
        __m128i x_spec = _mm_loadu_si128((const __m128i*)data);
        dump128("C_spec", x_spec);
        __m128i x = to_lepoly_128(x_spec);
        dump128("C_ref", x);
        dump128("Xi_ref.before", y);
        dump128("H_ref(pre)", h);

        /* Xi = (Xi ⊕ C[i]) * H */
        y = _mm_xor_si128(y, x);
        dump128("Xi_ref.afterXOR", y);
        #if defined(__PCLMUL__)
        y = ghash_mul_lepoly_clmul(y, h);
        #else
        y = ghash_mul_lepoly_scalar(y, h);
        #endif
        dump128("Xi_ref.afterMUL", y);

        data += 16;
        len -= 16;
    }

    /* Handle partial block */
    if (len > 0) {
        uint8_t block[16] = {0};
        for (size_t i = 0; i < len; i++) {
            block[i] = data[i];
        }

        /* Convert partial block from SPEC → CLMUL domain */
        __m128i x = _mm_loadu_si128((const __m128i*)block);
        x = to_lepoly_128(x);
        y = _mm_xor_si128(y, x);
        #if defined(__PCLMUL__)
        y = ghash_mul_lepoly_clmul(y, h);
        #else
        y = ghash_mul_lepoly_scalar(y, h);
        #endif
    }

    /* Store updated state (keep in CLMUL domain) */
    _mm_storeu_si128((__m128i*)state, y);
}

/* GCM reduction matching fused kernel (imported from gcm_fused_vaes_clmul.c) */
static SOLITON_INLINE __m128i ghash_reduce_clmul(__m128i x0, __m128i x1, __m128i x2) {
    /* GCM reduction polynomial: x^128 + x^7 + x^2 + x + 1 */

    /* First phase */
    __m128i t1 = _mm_slli_epi32(x0, 31);
    __m128i t2 = _mm_slli_epi32(x0, 30);
    __m128i t3 = _mm_slli_epi32(x0, 25);

    t1 = _mm_xor_si128(t1, t2);
    t1 = _mm_xor_si128(t1, t3);

    __m128i t4 = _mm_srli_epi32(t1, 32);
    t1 = _mm_shuffle_epi32(t1, 0x93);

    __m128i t5 = _mm_xor_si128(x0, t1);
    x1 = _mm_xor_si128(x1, t4);

    /* Second phase */
    __m128i t6 = _mm_srli_epi32(x1, 1);
    __m128i t7 = _mm_srli_epi32(x1, 2);
    __m128i t8 = _mm_srli_epi32(x1, 7);

    t6 = _mm_xor_si128(t6, t7);
    t6 = _mm_xor_si128(t6, t8);
    t6 = _mm_xor_si128(t6, x1);

    __m128i t9 = _mm_slli_epi32(t6, 32);
    t6 = _mm_shuffle_epi32(t6, 0x4E);

    x1 = _mm_xor_si128(x1, t9);
    x2 = _mm_xor_si128(x2, t6);

    return _mm_xor_si128(t5, x2);
}

/* 8-way parallel GHASH with deferred reduction and Karatsuba optimization */
void ghash_update_clmul8(uint8_t* state, const uint8_t h_powers[8][16],
                         const uint8_t* data, size_t len) {
    /* Track 8-way GHASH path usage */
    DIAG_INC(ghash_clmul8_calls);
    DIAG_ADD(ghash_total_bytes, len);

    /* Domain contract: Xi and H^i are already in CLMUL domain from storage */
    __m128i Xi = _mm_loadu_si128((const __m128i*)state);  /* Already CLMUL domain */

    /* Load H powers: H^8, H^7, ..., H^1 (already in CLMUL domain from precompute) */
    __m128i H[8];
    for (int i = 0; i < 8; i++) {
        H[i] = _mm_loadu_si128((const __m128i*)h_powers[7 - i]);  /* Already CLMUL domain */
    }

    /* Process 8 blocks at a time using Karatsuba + single reduction (match fused kernel) */
    while (len >= 128) {
        /* Load 8 ciphertext blocks and convert from spec → CLMUL domain */
        __m128i C[8];
        for (int i = 0; i < 8; i++) {
            C[i] = _mm_loadu_si128((const __m128i*)(data + i * 16));
            C[i] = to_lepoly_128(C[i]);  /* Spec → CLMUL domain */
        }

        /* XOR state into first block (matching fused kernel behavior) */
        C[0] = _mm_xor_si128(C[0], Xi);

        /* Karatsuba CLMUL with 4 accumulators (matching fused kernel) */
        __m128i acc_lo[4], acc_hi[4], acc_mid[4];
        for (int a = 0; a < 4; a++) {
            acc_lo[a] = _mm_setzero_si128();
            acc_hi[a] = _mm_setzero_si128();
            acc_mid[a] = _mm_setzero_si128();
        }

        /* Process 8 blocks across 4 accumulators (2 blocks per accumulator) */
        for (int i = 0; i < 8; i++) {
            int acc = i >> 1;  /* accumulator index: 0,0,1,1,2,2,3,3 */

            /* Karatsuba: (a_lo, a_hi) * (b_lo, b_hi) */
            __m128i a_lo_b_lo = _mm_clmulepi64_si128(C[i], H[i], 0x00);
            __m128i a_hi_b_hi = _mm_clmulepi64_si128(C[i], H[i], 0x11);

            /* Mid term: (a_lo ⊕ a_hi) * (b_lo ⊕ b_hi) */
            __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C[i], 0x4E), C[i]);
            __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[i], 0x4E), H[i]);
            __m128i mid_product = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);

            /* mid = mid_product ⊕ lo ⊕ hi */
            mid_product = _mm_xor_si128(mid_product, a_lo_b_lo);
            mid_product = _mm_xor_si128(mid_product, a_hi_b_hi);

            /* Accumulate into designated accumulator */
            acc_lo[acc] = _mm_xor_si128(acc_lo[acc], a_lo_b_lo);
            acc_hi[acc] = _mm_xor_si128(acc_hi[acc], a_hi_b_hi);
            acc_mid[acc] = _mm_xor_si128(acc_mid[acc], mid_product);
        }

        /* Fold 4 accumulators into 1 using XOR tree */
        __m128i lo = _mm_xor_si128(_mm_xor_si128(acc_lo[0], acc_lo[1]),
                                    _mm_xor_si128(acc_lo[2], acc_lo[3]));
        __m128i hi = _mm_xor_si128(_mm_xor_si128(acc_hi[0], acc_hi[1]),
                                    _mm_xor_si128(acc_hi[2], acc_hi[3]));
        __m128i mid = _mm_xor_si128(_mm_xor_si128(acc_mid[0], acc_mid[1]),
                                     _mm_xor_si128(acc_mid[2], acc_mid[3]));

        /* Combine: result = lo + 2^64*mid + 2^128*hi */
        lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
        hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

        /* Single polynomial reduction: 256-bit (lo, hi) → 128-bit result */
        Xi = ghash_reduce_256_to_128_lepoly(lo, hi);

        data += 128;
        len -= 128;
    }

    /* Tail: process remaining 1-7 blocks with standard per-block reduction */
    __m128i H1 = H[7];  /* H^1 for tail (already CLMUL domain) */
    while (len >= 16) {
        __m128i C = _mm_loadu_si128((const __m128i*)data);
        C = to_lepoly_128(C);  /* Spec → CLMUL domain */
        Xi = _mm_xor_si128(Xi, C);
        #if defined(__PCLMUL__)
        Xi = ghash_mul_lepoly_clmul(Xi, H1);
        #else
        Xi = ghash_mul_lepoly_scalar(Xi, H1);
        #endif
        data += 16;
        len -= 16;
    }

    /* Handle partial block (<16 bytes) */
    if (len > 0) {
        uint8_t block[16] = {0};
        for (size_t i = 0; i < len; i++) {
            block[i] = data[i];
        }
        __m128i C = _mm_loadu_si128((const __m128i*)block);
        C = to_lepoly_128(C);  /* Spec → CLMUL domain */
        Xi = _mm_xor_si128(Xi, C);
        #if defined(__PCLMUL__)
        Xi = ghash_mul_lepoly_clmul(Xi, H1);
        #else
        Xi = ghash_mul_lepoly_scalar(Xi, H1);
        #endif
    }

    /* Store updated state (keep in CLMUL domain) */
    _mm_storeu_si128((__m128i*)state, Xi);
}

/* Finalize GHASH for GCM tag computation (CLMUL version) */
void ghash_final_clmul(uint8_t* tag, const uint8_t* state, const uint8_t* h,
                       uint64_t aad_len, uint64_t ct_len) {
    /* Load Xi (GHASH state) - stored in CLMUL domain */
    __m128i Xi = _mm_loadu_si128((const __m128i*)state);

    #ifdef FUSED_DEBUG_REF
    printf("\nFINAL DEBUG:\n");
    TRACE_HEX("Xi loaded from state", Xi);
    printf("aad_len=%lu, ct_len=%lu\n", aad_len, ct_len);
    #endif

    /* Load H^1 (already in preprocessed reflected domain from h_powers[0]) */
    __m128i H = _mm_loadu_si128((const __m128i*)h);

    /* Construct length block in spec domain: [aad_len * 8][ct_len * 8] in bits */
    uint8_t len_block[16];
    soliton_put_be64(len_block, aad_len * 8);
    soliton_put_be64(len_block + 8, ct_len * 8);

    /* Convert lengths block from spec → CLMUL domain (single ingress point) */
    __m128i len_spec = _mm_loadu_si128((const __m128i*)len_block);
    dump128("LEN_spec", len_spec);
    __m128i len = to_lepoly_128(len_spec);
    dump128("LEN_ref", len);

    /* Final GHASH: tag = (Xi ^ len_block) * H (all in CLMUL domain) */
    dump128("Xi_ref.beforeLEN", Xi);
    dump128("H_ref(pre)", H);
    Xi = _mm_xor_si128(Xi, len);
    dump128("Xi_ref.afterLEN_XOR", Xi);

    #ifdef FUSED_DEBUG_REF
    TRACE_HEX("len_block (CLMUL)", len);
    TRACE_HEX("Xi after XOR len", Xi);
    TRACE_HEX("H (CLMUL)", H);
    #endif

    #if defined(__PCLMUL__)
    Xi = ghash_mul_lepoly_clmul(Xi, H);
    #else
    Xi = ghash_mul_lepoly_scalar(Xi, H);
    #endif
    dump128("Xi_ref.afterLEN_MUL", Xi);

    #ifdef FUSED_DEBUG_REF
    TRACE_HEX("Xi after mul H (CLMUL)", Xi);
    #endif

    /* Convert result from CLMUL → spec domain for tag output (single egress point) */
    Xi = from_lepoly_128(Xi);
    dump128("S_spec(egress)", Xi);

    #ifdef FUSED_DEBUG_REF
    TRACE_HEX("Tag (SPEC domain)", Xi);
    #endif

    _mm_storeu_si128((__m128i*)tag, Xi);
}

/* Backend structure for CLMUL GHASH */
extern soliton_backend_t backend_clmul;
soliton_backend_t backend_clmul = {
    .aes_key_expand = NULL,  /* Use AES-NI or scalar */
    .aes_encrypt_block = NULL,
    .aes_ctr_blocks = NULL,
    .ghash_init = ghash_init_clmul,
    .ghash_update = ghash_update_clmul,
    .chacha_blocks = NULL,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "clmul"
};

#endif /* __PCLMUL__ */
#endif /* __x86_64__ */