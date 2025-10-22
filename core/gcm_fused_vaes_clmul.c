/*
 * gcm_fused_vaes_clmul.c - Single-pass fused AES-GCM kernel
 * Write-avoid: CTR blocks stay in registers, feed GHASH, then store once
 *
 * Domain contract: Xi, H, H^i are stored in CLMUL (byte-reversed) domain.
 * All ingress (ciphertext from AES) is converted with to_lepoly(); see docs/ghash_domain_contract.md
 */

#include "common.h"
#include "diagnostics.h"

#if defined(__x86_64__) && defined(__VAES__) && defined(__PCLMUL__)

#include <immintrin.h>

/* =============================================================================
 * DOMAIN SHIMS & UNIFIED PRIMITIVES (matching ghash_clmul.c)
 * API boundary: GCM spec (big-endian) ↔ kernel domain (little-endian)
 * ============================================================================= */
static inline __m128i to_lepoly_128(__m128i x_spec) {
    const __m128i bswap_mask = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_spec, bswap_mask);
}

static inline __m128i from_lepoly_128(__m128i x_kernel) {
    const __m128i bswap_mask = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_kernel, bswap_mask);
}

/* Import unified primitives from ghash_clmul.c */
extern __m128i ghash_mul_lepoly_clmul(__m128i a_le, __m128i b_le);
extern __m128i ghash_reduce_256_to_128_lepoly(__m128i lo, __m128i hi);

/* External scalar AES helpers */
extern void aes256_encrypt_block_scalar(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]);

/* Include stdio for debug output */
#if defined(SOLITON_TRACE_GHASH) || defined(FUSED_DEBUG_REF)
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

/* =============================================================================
 * DIAGNOSTIC TOGGLES (compile-time)
 * ============================================================================= */
#ifndef FUSED_USE_REF_MULT
#define FUSED_USE_REF_MULT 0    /* 0=hot path Karatsuba, 1=unified ghash_mul_lepoly_clmul */
#endif

#ifndef FUSED_USE_REF_FOLD
#define FUSED_USE_REF_FOLD 0    /* 0=hot path Karatsuba (Gate P0 verified), 1=bypass to reference */
#endif

#ifndef SOLITON_TRACE_GHASH
#define SOLITON_TRACE_GHASH 0   /* 1=enable inline oracle */
#endif

/* =============================================================================
 * REFERENCE FUSED FOLD: Known-good implementation for comparison
 * Inputs: Xi_le (GHASH state in CLMUL domain)
 *         C_spec[8] (ciphertext in SPEC domain)
 *         Hpow_desc_le[8] = {H^8, H^7, ..., H^1} in CLMUL domain
 * Output: Updated Xi in CLMUL domain
 * Math: Xi_out = (Xi ⊕ C0)*H^8 ⊕ C1*H^7 ⊕ ... ⊕ C7*H^1
 * ============================================================================= */
static inline __m128i fused_fold_8_ref(__m128i Xi_le,
                                       const __m128i C_spec[8],
                                       const __m128i Hpow_desc_le[8]) {
    __m128i C_le[8];
    for (int i = 0; i < 8; i++) {
        C_le[i] = to_lepoly_128(C_spec[i]);
    }

    #ifdef FUSED_DEBUG_REF
    printf("REF FOLD DEBUG:\n");
    TRACE_HEX("Xi_le input", Xi_le);
    for (int i = 0; i < 8; i++) {
        printf("C_spec[%d]: ", i);
        TRACE_HEX("", C_spec[i]);
        printf("H^%d: ", 8-i);
        TRACE_HEX("", Hpow_desc_le[i]);
    }
    #endif

    /* Xi_out = (Xi ⊕ C[0])*H^8 ⊕ C[1]*H^7 ⊕ ... ⊕ C[7]*H^1
     * Oldest block C[0] gets HIGHEST power H^8, newest block C[7] gets LOWEST power H^1 */
    __m128i acc = ghash_mul_lepoly_clmul(_mm_xor_si128(Xi_le, C_le[0]), Hpow_desc_le[0]);  // (Xi⊕C[0])*H^8
    for (int i = 1; i < 8; i++) {
        acc = _mm_xor_si128(acc, ghash_mul_lepoly_clmul(C_le[i], Hpow_desc_le[i]));  // C[i]*H^(8-i)
    }

    #ifdef FUSED_DEBUG_REF
    TRACE_HEX("Xi_le output", acc);
    #endif

    return acc;
}

/*
 * Fused AES-GCM encrypt kernel: single-pass, write-avoid
 *
 * Input: 8 plaintext blocks, round keys, counters, GHASH state, H-powers
 * Output: 8 ciphertext blocks (stored once), updated GHASH state
 *
 * Key optimization: ciphertext stays in registers (C0...C7), fed to GHASH
 * before any store. Eliminates reload and store-forwarding stalls.
 */
void gcm_fused_encrypt8_vaes_clmul(
    const uint32_t* restrict round_keys,      /* AES-256 expanded keys */
    const uint8_t* restrict plaintext,        /* 128 bytes (8 blocks) */
    uint8_t* restrict ciphertext,             /* 128 bytes output */
    const uint8_t j0[16],                     /* Initial counter block */
    uint32_t counter_start,                   /* Starting counter value */
    uint8_t* restrict ghash_state,            /* 16 bytes GHASH accumulator */
    const uint8_t h_powers[8][16]             /* H^8...H^1 (64B aligned) */
) {
    /* Diagnostics: track that AES and GHASH happen in same batch */
    DIAG_INC(aes_vaes_calls);
    DIAG_ADD(aes_total_blocks, 8);

    /* Load ALL round keys into YMM registers (avoid loading in loop - causes stalls) */
    /* Each round key is 128 bits, broadcast to both 128-bit lanes of YMM for VAES */
    const __m128i* rk128 = (const __m128i*)round_keys;
    __m256i rk[15];  /* All 15 round keys for AES-256 (0-14) */
    for (int i = 0; i < 15; i++) {
        __m128i rk_xmm = _mm_loadu_si128(&rk128[i]);
        rk[i] = _mm256_broadcastsi128_si256(rk_xmm);
    }

    /* Prepare 8 counter blocks */
    __m128i ctr_base = _mm_loadu_si128((const __m128i*)j0);
    __m128i counters[8];
    for (int i = 0; i < 8; i++) {
        counters[i] = ctr_base;
        /* Set counter value (big-endian 32-bit at bytes 12-15) */
        uint32_t ctr_val = counter_start + i;
        counters[i] = _mm_insert_epi32(counters[i], __builtin_bswap32(ctr_val), 3);
    }

    /* Pack 8 counters into 4 YMM registers for VAES */
    __m256i ctr_ymm[4];
    ctr_ymm[0] = _mm256_setr_m128i(counters[0], counters[1]);
    ctr_ymm[1] = _mm256_setr_m128i(counters[2], counters[3]);
    ctr_ymm[2] = _mm256_setr_m128i(counters[4], counters[5]);
    ctr_ymm[3] = _mm256_setr_m128i(counters[6], counters[7]);

    /* AES-256 encryption: 14 rounds (XOR + 13 AESENC + AESENCLAST) */
    /* Round 0: AddRoundKey */
    ctr_ymm[0] = _mm256_xor_si256(ctr_ymm[0], rk[0]);
    ctr_ymm[1] = _mm256_xor_si256(ctr_ymm[1], rk[0]);
    ctr_ymm[2] = _mm256_xor_si256(ctr_ymm[2], rk[0]);
    ctr_ymm[3] = _mm256_xor_si256(ctr_ymm[3], rk[0]);

    /* Rounds 1-13: AESENC (fully unrolled for maximum pipelining) */
    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[1]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[1]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[1]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[1]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[2]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[2]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[2]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[2]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[3]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[3]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[3]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[3]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[4]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[4]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[4]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[4]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[5]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[5]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[5]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[5]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[6]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[6]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[6]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[6]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[7]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[7]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[7]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[7]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[8]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[8]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[8]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[8]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[9]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[9]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[9]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[9]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[10]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[10]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[10]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[10]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[11]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[11]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[11]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[11]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[12]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[12]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[12]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[12]);

    ctr_ymm[0] = _mm256_aesenc_epi128(ctr_ymm[0], rk[13]);
    ctr_ymm[1] = _mm256_aesenc_epi128(ctr_ymm[1], rk[13]);
    ctr_ymm[2] = _mm256_aesenc_epi128(ctr_ymm[2], rk[13]);
    ctr_ymm[3] = _mm256_aesenc_epi128(ctr_ymm[3], rk[13]);

    /* Round 14: AESENCLAST */
    ctr_ymm[0] = _mm256_aesenclast_epi128(ctr_ymm[0], rk[14]);
    ctr_ymm[1] = _mm256_aesenclast_epi128(ctr_ymm[1], rk[14]);
    ctr_ymm[2] = _mm256_aesenclast_epi128(ctr_ymm[2], rk[14]);
    ctr_ymm[3] = _mm256_aesenclast_epi128(ctr_ymm[3], rk[14]);

    /* Load plaintext and XOR to produce ciphertext IN REGISTERS */
    const __m256i* pt256 = (const __m256i*)plaintext;
    __m256i C_ymm[4];
    C_ymm[0] = _mm256_xor_si256(ctr_ymm[0], _mm256_loadu_si256(&pt256[0]));
    C_ymm[1] = _mm256_xor_si256(ctr_ymm[1], _mm256_loadu_si256(&pt256[1]));
    C_ymm[2] = _mm256_xor_si256(ctr_ymm[2], _mm256_loadu_si256(&pt256[2]));
    C_ymm[3] = _mm256_xor_si256(ctr_ymm[3], _mm256_loadu_si256(&pt256[3]));

    /* Extract 8 ciphertext blocks as 128-bit XMM (stay in registers!) */
    __m128i C[8];
    C[0] = _mm256_extracti128_si256(C_ymm[0], 0);
    C[1] = _mm256_extracti128_si256(C_ymm[0], 1);
    C[2] = _mm256_extracti128_si256(C_ymm[1], 0);
    C[3] = _mm256_extracti128_si256(C_ymm[1], 1);
    C[4] = _mm256_extracti128_si256(C_ymm[2], 0);
    C[5] = _mm256_extracti128_si256(C_ymm[2], 1);
    C[6] = _mm256_extracti128_si256(C_ymm[3], 0);
    C[7] = _mm256_extracti128_si256(C_ymm[3], 1);

    /* ====================================================================
     * CRITICAL: Feed C0...C7 to GHASH **BEFORE** storing to memory
     * This eliminates reload and enables true single-pass
     * ==================================================================== */

    /* Load current GHASH state Xi (already in CLMUL domain from storage) */
    __m128i Xi = _mm_loadu_si128((const __m128i*)ghash_state);

    /* Load H-powers: H^8, H^7, ..., H^1 (already in CLMUL domain from precompute)
     * GCM GHASH for 8 blocks: Xi_out = (Xi ⊕ C[0])*H^8 ⊕ C[1]*H^7 ⊕ ... ⊕ C[7]*H^1
     * Oldest block C[0] gets HIGHEST power H^8, newest block C[7] gets LOWEST power H^1 */
    __m128i H[8];
    for (int i = 0; i < 8; i++) {
        H[i] = _mm_loadu_si128((const __m128i*)h_powers[7 - i]);  // H[0]=H^8, H[7]=H^1
    }

    #if FUSED_USE_REF_FOLD
    /* BYPASS: Use reference fold for known-good result */
    Xi = fused_fold_8_ref(Xi, C, H);
    #else
    /* HOT PATH: Optimized Karatsuba fold */

    /* Convert ciphertext C[0..7] from spec domain → CLMUL domain (ONE conversion point) */
    __m128i C_le[8];
    for (int i = 0; i < 8; i++) {
        C_le[i] = to_lepoly_128(C[i]);
    }

    /* XOR state into first ciphertext block (both now in CLMUL domain) */
    C_le[0] = _mm_xor_si128(C_le[0], Xi);

    /* Karatsuba CLMUL with 4 accumulators (hide port 5 latency) */
    __m128i acc_lo[4], acc_hi[4], acc_mid[4];
    for (int a = 0; a < 4; a++) {
        acc_lo[a] = _mm_setzero_si128();
        acc_hi[a] = _mm_setzero_si128();
        acc_mid[a] = _mm_setzero_si128();
    }

    /* Process 8 blocks across 4 accumulators (2 blocks per accumulator)
     * All operations in CLMUL domain: C_le[i] * H[i] */
    for (int i = 0; i < 8; i++) {
        int acc = i >> 1;  /* accumulator index: 0,0,1,1,2,2,3,3 */

        /* Karatsuba: (a_lo, a_hi) * (b_lo, b_hi) */
        __m128i a_lo_b_lo = _mm_clmulepi64_si128(C_le[i], H[i], 0x00);
        __m128i a_hi_b_hi = _mm_clmulepi64_si128(C_le[i], H[i], 0x11);

        /* Mid term: (a_lo ⊕ a_hi) * (b_lo ⊕ b_hi) */
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C_le[i], 0x4E), C_le[i]);
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

    /* Single polynomial reduction using unified reducer (result remains in CLMUL domain) */
    Xi = ghash_reduce_256_to_128_lepoly(lo, hi);

    #ifdef FUSED_DEBUG_REF
    printf("HOT PATH result:\n");
    TRACE_HEX("Xi from hot path", Xi);
    #endif

    #endif  /* FUSED_USE_REF_FOLD */

    /* Store updated GHASH state (keep in CLMUL domain - no conversion) */
    _mm_storeu_si128((__m128i*)ghash_state, Xi);

    #ifdef FUSED_DEBUG_REF
    TRACE_HEX("Xi stored to ghash_state", Xi);
    #endif

    /* ====================================================================
     * NOW store ciphertext blocks (ONCE, after GHASH consumed them)
     * C[] contains ciphertext in spec domain - ready for caller
     * ==================================================================== */

    __m128i* ct128 = (__m128i*)ciphertext;
    for (int i = 0; i < 8; i++) {
        _mm_storeu_si128(&ct128[i], C[i]);
    }
}

#endif /* __x86_64__ && __VAES__ && __PCLMUL__ */
