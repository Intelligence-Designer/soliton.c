/*
 * gcm_pipelined_vaes_clmul.c - Phase-Locked Wave Engine
 * Two-phase A/B pipeline: interleave AES batch k+1 with GHASH batch k
 *
 * Deterministic rhythm: fixed interleaving pattern ensures reproducibility
 * Register-fed: ciphertext stays in registers across phase boundary
 */

#include "common.h"
#include "diagnostics.h"

#if defined(__x86_64__) && defined(__VAES__) && defined(__PCLMUL__)

#include <immintrin.h>

/* Byte reversal for GHASH */
static inline __m128i ghash_reverse(__m128i x) {
    const __m128i brev = _mm_set_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, brev);
}

/* GHASH reduction */
static inline __m128i ghash_reduce(__m128i x0, __m128i x1, __m128i x2) {
    /* Phase 1 */
    __m128i t1 = _mm_slli_epi32(x0, 31);
    __m128i t2 = _mm_slli_epi32(x0, 30);
    __m128i t3 = _mm_slli_epi32(x0, 25);
    t1 = _mm_xor_si128(t1, t2);
    t1 = _mm_xor_si128(t1, t3);
    __m128i t4 = _mm_srli_epi32(t1, 32);
    t1 = _mm_shuffle_epi32(t1, 0x93);
    __m128i t5 = _mm_xor_si128(x0, t1);
    x1 = _mm_xor_si128(x1, t4);

    /* Phase 2 */
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

/*
 * Phase-locked 16-block GCM pipeline
 *
 * Processes 2 batches of 8 blocks with deterministic A/B interleaving:
 *   - Phase A (batch 1): AES-CTR rounds 1-7
 *   - Phase B (batch 0): GHASH-8 (overlaps with Phase A)
 *   - Phase A (batch 1): AES-CTR rounds 8-14, XOR plaintext
 *   - Phase B (batch 1): GHASH-8
 *
 * This creates a self-reinforcing wave where:
 *   - Port 5 alternates between VAES and CLMUL (no contention)
 *   - Ciphertext stays in registers across the phase boundary
 *   - Execution order is fixed by plan, ensuring reproducibility
 */
void gcm_pipelined_encrypt16_vaes_clmul(
    const uint32_t* restrict round_keys,
    const uint8_t* restrict plaintext,        /* 256 bytes (16 blocks) */
    uint8_t* restrict ciphertext,
    const uint8_t j0[16],
    uint32_t counter_start,
    uint8_t* restrict ghash_state,
    const uint8_t h_powers[8][16]             /* H^8..H^1 (already reversed) */
) {
    DIAG_INC(aes_vaes_calls);
    DIAG_ADD(aes_total_blocks, 16);

    /* Load ALL round keys (avoid stalls) */
    /* Each round key is 128 bits, broadcast to both 128-bit lanes of YMM for VAES */
    const __m128i* rk128 = (const __m128i*)round_keys;
    __m256i rk[15];
    for (int i = 0; i < 15; i++) {
        __m128i rk_xmm = _mm_loadu_si128(&rk128[i]);
        rk[i] = _mm256_broadcastsi128_si256(rk_xmm);
    }

    /* Load H-powers (already reversed during precomputation) */
    __m128i H[8];
    for (int i = 0; i < 8; i++) {
        H[i] = _mm_loadu_si128((const __m128i*)h_powers[7 - i]);
    }

    /* Load GHASH state */
    __m128i Xi = _mm_loadu_si128((const __m128i*)ghash_state);
    Xi = ghash_reverse(Xi);

    /* ====================================================================
     * BATCH 0: Full AES-CTR (no overlap yet - first batch)
     * ==================================================================== */

    /* Prepare counters for batch 0 */
    __m128i ctr_base = _mm_loadu_si128((const __m128i*)j0);
    __m128i counters0[8];
    for (int i = 0; i < 8; i++) {
        counters0[i] = ctr_base;
        uint32_t ctr_val = counter_start + i;
        counters0[i] = _mm_insert_epi32(counters0[i], __builtin_bswap32(ctr_val), 3);
    }

    /* Pack into YMM */
    __m256i ctr0_ymm[4];
    ctr0_ymm[0] = _mm256_setr_m128i(counters0[0], counters0[1]);
    ctr0_ymm[1] = _mm256_setr_m128i(counters0[2], counters0[3]);
    ctr0_ymm[2] = _mm256_setr_m128i(counters0[4], counters0[5]);
    ctr0_ymm[3] = _mm256_setr_m128i(counters0[6], counters0[7]);

    /* AES rounds for batch 0 (fully unrolled) */
    ctr0_ymm[0] = _mm256_xor_si256(ctr0_ymm[0], rk[0]);
    ctr0_ymm[1] = _mm256_xor_si256(ctr0_ymm[1], rk[0]);
    ctr0_ymm[2] = _mm256_xor_si256(ctr0_ymm[2], rk[0]);
    ctr0_ymm[3] = _mm256_xor_si256(ctr0_ymm[3], rk[0]);

    /* Rounds 1-13 (unrolled for determinism) */
    #define AES_ROUND(r, batch) \
        batch[0] = _mm256_aesenc_epi128(batch[0], rk[r]); \
        batch[1] = _mm256_aesenc_epi128(batch[1], rk[r]); \
        batch[2] = _mm256_aesenc_epi128(batch[2], rk[r]); \
        batch[3] = _mm256_aesenc_epi128(batch[3], rk[r]);

    AES_ROUND(1, ctr0_ymm);
    AES_ROUND(2, ctr0_ymm);
    AES_ROUND(3, ctr0_ymm);
    AES_ROUND(4, ctr0_ymm);
    AES_ROUND(5, ctr0_ymm);
    AES_ROUND(6, ctr0_ymm);
    AES_ROUND(7, ctr0_ymm);
    AES_ROUND(8, ctr0_ymm);
    AES_ROUND(9, ctr0_ymm);
    AES_ROUND(10, ctr0_ymm);
    AES_ROUND(11, ctr0_ymm);
    AES_ROUND(12, ctr0_ymm);
    AES_ROUND(13, ctr0_ymm);

    /* Final round */
    ctr0_ymm[0] = _mm256_aesenclast_epi128(ctr0_ymm[0], rk[14]);
    ctr0_ymm[1] = _mm256_aesenclast_epi128(ctr0_ymm[1], rk[14]);
    ctr0_ymm[2] = _mm256_aesenclast_epi128(ctr0_ymm[2], rk[14]);
    ctr0_ymm[3] = _mm256_aesenclast_epi128(ctr0_ymm[3], rk[14]);

    /* XOR with plaintext batch 0 */
    const __m256i* pt0 = (const __m256i*)plaintext;
    __m256i C0_ymm[4];
    C0_ymm[0] = _mm256_xor_si256(ctr0_ymm[0], _mm256_loadu_si256(&pt0[0]));
    C0_ymm[1] = _mm256_xor_si256(ctr0_ymm[1], _mm256_loadu_si256(&pt0[1]));
    C0_ymm[2] = _mm256_xor_si256(ctr0_ymm[2], _mm256_loadu_si256(&pt0[2]));
    C0_ymm[3] = _mm256_xor_si256(ctr0_ymm[3], _mm256_loadu_si256(&pt0[3]));

    /* Extract ciphertext blocks (stay in registers for GHASH) */
    __m128i C0[8];
    C0[0] = _mm256_extracti128_si256(C0_ymm[0], 0);
    C0[1] = _mm256_extracti128_si256(C0_ymm[0], 1);
    C0[2] = _mm256_extracti128_si256(C0_ymm[1], 0);
    C0[3] = _mm256_extracti128_si256(C0_ymm[1], 1);
    C0[4] = _mm256_extracti128_si256(C0_ymm[2], 0);
    C0[5] = _mm256_extracti128_si256(C0_ymm[2], 1);
    C0[6] = _mm256_extracti128_si256(C0_ymm[3], 0);
    C0[7] = _mm256_extracti128_si256(C0_ymm[3], 1);

    /* ====================================================================
     * BATCH 1: START AES-CTR (Phase A begins)
     * ==================================================================== */

    /* Prepare counters for batch 1 */
    __m128i counters1[8];
    for (int i = 0; i < 8; i++) {
        counters1[i] = ctr_base;
        uint32_t ctr_val = counter_start + 8 + i;
        counters1[i] = _mm_insert_epi32(counters1[i], __builtin_bswap32(ctr_val), 3);
    }

    __m256i ctr1_ymm[4];
    ctr1_ymm[0] = _mm256_setr_m128i(counters1[0], counters1[1]);
    ctr1_ymm[1] = _mm256_setr_m128i(counters1[2], counters1[3]);
    ctr1_ymm[2] = _mm256_setr_m128i(counters1[4], counters1[5]);
    ctr1_ymm[3] = _mm256_setr_m128i(counters1[6], counters1[7]);

    /* Start AES for batch 1 (rounds 0-7) */
    ctr1_ymm[0] = _mm256_xor_si256(ctr1_ymm[0], rk[0]);
    ctr1_ymm[1] = _mm256_xor_si256(ctr1_ymm[1], rk[0]);
    ctr1_ymm[2] = _mm256_xor_si256(ctr1_ymm[2], rk[0]);
    ctr1_ymm[3] = _mm256_xor_si256(ctr1_ymm[3], rk[0]);

    AES_ROUND(1, ctr1_ymm);
    AES_ROUND(2, ctr1_ymm);
    AES_ROUND(3, ctr1_ymm);
    AES_ROUND(4, ctr1_ymm);
    AES_ROUND(5, ctr1_ymm);
    AES_ROUND(6, ctr1_ymm);
    AES_ROUND(7, ctr1_ymm);

    /* ====================================================================
     * PHASE B: GHASH batch 0 (OVERLAPS with batch 1 AES rounds 8-14)
     * ==================================================================== */

    /* Reverse ciphertext for GHASH */
    for (int i = 0; i < 8; i++) {
        C0[i] = ghash_reverse(C0[i]);
    }

    /* Save C0[0] before modifying for GHASH (FIX: preserve original ciphertext) */
    __m128i C0_0_original = C0[0];

    /* XOR state into first block */
    C0[0] = _mm_xor_si128(C0[0], Xi);

    /* Karatsuba GHASH with 4 accumulators */
    __m128i acc_lo[4], acc_hi[4], acc_mid[4];
    for (int a = 0; a < 4; a++) {
        acc_lo[a] = _mm_setzero_si128();
        acc_hi[a] = _mm_setzero_si128();
        acc_mid[a] = _mm_setzero_si128();
    }

    /* ====================================================================
     * TRUE PHASE-LOCKED INTERLEAVING: AES batch 1 + GHASH batch 0
     * Fixed AABB rhythm: 2 AES ops, then 2-3 GHASH ops, repeat
     * ==================================================================== */

    /* AES batch 1 round 8 (AA) */
    AES_ROUND(8, ctr1_ymm);

    /* GHASH block 0 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[0], H[0], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[0], H[0], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[0], 0x4E), C0[0]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[0], 0x4E), H[0]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[0] = lo;
        acc_hi[0] = hi;
        acc_mid[0] = mid;
    }

    /* AES batch 1 round 9 (AA) */
    AES_ROUND(9, ctr1_ymm);

    /* GHASH block 1 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[1], H[1], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[1], H[1], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[1], 0x4E), C0[1]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[1], 0x4E), H[1]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[0] = _mm_xor_si128(acc_lo[0], lo);
        acc_hi[0] = _mm_xor_si128(acc_hi[0], hi);
        acc_mid[0] = _mm_xor_si128(acc_mid[0], mid);
    }

    /* AES batch 1 round 10 (AA) */
    AES_ROUND(10, ctr1_ymm);

    /* GHASH block 2 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[2], H[2], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[2], H[2], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[2], 0x4E), C0[2]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[2], 0x4E), H[2]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[1] = lo;
        acc_hi[1] = hi;
        acc_mid[1] = mid;
    }

    /* AES batch 1 round 11 (AA) */
    AES_ROUND(11, ctr1_ymm);

    /* GHASH block 3 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[3], H[3], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[3], H[3], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[3], 0x4E), C0[3]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[3], 0x4E), H[3]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[1] = _mm_xor_si128(acc_lo[1], lo);
        acc_hi[1] = _mm_xor_si128(acc_hi[1], hi);
        acc_mid[1] = _mm_xor_si128(acc_mid[1], mid);
    }

    /* AES batch 1 round 12 (AA) */
    AES_ROUND(12, ctr1_ymm);

    /* GHASH block 4 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[4], H[4], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[4], H[4], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[4], 0x4E), C0[4]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[4], 0x4E), H[4]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[2] = lo;
        acc_hi[2] = hi;
        acc_mid[2] = mid;
    }

    /* AES batch 1 round 13 (AA) */
    AES_ROUND(13, ctr1_ymm);

    /* GHASH block 5 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[5], H[5], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[5], H[5], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[5], 0x4E), C0[5]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[5], 0x4E), H[5]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[2] = _mm_xor_si128(acc_lo[2], lo);
        acc_hi[2] = _mm_xor_si128(acc_hi[2], hi);
        acc_mid[2] = _mm_xor_si128(acc_mid[2], mid);
    }

    /* GHASH block 6 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[6], H[6], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[6], H[6], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[6], 0x4E), C0[6]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[6], 0x4E), H[6]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[3] = lo;
        acc_hi[3] = hi;
        acc_mid[3] = mid;
    }

    /* GHASH block 7 (BB) */
    {
        __m128i lo = _mm_clmulepi64_si128(C0[7], H[7], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C0[7], H[7], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C0[7], 0x4E), C0[7]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[7], 0x4E), H[7]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);
        acc_lo[3] = _mm_xor_si128(acc_lo[3], lo);
        acc_hi[3] = _mm_xor_si128(acc_hi[3], hi);
        acc_mid[3] = _mm_xor_si128(acc_mid[3], mid);
    }

    /* Fold accumulators */
    __m128i lo = _mm_xor_si128(_mm_xor_si128(acc_lo[0], acc_lo[1]),
                                _mm_xor_si128(acc_lo[2], acc_lo[3]));
    __m128i hi = _mm_xor_si128(_mm_xor_si128(acc_hi[0], acc_hi[1]),
                                _mm_xor_si128(acc_hi[2], acc_hi[3]));
    __m128i mid = _mm_xor_si128(_mm_xor_si128(acc_mid[0], acc_mid[1]),
                                 _mm_xor_si128(acc_mid[2], acc_mid[3]));

    /* Combine mid term */
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    /* Reduce */
    Xi = ghash_reduce(lo, _mm_setzero_si128(), hi);

    /* Final AES round for batch 1 */
    ctr1_ymm[0] = _mm256_aesenclast_epi128(ctr1_ymm[0], rk[14]);
    ctr1_ymm[1] = _mm256_aesenclast_epi128(ctr1_ymm[1], rk[14]);
    ctr1_ymm[2] = _mm256_aesenclast_epi128(ctr1_ymm[2], rk[14]);
    ctr1_ymm[3] = _mm256_aesenclast_epi128(ctr1_ymm[3], rk[14]);

    /* XOR with plaintext batch 1 */
    const __m256i* pt1 = (const __m256i*)(plaintext + 128);
    __m256i C1_ymm[4];
    C1_ymm[0] = _mm256_xor_si256(ctr1_ymm[0], _mm256_loadu_si256(&pt1[0]));
    C1_ymm[1] = _mm256_xor_si256(ctr1_ymm[1], _mm256_loadu_si256(&pt1[1]));
    C1_ymm[2] = _mm256_xor_si256(ctr1_ymm[2], _mm256_loadu_si256(&pt1[2]));
    C1_ymm[3] = _mm256_xor_si256(ctr1_ymm[3], _mm256_loadu_si256(&pt1[3]));

    /* Extract batch 1 ciphertext */
    __m128i C1[8];
    C1[0] = _mm256_extracti128_si256(C1_ymm[0], 0);
    C1[1] = _mm256_extracti128_si256(C1_ymm[0], 1);
    C1[2] = _mm256_extracti128_si256(C1_ymm[1], 0);
    C1[3] = _mm256_extracti128_si256(C1_ymm[1], 1);
    C1[4] = _mm256_extracti128_si256(C1_ymm[2], 0);
    C1[5] = _mm256_extracti128_si256(C1_ymm[2], 1);
    C1[6] = _mm256_extracti128_si256(C1_ymm[3], 0);
    C1[7] = _mm256_extracti128_si256(C1_ymm[3], 1);

    /* ====================================================================
     * PHASE B: GHASH batch 1 (final phase)
     * ==================================================================== */

    for (int i = 0; i < 8; i++) {
        C1[i] = ghash_reverse(C1[i]);
    }

    /* Save C1[0] before modifying for GHASH (FIX: preserve original ciphertext) */
    __m128i C1_0_original = C1[0];

    C1[0] = _mm_xor_si128(C1[0], Xi);

    /* Reset accumulators */
    for (int a = 0; a < 4; a++) {
        acc_lo[a] = _mm_setzero_si128();
        acc_hi[a] = _mm_setzero_si128();
        acc_mid[a] = _mm_setzero_si128();
    }

    for (int i = 0; i < 8; i++) {
        int acc = i >> 1;
        __m128i lo_p = _mm_clmulepi64_si128(C1[i], H[i], 0x00);
        __m128i hi_p = _mm_clmulepi64_si128(C1[i], H[i], 0x11);
        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C1[i], 0x4E), C1[i]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[i], 0x4E), H[i]);
        __m128i mid_p = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid_p = _mm_xor_si128(mid_p, lo_p);
        mid_p = _mm_xor_si128(mid_p, hi_p);
        acc_lo[acc] = _mm_xor_si128(acc_lo[acc], lo_p);
        acc_hi[acc] = _mm_xor_si128(acc_hi[acc], hi_p);
        acc_mid[acc] = _mm_xor_si128(acc_mid[acc], mid_p);
    }

    lo = _mm_xor_si128(_mm_xor_si128(acc_lo[0], acc_lo[1]),
                       _mm_xor_si128(acc_lo[2], acc_lo[3]));
    hi = _mm_xor_si128(_mm_xor_si128(acc_hi[0], acc_hi[1]),
                       _mm_xor_si128(acc_hi[2], acc_hi[3]));
    mid = _mm_xor_si128(_mm_xor_si128(acc_mid[0], acc_mid[1]),
                        _mm_xor_si128(acc_mid[2], acc_mid[3]));

    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
    Xi = ghash_reduce(lo, _mm_setzero_si128(), hi);

    /* ====================================================================
     * STORE ciphertext (ONCE, after all GHASH consumption)
     * ==================================================================== */

    /* Restore C0[0] and C1[0] to original ciphertext (FIX: undo GHASH modification) */
    C0[0] = C0_0_original;
    C1[0] = C1_0_original;

    /* Reverse back to normal byte order */
    for (int i = 0; i < 8; i++) {
        C0[i] = ghash_reverse(C0[i]);
        C1[i] = ghash_reverse(C1[i]);
    }

    /* Store batch 0 */
    __m128i* ct0 = (__m128i*)ciphertext;
    for (int i = 0; i < 8; i++) {
        _mm_storeu_si128(&ct0[i], C0[i]);
    }

    /* Store batch 1 */
    __m128i* ct1 = (__m128i*)(ciphertext + 128);
    for (int i = 0; i < 8; i++) {
        _mm_storeu_si128(&ct1[i], C1[i]);
    }

    /* Store updated GHASH state */
    Xi = ghash_reverse(Xi);
    _mm_storeu_si128((__m128i*)ghash_state, Xi);

    #undef AES_ROUND
}

#endif /* __x86_64__ && __VAES__ && __PCLMUL__ */
