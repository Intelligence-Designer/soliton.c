/**
 * gcm_fused16_vaes_clmul.c - Depth-16 fused AES-GCM kernel (non-pipelined)
 *
 * Processes 16 blocks (256 bytes) using H^1..H^16 with single reduction tree.
 * Expected improvement: 1.2-1.4× over depth-8 due to:
 * - Single reduction per 16 blocks (vs 2 reductions for 2×8)
 * - Better amortization of setup overhead
 * - Deeper GHASH fold tree
 */

#include "common.h"

#ifdef __x86_64__

#include <immintrin.h>

/* Fused encrypt 16 blocks with VAES + CLMUL GHASH using H^1..H^16 */
void gcm_fused_encrypt16_vaes_clmul(
    const uint32_t round_keys[60],
    const uint8_t pt[256],          /* 16 blocks plaintext */
    uint8_t ct[256],                /* 16 blocks ciphertext */
    const uint8_t j0[16],
    uint32_t counter_start,
    uint8_t ghash_state[16],
    const uint8_t (*h_powers)[16]   /* H^16..H^1 */
) {
    /* Load round keys (AES-256 = 15 rounds, but only 14 after initial XOR) */
    __m256i rk[15];
    for (int r = 0; r < 15; r++) {
        __m128i rk_lo = _mm_loadu_si128((const __m128i*)&round_keys[r * 4]);
        rk[r] = _mm256_broadcastsi128_si256(rk_lo);
    }

    /* Prepare 16 counter blocks */
    __m256i ctrs[8];  /* 8 ymm registers × 2 blocks per ymm = 16 blocks */

    /* Load j0 base and generate counter blocks */
    __m128i ctr_base = _mm_loadu_si128((const __m128i*)j0);

    /* Generate 16 counter blocks (2 per ymm register) */
    for (int i = 0; i < 8; i++) {
        /* Create two counter blocks */
        __m128i ctr_lo = ctr_base;
        __m128i ctr_hi = ctr_base;

        /* Set counter values (big-endian 32-bit at bytes 12-15) */
        uint32_t ctr_val1 = counter_start + i*2;
        uint32_t ctr_val2 = counter_start + i*2 + 1;

        ctr_lo = _mm_insert_epi32(ctr_lo, __builtin_bswap32(ctr_val1), 3);
        ctr_hi = _mm_insert_epi32(ctr_hi, __builtin_bswap32(ctr_val2), 3);

        ctrs[i] = _mm256_setr_m128i(ctr_lo, ctr_hi);
    }

    /* AES rounds 0-13 for all 16 blocks */
    for (int r = 0; r < 14; r++) {
        for (int i = 0; i < 8; i++) {
            ctrs[i] = _mm256_aesenc_epi128(ctrs[i], rk[r]);
        }
    }

    /* Final AES round */
    for (int i = 0; i < 8; i++) {
        ctrs[i] = _mm256_aesenclast_epi128(ctrs[i], rk[14]);
    }

    /* XOR with plaintext and store ciphertext */
    __m128i C[16];  /* Ciphertext blocks for GHASH */
    for (int i = 0; i < 8; i++) {
        __m256i pt_blocks = _mm256_loadu_si256((const __m256i*)&pt[i * 32]);
        __m256i ct_blocks = _mm256_xor_si256(ctrs[i], pt_blocks);
        _mm256_storeu_si256((__m256i*)&ct[i * 32], ct_blocks);

        /* Extract 128-bit blocks for GHASH */
        C[i*2] = _mm256_castsi256_si128(ct_blocks);
        C[i*2+1] = _mm256_extracti128_si256(ct_blocks, 1);
    }

    /* GHASH: Multiply each ciphertext block by corresponding H power */

    /* Load current GHASH state Xi (already in normal byte order) */
    __m128i Xi = _mm_loadu_si128((const __m128i*)ghash_state);

    /* Load H powers (in normal byte order) */
    __m128i H[16];
    for (int i = 0; i < 16; i++) {
        H[i] = _mm_loadu_si128((const __m128i*)h_powers[15-i]);  /* H^16..H^1 */
    }

    /* Save C[0] before modifying for GHASH (FIX: preserve original ciphertext) */
    __m128i C0_original = C[0];

    /* XOR state into first ciphertext block */
    C[0] = _mm_xor_si128(C[0], Xi);

    /* Karatsuba multiplication for all 16 blocks */
    __m128i acc_lo[16], acc_hi[16], acc_mid[16];

    for (int i = 0; i < 16; i++) {
        __m128i lo = _mm_clmulepi64_si128(C[i], H[i], 0x00);
        __m128i hi = _mm_clmulepi64_si128(C[i], H[i], 0x11);

        __m128i a_xor = _mm_xor_si128(_mm_shuffle_epi32(C[i], 0x4E), C[i]);
        __m128i b_xor = _mm_xor_si128(_mm_shuffle_epi32(H[i], 0x4E), H[i]);
        __m128i mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        mid = _mm_xor_si128(mid, lo);
        mid = _mm_xor_si128(mid, hi);

        acc_lo[i] = lo;
        acc_hi[i] = hi;
        acc_mid[i] = mid;
    }

    /* Reduction tree: 16 -> 8 -> 4 -> 2 -> 1 */
    for (int i = 0; i < 8; i++) {
        acc_lo[i] = _mm_xor_si128(acc_lo[i], acc_lo[i + 8]);
        acc_hi[i] = _mm_xor_si128(acc_hi[i], acc_hi[i + 8]);
        acc_mid[i] = _mm_xor_si128(acc_mid[i], acc_mid[i + 8]);
    }

    for (int i = 0; i < 4; i++) {
        acc_lo[i] = _mm_xor_si128(acc_lo[i], acc_lo[i + 4]);
        acc_hi[i] = _mm_xor_si128(acc_hi[i], acc_hi[i + 4]);
        acc_mid[i] = _mm_xor_si128(acc_mid[i], acc_mid[i + 4]);
    }

    for (int i = 0; i < 2; i++) {
        acc_lo[i] = _mm_xor_si128(acc_lo[i], acc_lo[i + 2]);
        acc_hi[i] = _mm_xor_si128(acc_hi[i], acc_hi[i + 2]);
        acc_mid[i] = _mm_xor_si128(acc_mid[i], acc_mid[i + 2]);
    }

    __m128i final_lo = _mm_xor_si128(acc_lo[0], acc_lo[1]);
    __m128i final_hi = _mm_xor_si128(acc_hi[0], acc_hi[1]);
    __m128i final_mid = _mm_xor_si128(acc_mid[0], acc_mid[1]);

    /* Final reduction from Karatsuba */
    __m128i tmp_lo = _mm_slli_si128(final_mid, 8);
    __m128i tmp_hi = _mm_srli_si128(final_mid, 8);
    final_lo = _mm_xor_si128(final_lo, tmp_lo);
    final_hi = _mm_xor_si128(final_hi, tmp_hi);

    /* GF(2^128) reduction */
    __m128i poly = _mm_setr_epi32(1, 0, 0, 0xC2000000);

    __m128i tmp1 = _mm_clmulepi64_si128(final_lo, poly, 0x10);
    __m128i tmp2 = _mm_shuffle_epi32(final_lo, 0x4E);
    __m128i tmp3 = _mm_xor_si128(tmp2, tmp1);

    __m128i tmp4 = _mm_clmulepi64_si128(tmp3, poly, 0x10);
    __m128i tmp5 = _mm_shuffle_epi32(tmp3, 0x4E);
    __m128i tmp6 = _mm_xor_si128(tmp5, tmp4);
    __m128i result = _mm_xor_si128(tmp6, final_hi);

    /* Store updated GHASH state (already in normal byte order) */
    _mm_storeu_si128((__m128i*)ghash_state, result);

    /* Restore C[0] to original ciphertext (FIX: don't output GHASH-modified value) */
    C[0] = C0_original;
}

#endif /* __x86_64__ */
