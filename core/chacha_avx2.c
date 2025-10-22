/*
 * chacha_avx2.c - ChaCha20 implementation using AVX2
 * 8-way parallel processing for improved throughput
 */

#include "common.h"

#ifdef __x86_64__

#include <immintrin.h>

/* Check for AVX2 support at compile time */
#ifdef __AVX2__

/* ChaCha20 quarter-round on AVX2 vectors */
#define CHACHA_QR_AVX2(a, b, c, d)                     \
    do {                                                \
        a = _mm256_add_epi32(a, b);                   \
        d = _mm256_xor_si256(d, a);                   \
        d = _mm256_shuffle_epi8(d, rot16);            \
        c = _mm256_add_epi32(c, d);                   \
        b = _mm256_xor_si256(b, c);                   \
        b = _mm256_or_si256(                          \
            _mm256_slli_epi32(b, 12),                 \
            _mm256_srli_epi32(b, 20));                \
        a = _mm256_add_epi32(a, b);                   \
        d = _mm256_xor_si256(d, a);                   \
        d = _mm256_shuffle_epi8(d, rot8);             \
        c = _mm256_add_epi32(c, d);                   \
        b = _mm256_xor_si256(b, c);                   \
        b = _mm256_or_si256(                          \
            _mm256_slli_epi32(b, 7),                  \
            _mm256_srli_epi32(b, 25));                \
    } while (0)

/* ChaCha20 8-block parallel processing */
void chacha20_blocks8_avx2(const uint8_t key[32], const uint8_t nonce[12],
                           uint32_t counter, const uint8_t* in, uint8_t* out) {
    /* Rotation constants */
    const __m256i rot16 = _mm256_set_epi8(
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2
    );
    const __m256i rot8 = _mm256_set_epi8(
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3
    );

    /* Initialize state for 8 blocks */
    __m256i s0, s1, s2, s3, s4, s5, s6, s7;
    __m256i s8, s9, s10, s11, s12, s13, s14, s15;

    /* Constants "expand 32-byte k" */
    s0 = _mm256_set1_epi32(0x61707865);
    s1 = _mm256_set1_epi32(0x3320646e);
    s2 = _mm256_set1_epi32(0x79622d32);
    s3 = _mm256_set1_epi32(0x6b206574);

    /* Key (broadcast to all lanes) */
    s4 = _mm256_set1_epi32(((uint32_t*)key)[0]);
    s5 = _mm256_set1_epi32(((uint32_t*)key)[1]);
    s6 = _mm256_set1_epi32(((uint32_t*)key)[2]);
    s7 = _mm256_set1_epi32(((uint32_t*)key)[3]);
    s8 = _mm256_set1_epi32(((uint32_t*)key)[4]);
    s9 = _mm256_set1_epi32(((uint32_t*)key)[5]);
    s10 = _mm256_set1_epi32(((uint32_t*)key)[6]);
    s11 = _mm256_set1_epi32(((uint32_t*)key)[7]);

    /* Counter (different for each block) */
    s12 = _mm256_setr_epi32(
        counter, counter + 1, counter + 2, counter + 3,
        counter + 4, counter + 5, counter + 6, counter + 7
    );

    /* Nonce (broadcast to all lanes) */
    s13 = _mm256_set1_epi32(((uint32_t*)nonce)[0]);
    s14 = _mm256_set1_epi32(((uint32_t*)nonce)[1]);
    s15 = _mm256_set1_epi32(((uint32_t*)nonce)[2]);

    /* Save initial state */
    __m256i init0 = s0, init1 = s1, init2 = s2, init3 = s3;
    __m256i init4 = s4, init5 = s5, init6 = s6, init7 = s7;
    __m256i init8 = s8, init9 = s9, init10 = s10, init11 = s11;
    __m256i init12 = s12, init13 = s13, init14 = s14, init15 = s15;

    /* 20 rounds (10 double-rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        CHACHA_QR_AVX2(s0, s4, s8, s12);
        CHACHA_QR_AVX2(s1, s5, s9, s13);
        CHACHA_QR_AVX2(s2, s6, s10, s14);
        CHACHA_QR_AVX2(s3, s7, s11, s15);

        /* Diagonal rounds */
        CHACHA_QR_AVX2(s0, s5, s10, s15);
        CHACHA_QR_AVX2(s1, s6, s11, s12);
        CHACHA_QR_AVX2(s2, s7, s8, s13);
        CHACHA_QR_AVX2(s3, s4, s9, s14);
    }

    /* Add initial state */
    s0 = _mm256_add_epi32(s0, init0);
    s1 = _mm256_add_epi32(s1, init1);
    s2 = _mm256_add_epi32(s2, init2);
    s3 = _mm256_add_epi32(s3, init3);
    s4 = _mm256_add_epi32(s4, init4);
    s5 = _mm256_add_epi32(s5, init5);
    s6 = _mm256_add_epi32(s6, init6);
    s7 = _mm256_add_epi32(s7, init7);
    s8 = _mm256_add_epi32(s8, init8);
    s9 = _mm256_add_epi32(s9, init9);
    s10 = _mm256_add_epi32(s10, init10);
    s11 = _mm256_add_epi32(s11, init11);
    s12 = _mm256_add_epi32(s12, init12);
    s13 = _mm256_add_epi32(s13, init13);
    s14 = _mm256_add_epi32(s14, init14);
    s15 = _mm256_add_epi32(s15, init15);

    /* Transpose and XOR with input */
    __m256i t0, t1, t2, t3, t4, t5, t6, t7;

    /* Transpose to get correct byte order for each block */
    t0 = _mm256_unpacklo_epi32(s0, s1);
    t1 = _mm256_unpacklo_epi32(s2, s3);
    t2 = _mm256_unpackhi_epi32(s0, s1);
    t3 = _mm256_unpackhi_epi32(s2, s3);
    t4 = _mm256_unpacklo_epi32(s4, s5);
    t5 = _mm256_unpacklo_epi32(s6, s7);
    t6 = _mm256_unpackhi_epi32(s4, s5);
    t7 = _mm256_unpackhi_epi32(s6, s7);

    s0 = _mm256_unpacklo_epi64(t0, t1);
    s1 = _mm256_unpackhi_epi64(t0, t1);
    s2 = _mm256_unpacklo_epi64(t2, t3);
    s3 = _mm256_unpackhi_epi64(t2, t3);
    s4 = _mm256_unpacklo_epi64(t4, t5);
    s5 = _mm256_unpackhi_epi64(t4, t5);
    s6 = _mm256_unpacklo_epi64(t6, t7);
    s7 = _mm256_unpackhi_epi64(t6, t7);

    /* Continue with remaining state */
    t0 = _mm256_unpacklo_epi32(s8, s9);
    t1 = _mm256_unpacklo_epi32(s10, s11);
    t2 = _mm256_unpackhi_epi32(s8, s9);
    t3 = _mm256_unpackhi_epi32(s10, s11);
    t4 = _mm256_unpacklo_epi32(s12, s13);
    t5 = _mm256_unpacklo_epi32(s14, s15);
    t6 = _mm256_unpackhi_epi32(s12, s13);
    t7 = _mm256_unpackhi_epi32(s14, s15);

    s8 = _mm256_unpacklo_epi64(t0, t1);
    s9 = _mm256_unpackhi_epi64(t0, t1);
    s10 = _mm256_unpacklo_epi64(t2, t3);
    s11 = _mm256_unpackhi_epi64(t2, t3);
    s12 = _mm256_unpacklo_epi64(t4, t5);
    s13 = _mm256_unpackhi_epi64(t4, t5);
    s14 = _mm256_unpacklo_epi64(t6, t7);
    s15 = _mm256_unpackhi_epi64(t6, t7);

    /* Final transpose to get blocks in correct order */
    /* After all the mixing, we need to arrange data so each 64-byte block is contiguous */

    /* Permute to group data by blocks instead of by word position */
    __m256i perm_idx = _mm256_setr_epi32(0, 4, 1, 5, 2, 6, 3, 7);

    /* Process first half of state (words 0-7) */
    __m256i w0 = _mm256_permutevar8x32_epi32(s0, perm_idx);
    __m256i w1 = _mm256_permutevar8x32_epi32(s1, perm_idx);
    __m256i w2 = _mm256_permutevar8x32_epi32(s2, perm_idx);
    __m256i w3 = _mm256_permutevar8x32_epi32(s3, perm_idx);
    __m256i w4 = _mm256_permutevar8x32_epi32(s4, perm_idx);
    __m256i w5 = _mm256_permutevar8x32_epi32(s5, perm_idx);
    __m256i w6 = _mm256_permutevar8x32_epi32(s6, perm_idx);
    __m256i w7 = _mm256_permutevar8x32_epi32(s7, perm_idx);

    /* Process second half of state (words 8-15) */
    __m256i w8 = _mm256_permutevar8x32_epi32(s8, perm_idx);
    __m256i w9 = _mm256_permutevar8x32_epi32(s9, perm_idx);
    __m256i w10 = _mm256_permutevar8x32_epi32(s10, perm_idx);
    __m256i w11 = _mm256_permutevar8x32_epi32(s11, perm_idx);
    __m256i w12 = _mm256_permutevar8x32_epi32(s12, perm_idx);
    __m256i w13 = _mm256_permutevar8x32_epi32(s13, perm_idx);
    __m256i w14 = _mm256_permutevar8x32_epi32(s14, perm_idx);
    __m256i w15 = _mm256_permutevar8x32_epi32(s15, perm_idx);

    /* Store transposed state and XOR with input */
    __m256i* output = (__m256i*)out;
    const __m256i* input = (const __m256i*)in;

    /* Store first 256 bytes (blocks 0-3) */
    _mm256_storeu_si256(output + 0, _mm256_xor_si256(w0, _mm256_loadu_si256(input + 0)));
    _mm256_storeu_si256(output + 1, _mm256_xor_si256(w1, _mm256_loadu_si256(input + 1)));
    _mm256_storeu_si256(output + 2, _mm256_xor_si256(w2, _mm256_loadu_si256(input + 2)));
    _mm256_storeu_si256(output + 3, _mm256_xor_si256(w3, _mm256_loadu_si256(input + 3)));
    _mm256_storeu_si256(output + 4, _mm256_xor_si256(w4, _mm256_loadu_si256(input + 4)));
    _mm256_storeu_si256(output + 5, _mm256_xor_si256(w5, _mm256_loadu_si256(input + 5)));
    _mm256_storeu_si256(output + 6, _mm256_xor_si256(w6, _mm256_loadu_si256(input + 6)));
    _mm256_storeu_si256(output + 7, _mm256_xor_si256(w7, _mm256_loadu_si256(input + 7)));

    /* Store second 256 bytes (blocks 4-7) */
    _mm256_storeu_si256(output + 8, _mm256_xor_si256(w8, _mm256_loadu_si256(input + 8)));
    _mm256_storeu_si256(output + 9, _mm256_xor_si256(w9, _mm256_loadu_si256(input + 9)));
    _mm256_storeu_si256(output + 10, _mm256_xor_si256(w10, _mm256_loadu_si256(input + 10)));
    _mm256_storeu_si256(output + 11, _mm256_xor_si256(w11, _mm256_loadu_si256(input + 11)));
    _mm256_storeu_si256(output + 12, _mm256_xor_si256(w12, _mm256_loadu_si256(input + 12)));
    _mm256_storeu_si256(output + 13, _mm256_xor_si256(w13, _mm256_loadu_si256(input + 13)));
    _mm256_storeu_si256(output + 14, _mm256_xor_si256(w14, _mm256_loadu_si256(input + 14)));
    _mm256_storeu_si256(output + 15, _mm256_xor_si256(w15, _mm256_loadu_si256(input + 15)));
}

/* ChaCha20 blocks using AVX2 */
void chacha20_blocks_avx2(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, const uint8_t* in, uint8_t* out, size_t blocks) {
    /* Process 8 blocks at a time */
    while (blocks >= 8) {
        chacha20_blocks8_avx2(key, nonce, counter, in, out);
        counter += 8;
        in += 512;
        out += 512;
        blocks -= 8;
    }

    /* Handle remaining blocks with scalar fallback */
    if (blocks > 0) {
        extern void chacha20_blocks_scalar(const uint8_t*, const uint8_t*,
                                          uint32_t, const uint8_t*, uint8_t*, size_t);
        chacha20_blocks_scalar(key, nonce, counter, in, out, blocks);
    }
}

/* Backend structure for AVX2 */
extern soliton_backend_t backend_avx2;
soliton_backend_t backend_avx2 = {
    .aes_key_expand = NULL,  /* Use scalar AES for now */
    .aes_encrypt_block = NULL,
    .aes_ctr_blocks = NULL,
    .ghash_init = NULL,
    .ghash_update = NULL,
    .chacha_blocks = (void (*)(const uint8_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t))chacha20_blocks_avx2,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "avx2"
};

#endif /* __AVX2__ */
#endif /* __x86_64__ */