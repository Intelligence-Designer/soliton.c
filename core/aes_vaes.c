/*
 * aes_vaes.c - AES-256 implementation using VAES instructions
 * Requires x86-64 with VAES, VPCLMULQDQ, and AVX2/AVX-512
 */

#include "common.h"

#ifdef __x86_64__

#include <immintrin.h>

/* Check for VAES support at compile time */
#if defined(__VAES__) && defined(__AES__)

/* External scalar key expansion - use for VAES too */
extern void aes256_key_expand_scalar(const uint8_t key[32], uint32_t round_keys[60]);

/* AES-256 key expansion using scalar - VAES doesn't accelerate key expansion */
/* Forward declaration of AES-NI accelerated key expansion */
extern void aes256_key_expand_aesni(const uint8_t key[32], uint32_t* round_keys);

void aes256_key_expand_vaes(const uint8_t key[32], uint32_t* round_keys) {
    /* Use AES-NI accelerated key expansion (~500 cycles vs 6.7k scalar)
     * CRITICAL OPTIMIZATION: Reduces init overhead from 6.7k to ~500 cycles */
    aes256_key_expand_aesni(key, round_keys);
}

/* AES-256 CTR mode using VAES - 8 blocks parallel */
void aes256_ctr_blocks8_vaes(const uint32_t* round_keys, const uint8_t iv[16],
                             uint32_t counter, const uint8_t* in, uint8_t* out) {
    /* Load round keys */
    __m256i rk[15];
    for (int i = 0; i < 15; i++) {
        __m128i k128 = _mm_loadu_si128((const __m128i*)(round_keys + i * 4));
        rk[i] = _mm256_broadcastsi128_si256(k128);
    }

    /* Prepare counter blocks using full 16-byte IV (loads all bytes including 8-11) */
    __m128i iv_base = _mm_loadu_si128((const __m128i*)iv);

    /* Prepare 8 counter blocks by setting counter field for each */
    __m128i counters[8];
    for (int i = 0; i < 8; i++) {
        counters[i] = iv_base;
        /* Set counter value (big-endian 32-bit at bytes 12-15) */
        uint32_t ctr_val = counter + i;
        counters[i] = _mm_insert_epi32(counters[i], __builtin_bswap32(ctr_val), 3);
    }

    /* Pack 8 counters into 4 YMM registers for VAES */
    __m256i ctr_blocks[4];
    ctr_blocks[0] = _mm256_setr_m128i(counters[0], counters[1]);
    ctr_blocks[1] = _mm256_setr_m128i(counters[2], counters[3]);
    ctr_blocks[2] = _mm256_setr_m128i(counters[4], counters[5]);
    ctr_blocks[3] = _mm256_setr_m128i(counters[6], counters[7]);

    /* AES encryption rounds */
    __m256i state[4];
    state[0] = _mm256_xor_si256(ctr_blocks[0], rk[0]);
    state[1] = _mm256_xor_si256(ctr_blocks[1], rk[0]);
    state[2] = _mm256_xor_si256(ctr_blocks[2], rk[0]);
    state[3] = _mm256_xor_si256(ctr_blocks[3], rk[0]);

    for (int round = 1; round < 14; round++) {
        state[0] = _mm256_aesenc_epi128(state[0], rk[round]);
        state[1] = _mm256_aesenc_epi128(state[1], rk[round]);
        state[2] = _mm256_aesenc_epi128(state[2], rk[round]);
        state[3] = _mm256_aesenc_epi128(state[3], rk[round]);
    }

    state[0] = _mm256_aesenclast_epi128(state[0], rk[14]);
    state[1] = _mm256_aesenclast_epi128(state[1], rk[14]);
    state[2] = _mm256_aesenclast_epi128(state[2], rk[14]);
    state[3] = _mm256_aesenclast_epi128(state[3], rk[14]);

    /* XOR with input */
    __m256i in_blocks[4];
    in_blocks[0] = _mm256_loadu_si256((const __m256i*)in);
    in_blocks[1] = _mm256_loadu_si256((const __m256i*)(in + 32));
    in_blocks[2] = _mm256_loadu_si256((const __m256i*)(in + 64));
    in_blocks[3] = _mm256_loadu_si256((const __m256i*)(in + 96));

    state[0] = _mm256_xor_si256(state[0], in_blocks[0]);
    state[1] = _mm256_xor_si256(state[1], in_blocks[1]);
    state[2] = _mm256_xor_si256(state[2], in_blocks[2]);
    state[3] = _mm256_xor_si256(state[3], in_blocks[3]);

    /* Store output */
    _mm256_storeu_si256((__m256i*)out, state[0]);
    _mm256_storeu_si256((__m256i*)(out + 32), state[1]);
    _mm256_storeu_si256((__m256i*)(out + 64), state[2]);
    _mm256_storeu_si256((__m256i*)(out + 96), state[3]);
}

/* AES-256 CTR mode using VAES - variable blocks */
void aes256_ctr_blocks_vaes(const uint32_t* round_keys, const uint8_t iv[16],
                            uint32_t counter, const uint8_t* in, uint8_t* out, size_t blocks) {
    /* Process 8 blocks at a time */
    while (blocks >= 8) {
        aes256_ctr_blocks8_vaes(round_keys, iv, counter, in, out);
        counter += 8;
        in += 128;
        out += 128;
        blocks -= 8;
    }

    /* Handle remaining blocks with scalar fallback */
    if (blocks > 0) {
        extern void aes256_ctr_blocks_scalar(const uint32_t*, const uint8_t*,
                                            uint32_t, const uint8_t*, uint8_t*, size_t);
        aes256_ctr_blocks_scalar(round_keys, iv, counter, in, out, blocks);
    }
}

/* External GHASH functions - use scalar for now */
extern void ghash_init_scalar(uint8_t* h, const uint32_t* round_keys);
extern void ghash_update_scalar(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t len);

/* External scalar AES block function for single blocks */
extern void aes256_encrypt_block_scalar(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]);

/* External CLMUL GHASH functions */
extern void ghash_init_clmul(uint8_t h[16], const uint32_t* round_keys);
extern void ghash_update_clmul(uint8_t state[16], const uint8_t* h, const uint8_t* data, size_t len);

/* Backend structure for VAES */
extern soliton_backend_t backend_vaes;
/* Use AES-NI for single blocks (much faster than scalar) */
extern void aes256_encrypt_block_aesni(const uint32_t*, const uint8_t*, uint8_t*);

soliton_backend_t backend_vaes = {
    .aes_key_expand = (void (*)(const uint8_t*, uint32_t*))aes256_key_expand_vaes,
    .aes_encrypt_block = (void (*)(const uint32_t*, const uint8_t*, uint8_t*))aes256_encrypt_block_aesni,  /* Use AES-NI for single blocks */
    .aes_ctr_blocks = (void (*)(const uint32_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t))aes256_ctr_blocks_vaes,
    .ghash_init = (void (*)(uint8_t*, const uint32_t*))ghash_init_clmul,    /* CLMUL-accelerated GHASH */
    .ghash_update = (void (*)(uint8_t*, const uint8_t*, const uint8_t*, size_t))ghash_update_clmul,  /* CLMUL-accelerated GHASH */
    .chacha_blocks = NULL,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "vaes+clmul"
};

#endif /* __VAES__ && __AES__ */
#endif /* __x86_64__ */