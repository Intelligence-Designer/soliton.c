/*
 * aes_neon.c - AES implementation using ARM NEON with crypto extensions
 * Requires ARMv8-A with crypto extensions (AES)
 */

#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO

#include <arm_neon.h>
#include "../include/soliton.h"

/* Convert byte array to uint32_t for round keys */
static inline void bytes_to_words(uint32_t* dst, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len / 4; i++) {
        dst[i] = ((uint32_t)src[4*i] << 0) |
                 ((uint32_t)src[4*i+1] << 8) |
                 ((uint32_t)src[4*i+2] << 16) |
                 ((uint32_t)src[4*i+3] << 24);
    }
}

/* AES-256 key expansion using ARM crypto instructions */
void aes256_key_expand_neon(const uint8_t key[32], uint32_t round_keys[60]) {
    uint8x16_t k0 = vld1q_u8(key);
    uint8x16_t k1 = vld1q_u8(key + 16);

    /* Store first two round keys */
    vst1q_u8((uint8_t*)round_keys, k0);
    vst1q_u8((uint8_t*)round_keys + 16, k1);

    /* Use scalar key expansion for now (can be optimized with NEON later) */
    extern void aes256_key_expand_scalar(const uint8_t*, uint32_t*);
    aes256_key_expand_scalar(key, round_keys);
}

/* AES encryption using ARM crypto instructions */
static inline uint8x16_t aes_encrypt_block_neon(const uint8x16_t* round_keys, uint8x16_t block) {
    /* Initial round */
    block = vaesdq_u8(block, round_keys[0]);
    block = vaesmcq_u8(block);

    /* Main rounds (13 for AES-256) */
    for (int i = 1; i < 13; i++) {
        block = vaesdq_u8(block, round_keys[i]);
        block = vaesmcq_u8(block);
    }

    /* Final round (no MixColumns) */
    block = vaesdq_u8(block, round_keys[13]);
    block = veorq_u8(block, round_keys[14]);

    return block;
}

/* Process 4 blocks in parallel using NEON */
void aes256_ctr_blocks4_neon(
    const uint32_t* round_keys,
    const uint8_t iv[16],
    uint32_t counter,
    const uint8_t* in,
    uint8_t* out,
    size_t blocks
) {
    /* Load round keys as NEON vectors */
    uint8x16_t rk[15];
    for (int i = 0; i < 15; i++) {
        rk[i] = vld1q_u8((const uint8_t*)(round_keys + i * 4));
    }

    /* Prepare counter blocks */
    uint8_t ctr_block[16];
    for (int i = 0; i < 12; i++) {
        ctr_block[i] = iv[i];
    }

    /* Process 4 blocks at a time */
    while (blocks >= 4) {
        uint8x16_t b0, b1, b2, b3;
        uint8x16_t c0, c1, c2, c3;

        /* Set up counter values */
        *(uint32_t*)(ctr_block + 12) = __builtin_bswap32(counter);
        b0 = vld1q_u8(ctr_block);
        counter++;

        *(uint32_t*)(ctr_block + 12) = __builtin_bswap32(counter);
        b1 = vld1q_u8(ctr_block);
        counter++;

        *(uint32_t*)(ctr_block + 12) = __builtin_bswap32(counter);
        b2 = vld1q_u8(ctr_block);
        counter++;

        *(uint32_t*)(ctr_block + 12) = __builtin_bswap32(counter);
        b3 = vld1q_u8(ctr_block);
        counter++;

        /* Encrypt counter blocks */
        c0 = aes_encrypt_block_neon(rk, b0);
        c1 = aes_encrypt_block_neon(rk, b1);
        c2 = aes_encrypt_block_neon(rk, b2);
        c3 = aes_encrypt_block_neon(rk, b3);

        /* XOR with plaintext */
        uint8x16_t p0 = vld1q_u8(in);
        uint8x16_t p1 = vld1q_u8(in + 16);
        uint8x16_t p2 = vld1q_u8(in + 32);
        uint8x16_t p3 = vld1q_u8(in + 48);

        c0 = veorq_u8(c0, p0);
        c1 = veorq_u8(c1, p1);
        c2 = veorq_u8(c2, p2);
        c3 = veorq_u8(c3, p3);

        /* Store ciphertext */
        vst1q_u8(out, c0);
        vst1q_u8(out + 16, c1);
        vst1q_u8(out + 32, c2);
        vst1q_u8(out + 48, c3);

        in += 64;
        out += 64;
        blocks -= 4;
    }

    /* Handle remaining blocks with scalar */
    if (blocks > 0) {
        extern void aes256_ctr_blocks_scalar(const uint32_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
        aes256_ctr_blocks_scalar(round_keys, iv, counter, in, out, blocks);
    }
}

/* Main CTR mode entry point */
void aes256_ctr_blocks_neon(
    const uint32_t* round_keys,
    const uint8_t iv[16],
    uint32_t counter,
    const uint8_t* in,
    uint8_t* out,
    size_t blocks
) {
    /* Use 4-block parallel for larger operations */
    if (blocks >= 4) {
        aes256_ctr_blocks4_neon(round_keys, iv, counter, in, out, blocks);
    } else {
        /* Fall back to scalar for small operations */
        extern void aes256_ctr_blocks_scalar(const uint32_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
        aes256_ctr_blocks_scalar(round_keys, iv, counter, in, out, blocks);
    }
}

/* Single block encryption for GCM */
void aes256_encrypt_block_neon(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]) {
    uint8x16_t rk[15];
    for (int i = 0; i < 15; i++) {
        rk[i] = vld1q_u8((const uint8_t*)(round_keys + i * 4));
    }

    uint8x16_t block = vld1q_u8(in);
    block = aes_encrypt_block_neon(rk, block);
    vst1q_u8(out, block);
}

/* External functions for GHASH */
extern void ghash_init_pmull(uint8_t* h, const uint32_t* round_keys);
extern void ghash_update_pmull(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t len);
extern void aes256_encrypt_block_scalar(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]);

/* Backend structure for NEON AES */
extern soliton_backend_t backend_neon;
soliton_backend_t backend_neon = {
    .aes_key_expand = (void (*)(const uint8_t*, uint32_t*))aes256_key_expand_neon,
    .aes_encrypt_block = (void (*)(const uint32_t*, const uint8_t*, uint8_t*))aes256_encrypt_block_neon,
    .aes_ctr_blocks = (void (*)(const uint32_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t))aes256_ctr_blocks_neon,
    .ghash_init = (void (*)(uint8_t*, const uint32_t*))ghash_init_pmull,
    .ghash_update = (void (*)(uint8_t*, const uint8_t*, const uint8_t*, size_t))ghash_update_pmull,
    .chacha_blocks = NULL,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "neon"
};

#endif /* __ARM_FEATURE_CRYPTO */
#endif /* __aarch64__ */