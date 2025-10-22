/*
 * ghash_pmull.c - GHASH implementation using ARM NEON PMULL instructions
 * Polynomial multiplication in GF(2^128) using ARM crypto extensions
 */

#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO

#include <arm_neon.h>
#include "../include/soliton.h"

/* Reverse bytes in a 128-bit vector for GHASH */
static inline uint8x16_t reverse_bytes_neon(uint8x16_t v) {
    const uint8x16_t rev_mask = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
    return vqtbl1q_u8(v, rev_mask);
}

/* Initialize GHASH key H = AES_K(0) */
void ghash_init_pmull(uint8_t* h, const uint32_t* round_keys) {
    uint8_t zero[16] = {0};

    /* Use AES to encrypt zero block */
    extern void aes256_encrypt_block_scalar(const uint32_t*, const uint8_t*, uint8_t*);
    aes256_encrypt_block_scalar(round_keys, zero, h);

    /* Convert to little-endian for GHASH */
    uint8x16_t h_vec = vld1q_u8(h);
    h_vec = reverse_bytes_neon(h_vec);
    vst1q_u8(h, h_vec);
}

/* Polynomial reduction after multiplication */
static inline poly128_t ghash_reduce_pmull(poly128_t high, poly128_t low) {
    /* Reduction polynomial: x^128 + x^7 + x^2 + x + 1 */
    const poly64_t poly = 0x87;

    /* Shift and reduce */
    poly64_t t0 = vgetq_lane_p64(low, 0);
    poly64_t t1 = vgetq_lane_p64(low, 1);
    poly64_t t2 = vgetq_lane_p64(high, 0);
    poly64_t t3 = vgetq_lane_p64(high, 1);

    /* First phase of reduction */
    poly128_t tmp = vmull_p64(t3, poly);
    t3 = vgetq_lane_p64(tmp, 1);
    t2 ^= vgetq_lane_p64(tmp, 0);

    tmp = vmull_p64(t2, poly);
    t2 = vgetq_lane_p64(tmp, 1);
    t1 ^= vgetq_lane_p64(tmp, 0);

    /* Combine result */
    poly128_t result;
    result = vsetq_lane_p64(t1, result, 0);
    result = vsetq_lane_p64(t2 ^ t3, result, 1);

    return result;
}

/* GHASH multiplication using PMULL */
static inline poly128_t ghash_mul_pmull(poly128_t a, poly128_t b) {
    /* Split into 64-bit halves */
    poly64_t a0 = vgetq_lane_p64(a, 0);
    poly64_t a1 = vgetq_lane_p64(a, 1);
    poly64_t b0 = vgetq_lane_p64(b, 0);
    poly64_t b1 = vgetq_lane_p64(b, 1);

    /* Karatsuba multiplication */
    poly128_t z0 = vmull_p64(a0, b0);           /* a0 * b0 */
    poly128_t z2 = vmull_p64(a1, b1);           /* a1 * b1 */
    poly128_t z1 = vmull_p64(a0 ^ a1, b0 ^ b1); /* (a0 + a1) * (b0 + b1) */

    /* Combine middle term */
    z1 = veorq_p8(z1, z0);
    z1 = veorq_p8(z1, z2);

    /* Shift middle term */
    poly64_t m0 = vgetq_lane_p64(z1, 0);
    poly64_t m1 = vgetq_lane_p64(z1, 1);

    poly128_t low, high;
    low = vsetq_lane_p64(vgetq_lane_p64(z0, 0), low, 0);
    low = vsetq_lane_p64(vgetq_lane_p64(z0, 1) ^ m0, low, 1);
    high = vsetq_lane_p64(vgetq_lane_p64(z2, 0) ^ m1, high, 0);
    high = vsetq_lane_p64(vgetq_lane_p64(z2, 1), high, 1);

    /* Reduce */
    return ghash_reduce_pmull(high, low);
}

/* Update GHASH with data blocks */
void ghash_update_pmull(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t len) {
    poly128_t h_vec = vld1q_p8(h);
    poly128_t s_vec = vld1q_p8(state);

    /* Process complete 16-byte blocks */
    while (len >= 16) {
        poly128_t d_vec = vld1q_p8(data);

        /* Reverse bytes for GHASH */
        d_vec = reverse_bytes_neon((uint8x16_t)d_vec);

        /* XOR with state */
        s_vec = veorq_p8(s_vec, d_vec);

        /* Multiply by H */
        s_vec = ghash_mul_pmull(s_vec, h_vec);

        data += 16;
        len -= 16;
    }

    /* Handle partial block */
    if (len > 0) {
        uint8_t pad[16] = {0};
        for (size_t i = 0; i < len; i++) {
            pad[i] = data[i];
        }

        poly128_t d_vec = vld1q_p8(pad);
        d_vec = reverse_bytes_neon((uint8x16_t)d_vec);
        s_vec = veorq_p8(s_vec, d_vec);
        s_vec = ghash_mul_pmull(s_vec, h_vec);
    }

    /* Store result */
    vst1q_p8(state, s_vec);
}

/* Process multiple blocks with precomputed powers for better performance */
void ghash_update_blocks_pmull(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t blocks) {
    if (blocks == 0) return;

    poly128_t h1 = vld1q_p8(h);
    poly128_t s = vld1q_p8(state);

    /* Precompute H^2, H^3, H^4 for 4-way parallel */
    poly128_t h2 = ghash_mul_pmull(h1, h1);
    poly128_t h3 = ghash_mul_pmull(h2, h1);
    poly128_t h4 = ghash_mul_pmull(h2, h2);

    /* Process 4 blocks at a time */
    while (blocks >= 4) {
        poly128_t d0 = vld1q_p8(data);
        poly128_t d1 = vld1q_p8(data + 16);
        poly128_t d2 = vld1q_p8(data + 32);
        poly128_t d3 = vld1q_p8(data + 48);

        /* Reverse bytes */
        d0 = reverse_bytes_neon((uint8x16_t)d0);
        d1 = reverse_bytes_neon((uint8x16_t)d1);
        d2 = reverse_bytes_neon((uint8x16_t)d2);
        d3 = reverse_bytes_neon((uint8x16_t)d3);

        /* Horner's method: s = (((s*H + d0)*H + d1)*H + d2)*H + d3 */
        s = veorq_p8(s, d0);
        s = ghash_mul_pmull(s, h4);

        poly128_t t1 = ghash_mul_pmull(d1, h3);
        poly128_t t2 = ghash_mul_pmull(d2, h2);
        poly128_t t3 = ghash_mul_pmull(d3, h1);

        s = veorq_p8(s, t1);
        s = veorq_p8(s, t2);
        s = veorq_p8(s, t3);

        data += 64;
        blocks -= 4;
    }

    /* Process remaining blocks */
    while (blocks > 0) {
        poly128_t d = vld1q_p8(data);
        d = reverse_bytes_neon((uint8x16_t)d);
        s = veorq_p8(s, d);
        s = ghash_mul_pmull(s, h1);

        data += 16;
        blocks--;
    }

    vst1q_p8(state, s);
}

/* Backend structure for PMULL GHASH */
extern soliton_backend_t backend_pmull;
soliton_backend_t backend_pmull = {
    .aes_key_expand = NULL,
    .aes_encrypt_block = NULL,
    .aes_ctr_blocks = NULL,
    .ghash_init = (void (*)(uint8_t*, const uint32_t*))ghash_init_pmull,
    .ghash_update = (void (*)(uint8_t*, const uint8_t*, const uint8_t*, size_t))ghash_update_pmull,
    .chacha_blocks = NULL,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "pmull"
};

#endif /* __ARM_FEATURE_CRYPTO */
#endif /* __aarch64__ */