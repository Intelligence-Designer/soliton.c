/*
 * chacha_neon.c - ChaCha20 implementation using ARM NEON
 * 4-way parallel processing with NEON SIMD instructions
 */

#ifdef __aarch64__
#ifdef __ARM_NEON

#include <arm_neon.h>
#include "../include/soliton.h"

/* ChaCha20 constants */
static const uint32_t CHACHA_CONST[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

/* Quarter round on NEON vectors */
#define QUARTER_ROUND(a, b, c, d) do { \
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = vrorq_n_u32(d, 16); \
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = vrorq_n_u32(b, 12); \
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = vrorq_n_u32(d, 8); \
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = vrorq_n_u32(b, 7); \
} while(0)

/* Rotate right for NEON (ARMv8 has vrorq) */
static inline uint32x4_t vrorq_n_u32(uint32x4_t v, int n) {
    return vorrq_u32(vshrq_n_u32(v, n), vshlq_n_u32(v, 32 - n));
}

/* Process 4 blocks in parallel */
void chacha20_blocks4_neon(
    const uint32_t key[8],
    const uint32_t nonce[3],
    uint32_t counter,
    const uint8_t* in,
    uint8_t* out,
    size_t blocks
) {
    /* Load key */
    uint32x4_t k0 = vld1q_u32(&key[0]);
    uint32x4_t k1 = vld1q_u32(&key[4]);

    /* Prepare nonce and counter */
    uint32_t nc[4];
    nc[0] = counter;
    nc[1] = nonce[0];
    nc[2] = nonce[1];
    nc[3] = nonce[2];

    while (blocks >= 4) {
        /* Initialize states for 4 blocks */
        uint32x4_t s0[4], s1[4], s2[4], s3[4];

        /* Constants row */
        s0[0] = vld1q_u32(CHACHA_CONST);
        s1[0] = s0[0];
        s2[0] = s0[0];
        s3[0] = s0[0];

        /* Key rows */
        s0[1] = k0;
        s1[1] = k0;
        s2[1] = k0;
        s3[1] = k0;

        s0[2] = k1;
        s1[2] = k1;
        s2[2] = k1;
        s3[2] = k1;

        /* Counter and nonce row */
        nc[0] = counter++;
        s0[3] = vld1q_u32(nc);
        nc[0] = counter++;
        s1[3] = vld1q_u32(nc);
        nc[0] = counter++;
        s2[3] = vld1q_u32(nc);
        nc[0] = counter++;
        s3[3] = vld1q_u32(nc);

        /* Save initial state */
        uint32x4_t init0[4] = {s0[0], s0[1], s0[2], s0[3]};
        uint32x4_t init1[4] = {s1[0], s1[1], s1[2], s1[3]};
        uint32x4_t init2[4] = {s2[0], s2[1], s2[2], s2[3]};
        uint32x4_t init3[4] = {s3[0], s3[1], s3[2], s3[3]};

        /* 20 rounds (10 double-rounds) */
        for (int i = 0; i < 10; i++) {
            /* Column rounds */
            QUARTER_ROUND(s0[0], s0[1], s0[2], s0[3]);
            QUARTER_ROUND(s1[0], s1[1], s1[2], s1[3]);
            QUARTER_ROUND(s2[0], s2[1], s2[2], s2[3]);
            QUARTER_ROUND(s3[0], s3[1], s3[2], s3[3]);

            /* Diagonal rounds - shuffle for diagonal */
            s0[1] = vextq_u32(s0[1], s0[1], 1);
            s0[2] = vextq_u32(s0[2], s0[2], 2);
            s0[3] = vextq_u32(s0[3], s0[3], 3);

            s1[1] = vextq_u32(s1[1], s1[1], 1);
            s1[2] = vextq_u32(s1[2], s1[2], 2);
            s1[3] = vextq_u32(s1[3], s1[3], 3);

            s2[1] = vextq_u32(s2[1], s2[1], 1);
            s2[2] = vextq_u32(s2[2], s2[2], 2);
            s2[3] = vextq_u32(s2[3], s2[3], 3);

            s3[1] = vextq_u32(s3[1], s3[1], 1);
            s3[2] = vextq_u32(s3[2], s3[2], 2);
            s3[3] = vextq_u32(s3[3], s3[3], 3);

            QUARTER_ROUND(s0[0], s0[1], s0[2], s0[3]);
            QUARTER_ROUND(s1[0], s1[1], s1[2], s1[3]);
            QUARTER_ROUND(s2[0], s2[1], s2[2], s2[3]);
            QUARTER_ROUND(s3[0], s3[1], s3[2], s3[3]);

            /* Unshuffle */
            s0[1] = vextq_u32(s0[1], s0[1], 3);
            s0[2] = vextq_u32(s0[2], s0[2], 2);
            s0[3] = vextq_u32(s0[3], s0[3], 1);

            s1[1] = vextq_u32(s1[1], s1[1], 3);
            s1[2] = vextq_u32(s1[2], s1[2], 2);
            s1[3] = vextq_u32(s1[3], s1[3], 1);

            s2[1] = vextq_u32(s2[1], s2[1], 3);
            s2[2] = vextq_u32(s2[2], s2[2], 2);
            s2[3] = vextq_u32(s2[3], s2[3], 1);

            s3[1] = vextq_u32(s3[1], s3[1], 3);
            s3[2] = vextq_u32(s3[2], s3[2], 2);
            s3[3] = vextq_u32(s3[3], s3[3], 1);
        }

        /* Add initial state */
        s0[0] = vaddq_u32(s0[0], init0[0]);
        s0[1] = vaddq_u32(s0[1], init0[1]);
        s0[2] = vaddq_u32(s0[2], init0[2]);
        s0[3] = vaddq_u32(s0[3], init0[3]);

        s1[0] = vaddq_u32(s1[0], init1[0]);
        s1[1] = vaddq_u32(s1[1], init1[1]);
        s1[2] = vaddq_u32(s1[2], init1[2]);
        s1[3] = vaddq_u32(s1[3], init1[3]);

        s2[0] = vaddq_u32(s2[0], init2[0]);
        s2[1] = vaddq_u32(s2[1], init2[1]);
        s2[2] = vaddq_u32(s2[2], init2[2]);
        s2[3] = vaddq_u32(s2[3], init2[3]);

        s3[0] = vaddq_u32(s3[0], init3[0]);
        s3[1] = vaddq_u32(s3[1], init3[1]);
        s3[2] = vaddq_u32(s3[2], init3[2]);
        s3[3] = vaddq_u32(s3[3], init3[3]);

        /* XOR with input and write output */
        if (in && out) {
            for (int i = 0; i < 4; i++) {
                uint32x4_t p = vld1q_u32((const uint32_t*)(in + i * 16));
                vst1q_u32((uint32_t*)(out + i * 16), veorq_u32(s0[i], p));
            }
            for (int i = 0; i < 4; i++) {
                uint32x4_t p = vld1q_u32((const uint32_t*)(in + 64 + i * 16));
                vst1q_u32((uint32_t*)(out + 64 + i * 16), veorq_u32(s1[i], p));
            }
            for (int i = 0; i < 4; i++) {
                uint32x4_t p = vld1q_u32((const uint32_t*)(in + 128 + i * 16));
                vst1q_u32((uint32_t*)(out + 128 + i * 16), veorq_u32(s2[i], p));
            }
            for (int i = 0; i < 4; i++) {
                uint32x4_t p = vld1q_u32((const uint32_t*)(in + 192 + i * 16));
                vst1q_u32((uint32_t*)(out + 192 + i * 16), veorq_u32(s3[i], p));
            }
        }

        blocks -= 4;
        if (in) in += 256;
        if (out) out += 256;
    }

    /* Handle remaining blocks with scalar */
    if (blocks > 0) {
        extern void chacha20_blocks_scalar(const uint32_t*, const uint32_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
        chacha20_blocks_scalar(key, nonce, counter, in, out, blocks);
    }
}

/* Main entry point for ChaCha20 NEON */
void chacha20_blocks_neon(
    const uint32_t key[8],
    const uint32_t nonce[3],
    uint32_t counter,
    const uint8_t* in,
    uint8_t* out,
    size_t blocks
) {
    if (blocks >= 4) {
        chacha20_blocks4_neon(key, nonce, counter, in, out, blocks);
    } else if (blocks > 0) {
        extern void chacha20_blocks_scalar(const uint32_t*, const uint32_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
        chacha20_blocks_scalar(key, nonce, counter, in, out, blocks);
    }
}

/* Backend structure for NEON ChaCha20 */
extern soliton_backend_t backend_chacha_neon;
soliton_backend_t backend_chacha_neon = {
    .aes_key_expand = NULL,
    .aes_encrypt_block = NULL,
    .aes_ctr_blocks = NULL,
    .ghash_init = NULL,
    .ghash_update = NULL,
    .chacha_blocks = (void (*)(const uint32_t*, const uint32_t*, uint32_t, const uint8_t*, uint8_t*, size_t))chacha20_blocks_neon,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "chacha_neon"
};

#endif /* __ARM_NEON */
#endif /* __aarch64__ */