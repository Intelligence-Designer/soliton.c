/*
 * chacha_scalar.c - ChaCha20 stream cipher implementation (RFC 8439)
 * Constant-time scalar implementation
 */

#include "common.h"
#include "ct_utils.h"

/* ChaCha20 constants */
static const uint32_t CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574  /* "expand 32-byte k" */
};

/* ChaCha20 quarter-round function */
static SOLITON_INLINE void chacha_qr(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = SOLITON_ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = SOLITON_ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = SOLITON_ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = SOLITON_ROTL32(*b, 7);
}

/* ChaCha20 block function */
static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];

    /* Copy input to working state */
    for (int i = 0; i < 16; i++) {
        x[i] = in[i];
    }

    /* 20 rounds (10 double-rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        chacha_qr(&x[0], &x[4], &x[8],  &x[12]);
        chacha_qr(&x[1], &x[5], &x[9],  &x[13]);
        chacha_qr(&x[2], &x[6], &x[10], &x[14]);
        chacha_qr(&x[3], &x[7], &x[11], &x[15]);

        /* Diagonal rounds */
        chacha_qr(&x[0], &x[5], &x[10], &x[15]);
        chacha_qr(&x[1], &x[6], &x[11], &x[12]);
        chacha_qr(&x[2], &x[7], &x[8],  &x[13]);
        chacha_qr(&x[3], &x[4], &x[9],  &x[14]);
    }

    /* Add input to output */
    for (int i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

/* Initialize ChaCha20 state */
static void chacha20_init_state(uint32_t state[16], const uint8_t key[32],
                                const uint8_t nonce[12], uint32_t counter) {
    /* Constants */
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];

    /* Key (8 words) */
    state[4] = soliton_le32(key + 0);
    state[5] = soliton_le32(key + 4);
    state[6] = soliton_le32(key + 8);
    state[7] = soliton_le32(key + 12);
    state[8] = soliton_le32(key + 16);
    state[9] = soliton_le32(key + 20);
    state[10] = soliton_le32(key + 24);
    state[11] = soliton_le32(key + 28);

    /* Counter */
    state[12] = counter;

    /* Nonce (3 words) */
    state[13] = soliton_le32(nonce + 0);
    state[14] = soliton_le32(nonce + 4);
    state[15] = soliton_le32(nonce + 8);
}

/* Generate ChaCha20 keystream for multiple blocks */
void chacha20_blocks_scalar(const uint8_t key[32], const uint8_t nonce[12],
                           uint32_t counter, const uint8_t* in, uint8_t* out, size_t blocks) {
    uint32_t state[16];
    uint32_t keystream[16];

    for (size_t i = 0; i < blocks; i++) {
        /* Initialize state for this block */
        chacha20_init_state(state, key, nonce, counter + (uint32_t)i);

        /* Generate keystream block */
        chacha20_block(keystream, state);

        /* XOR with input (handle both encryption and decryption) */
        if (in != NULL && out != NULL) {
            for (int j = 0; j < 16; j++) {
                uint32_t ks_word = keystream[j];
                uint32_t in_word = soliton_le32(in + i * 64 + j * 4);
                uint32_t out_word = in_word ^ ks_word;
                soliton_put_le32(out + i * 64 + j * 4, out_word);
            }
        }
    }

    /* Wipe keystream */
    soliton_wipe(keystream, sizeof(keystream));
}

/* Generate ChaCha20 keystream with partial block support */
void chacha20_xor_scalar(const uint8_t key[32], const uint8_t nonce[12],
                        uint32_t counter, const uint8_t* in, uint8_t* out, size_t len) {
    size_t full_blocks = len / 64;
    size_t remainder = len % 64;

    /* Process full blocks */
    if (full_blocks > 0) {
        chacha20_blocks_scalar(key, nonce, counter, in, out, full_blocks);
        in += full_blocks * 64;
        out += full_blocks * 64;
        counter += (uint32_t)full_blocks;
    }

    /* Process partial block */
    if (remainder > 0) {
        uint32_t state[16];
        uint32_t keystream[16];
        uint8_t ks_bytes[64];

        /* Generate keystream for partial block */
        chacha20_init_state(state, key, nonce, counter);
        chacha20_block(keystream, state);

        /* Convert keystream to bytes */
        for (int i = 0; i < 16; i++) {
            soliton_put_le32(ks_bytes + i * 4, keystream[i]);
        }

        /* XOR with remaining input */
        for (size_t i = 0; i < remainder; i++) {
            out[i] = in[i] ^ ks_bytes[i];
        }

        /* Wipe temporary buffers */
        soliton_wipe(keystream, sizeof(keystream));
        soliton_wipe(ks_bytes, sizeof(ks_bytes));
    }
}

/* ChaCha20-Poly1305 one-time key generation */
void chacha20_poly1305_key_gen_scalar(uint8_t poly_key[32], const uint8_t key[32],
                                      const uint8_t nonce[12]) {
    uint32_t state[16];
    uint32_t keystream[16];

    /* Generate first ChaCha20 block with counter=0 */
    chacha20_init_state(state, key, nonce, 0);
    chacha20_block(keystream, state);

    /* Extract first 32 bytes as Poly1305 key */
    for (int i = 0; i < 8; i++) {
        soliton_put_le32(poly_key + i * 4, keystream[i]);
    }

    /* Wipe keystream */
    soliton_wipe(keystream, sizeof(keystream));
}

/* 4-way parallel ChaCha20 for better throughput */
void chacha20_blocks4_scalar(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, const uint8_t* in, uint8_t* out) {
    uint32_t state0[16], state1[16], state2[16], state3[16];
    uint32_t ks0[16], ks1[16], ks2[16], ks3[16];

    /* Initialize states with consecutive counters */
    chacha20_init_state(state0, key, nonce, counter + 0);
    chacha20_init_state(state1, key, nonce, counter + 1);
    chacha20_init_state(state2, key, nonce, counter + 2);
    chacha20_init_state(state3, key, nonce, counter + 3);

    /* Generate keystreams */
    chacha20_block(ks0, state0);
    chacha20_block(ks1, state1);
    chacha20_block(ks2, state2);
    chacha20_block(ks3, state3);

    /* XOR with input */
    for (int i = 0; i < 16; i++) {
        uint32_t in0 = soliton_le32(in + 0 * 64 + i * 4);
        uint32_t in1 = soliton_le32(in + 1 * 64 + i * 4);
        uint32_t in2 = soliton_le32(in + 2 * 64 + i * 4);
        uint32_t in3 = soliton_le32(in + 3 * 64 + i * 4);

        soliton_put_le32(out + 0 * 64 + i * 4, in0 ^ ks0[i]);
        soliton_put_le32(out + 1 * 64 + i * 4, in1 ^ ks1[i]);
        soliton_put_le32(out + 2 * 64 + i * 4, in2 ^ ks2[i]);
        soliton_put_le32(out + 3 * 64 + i * 4, in3 ^ ks3[i]);
    }

    /* Wipe keystreams */
    soliton_wipe(ks0, sizeof(ks0));
    soliton_wipe(ks1, sizeof(ks1));
    soliton_wipe(ks2, sizeof(ks2));
    soliton_wipe(ks3, sizeof(ks3));
}

/* Optimized ChaCha20 for multiple blocks using 4-way parallelism */
void chacha20_blocks_opt_scalar(const uint8_t key[32], const uint8_t nonce[12],
                               uint32_t counter, const uint8_t* in, uint8_t* out, size_t blocks) {
    /* Process 4 blocks at a time */
    while (blocks >= 4) {
        chacha20_blocks4_scalar(key, nonce, counter, in, out);
        counter += 4;
        in += 256;
        out += 256;
        blocks -= 4;
    }

    /* Process remaining blocks */
    if (blocks > 0) {
        chacha20_blocks_scalar(key, nonce, counter, in, out, blocks);
    }
}

/* Backend structure for scalar ChaCha20 */
soliton_backend_t backend_chacha_scalar = {
    .aes_key_expand = NULL,
    .aes_encrypt_block = NULL,
    .aes_ctr_blocks = NULL,
    .ghash_init = NULL,
    .ghash_update = NULL,
    .chacha_blocks = (void (*)(const uint8_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t))chacha20_blocks_opt_scalar,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "chacha_scalar"
};