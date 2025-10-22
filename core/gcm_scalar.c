/*
 * gcm_scalar.c - Constant-time GHASH implementation for GCM mode
 * Polynomial multiplication in GF(2^128) with reduction
 */

#include "common.h"
#include "ct_utils.h"

/* GF(2^128) reduction polynomial: x^128 + x^7 + x^2 + x + 1
 * In reflected representation: 0xE1 at high bits */
#define GHASH_R 0xE100000000000000ULL

/* Load block as big-endian 128-bit value */
static void ghash_load_block(uint64_t* hi, uint64_t* lo, const uint8_t block[16]) {
    /* Load as big-endian: byte 0 is most significant */
    *hi = soliton_be64(block);
    *lo = soliton_be64(block + 8);
}

/* Store block from 128-bit value */
static void ghash_store_block(uint8_t block[16], uint64_t hi, uint64_t lo) {
    /* Store as big-endian */
    soliton_put_be64(block, hi);
    soliton_put_be64(block + 8, lo);
}

/* Multiply two 128-bit values in GF(2^128) using NIST algorithm
 * Reference: NIST SP 800-38D Algorithm 1 (right-shifting variant) */
static void gf128_mul(uint64_t* z_hi, uint64_t* z_lo,
                     uint64_t x_hi, uint64_t x_lo,
                     uint64_t h_hi, uint64_t h_lo) {
    uint64_t z_h = 0;
    uint64_t z_l = 0;
    uint64_t v_h = h_hi;
    uint64_t v_l = h_lo;

    /* Process all 128 bits of x from MSB to LSB */
    for (int i = 0; i < 64; i++) {
        /* Check bit (63-i) of x_hi (processing from MSB to LSB) */
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
        v_h ^= GHASH_R & reduce;
    }

    for (int i = 0; i < 64; i++) {
        /* Check bit (63-i) of x_lo (processing from MSB to LSB) */
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
        v_h ^= GHASH_R & reduce;
    }

    *z_hi = z_h;
    *z_lo = z_l;
}

/* Initialize GHASH key H = AES_K(0) */
void ghash_init_scalar(uint8_t h[16], const uint32_t* round_keys) {
    uint8_t zero[16] = {0};

    /* H = AES_K(0) */
    extern void aes256_encrypt_block_scalar(const uint32_t*, const uint8_t*, uint8_t*);
    aes256_encrypt_block_scalar(round_keys, zero, h);
}

/* Update GHASH with data blocks */
void ghash_update_scalar(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t len) {
    uint64_t h_hi, h_lo;
    uint64_t s_hi, s_lo;
    uint64_t d_hi, d_lo;

    /* Load H */
    ghash_load_block(&h_hi, &h_lo, h);

    /* Load current state */
    ghash_load_block(&s_hi, &s_lo, state);

    /* Process complete blocks */
    while (len >= 16) {
        /* Load data block */
        ghash_load_block(&d_hi, &d_lo, data);

        /* state = (state ^ data) * H */
        s_hi ^= d_hi;
        s_lo ^= d_lo;
        gf128_mul(&s_hi, &s_lo, s_hi, s_lo, h_hi, h_lo);

        data += 16;
        len -= 16;
    }

    /* Handle partial block */
    if (len > 0) {
        uint8_t block[16] = {0};
        for (size_t i = 0; i < len; i++) {
            block[i] = data[i];
        }

        ghash_load_block(&d_hi, &d_lo, block);
        s_hi ^= d_hi;
        s_lo ^= d_lo;
        gf128_mul(&s_hi, &s_lo, s_hi, s_lo, h_hi, h_lo);

        /* Wipe temporary block */
        soliton_wipe(block, sizeof(block));
    }

    /* Store updated state */
    ghash_store_block(state, s_hi, s_lo);
}

/* Compute powers of H for optimization */
void ghash_precompute_powers_scalar(uint8_t h_powers[16][16], const uint8_t h[16]) {
    uint64_t h_hi, h_lo;
    uint64_t power_hi, power_lo;

    /* Load H */
    ghash_load_block(&h_hi, &h_lo, h);

    /* H^1 = H */
    ghash_store_block(h_powers[0], h_hi, h_lo);

    power_hi = h_hi;
    power_lo = h_lo;

    /* Compute H^2, H^3, ..., H^16 */
    for (int i = 1; i < 16; i++) {
        gf128_mul(&power_hi, &power_lo, power_hi, power_lo, h_hi, h_lo);
        ghash_store_block(h_powers[i], power_hi, power_lo);
    }
}

/* Optimized GHASH update using precomputed powers (for 8-block parallel processing) */
void ghash_update_blocks_scalar(uint8_t* state, const uint8_t h_powers[8][16],
                                const uint8_t* data, size_t blocks) {
    uint64_t s_hi, s_lo;
    uint64_t acc_hi = 0, acc_lo = 0;

    /* Load current state */
    ghash_load_block(&s_hi, &s_lo, state);

    /* Process 8 blocks at a time */
    while (blocks >= 8) {
        acc_hi = 0;
        acc_lo = 0;

        /* XOR state into first block (matching GCM spec and fused kernels) */
        uint64_t d0_hi, d0_lo;
        ghash_load_block(&d0_hi, &d0_lo, data);
        d0_hi ^= s_hi;
        d0_lo ^= s_lo;

        /* Multiply first block (with state) by H^8 */
        uint64_t h_hi, h_lo, t_hi, t_lo;
        ghash_load_block(&h_hi, &h_lo, h_powers[7]);  /* H^8 */
        gf128_mul(&t_hi, &t_lo, d0_hi, d0_lo, h_hi, h_lo);
        acc_hi ^= t_hi;
        acc_lo ^= t_lo;

        /* Accumulate blocks 1-7 with powers H^7 down to H^1 */
        for (int i = 1; i < 8; i++) {
            uint64_t d_hi, d_lo;

            ghash_load_block(&d_hi, &d_lo, data + i * 16);
            ghash_load_block(&h_hi, &h_lo, h_powers[7 - i]);

            gf128_mul(&t_hi, &t_lo, d_hi, d_lo, h_hi, h_lo);
            acc_hi ^= t_hi;
            acc_lo ^= t_lo;
        }

        /* Result becomes new state */
        s_hi = acc_hi;
        s_lo = acc_lo;

        data += 128;
        blocks -= 8;
    }

    /* Process remaining blocks */
    if (blocks > 0) {
        uint64_t h_hi, h_lo;
        ghash_load_block(&h_hi, &h_lo, h_powers[0]);  /* H^1 */

        while (blocks > 0) {
            uint64_t d_hi, d_lo;
            ghash_load_block(&d_hi, &d_lo, data);

            s_hi ^= d_hi;
            s_lo ^= d_lo;
            gf128_mul(&s_hi, &s_lo, s_hi, s_lo, h_hi, h_lo);

            data += 16;
            blocks--;
        }
    }

    /* Store updated state */
    ghash_store_block(state, s_hi, s_lo);
}

/* Finalize GHASH for GCM tag computation */
void ghash_final_scalar(uint8_t* tag, const uint8_t* state, const uint8_t* h,
                       uint64_t aad_len, uint64_t ct_len) {
    uint64_t h_hi, h_lo;
    uint64_t s_hi, s_lo;
    uint8_t len_block[16];

    /* Load H and state */
    ghash_load_block(&h_hi, &h_lo, h);
    ghash_load_block(&s_hi, &s_lo, state);

    /* Construct length block: [aad_len * 8][ct_len * 8] in bits */
    soliton_put_be64(len_block, aad_len * 8);
    soliton_put_be64(len_block + 8, ct_len * 8);

    /* Final GHASH: state = (state ^ len_block) * H */
    uint64_t len_hi, len_lo;
    ghash_load_block(&len_hi, &len_lo, len_block);

    s_hi ^= len_hi;
    s_lo ^= len_lo;
    gf128_mul(&s_hi, &s_lo, s_hi, s_lo, h_hi, h_lo);

    /* Store final tag */
    ghash_store_block(tag, s_hi, s_lo);
}

/* GHASH functions are now directly linked in aes_scalar.c */