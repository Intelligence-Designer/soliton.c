/*
 * aes_scalar.c - Table-free, constant-time AES-256 implementation
 * Freestanding C17 - no lookup tables, no secret-dependent branches
 */

#include "common.h"
#include "ct_utils.h"

/* AES round constants */
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/* GF(2^8) operations for AES */

/* Multiply in GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1 */
static SOLITON_INLINE uint8_t gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = -(b & 1);
        p ^= a & mask;
        uint8_t hi = -(a >> 7);
        a = (a << 1) ^ (0x1B & hi);
        b >>= 1;
    }
    return p;
}

/* Square in GF(2^8) */
static SOLITON_INLINE uint8_t gf256_square(uint8_t a) {
    return gf256_mul(a, a);
}


/* AES S-box using algebraic method */
static SOLITON_INLINE uint8_t aes_sbox(uint8_t x) {
    /* Step 1: Multiplicative inverse in GF(2^8) */
    uint8_t inv;
    if (x == 0) {
        inv = 0;  /* 0 has no inverse, map to 0 */
    } else {
        /* For non-zero x, compute x^254 = x^(-1) in GF(2^8) */
        uint8_t a = x;
        uint8_t a2 = gf256_square(a);
        uint8_t a3 = gf256_mul(a, a2);
        uint8_t a6 = gf256_square(a3);
        uint8_t a7 = gf256_mul(a, a6);
        uint8_t a14 = gf256_square(a7);
        uint8_t a15 = gf256_mul(a, a14);
        uint8_t a30 = gf256_square(a15);
        uint8_t a60 = gf256_square(a30);
        uint8_t a120 = gf256_square(a60);
        uint8_t a127 = gf256_mul(a7, a120);
        uint8_t a254 = gf256_square(a127);
        inv = a254;
    }

    /* Step 2: Affine transformation
     * b_i = s_i ⊕ s_{(i+4)%8} ⊕ s_{(i+5)%8} ⊕ s_{(i+6)%8} ⊕ s_{(i+7)%8} ⊕ c_i
     * where c = 0x63
     */
    uint8_t s = inv;
    uint8_t result = 0x63;  /* The constant c */

    for (int i = 0; i < 8; i++) {
        uint8_t bit = ((s >> i) & 1) ^
                     ((s >> ((i + 4) % 8)) & 1) ^
                     ((s >> ((i + 5) % 8)) & 1) ^
                     ((s >> ((i + 6) % 8)) & 1) ^
                     ((s >> ((i + 7) % 8)) & 1);
        result ^= (bit << i);
    }

    return result;
}

/* Apply S-box to 4 bytes */
static SOLITON_INLINE uint32_t aes_sbox_word(uint32_t w) {
    uint8_t b0 = aes_sbox((uint8_t)(w >> 0));
    uint8_t b1 = aes_sbox((uint8_t)(w >> 8));
    uint8_t b2 = aes_sbox((uint8_t)(w >> 16));
    uint8_t b3 = aes_sbox((uint8_t)(w >> 24));
    return (uint32_t)b0 | ((uint32_t)b1 << 8) |
           ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

/* AES MixColumns operation on a column */
static SOLITON_INLINE uint32_t aes_mix_column(uint32_t col) {
    uint8_t b0 = (uint8_t)(col >> 0);
    uint8_t b1 = (uint8_t)(col >> 8);
    uint8_t b2 = (uint8_t)(col >> 16);
    uint8_t b3 = (uint8_t)(col >> 24);

    uint8_t t = b0 ^ b1 ^ b2 ^ b3;
    uint8_t u0 = b0 ^ b1;
    uint8_t u1 = b1 ^ b2;
    uint8_t u2 = b2 ^ b3;
    uint8_t u3 = b3 ^ b0;

    u0 = gf256_mul(u0, 2);
    u1 = gf256_mul(u1, 2);
    u2 = gf256_mul(u2, 2);
    u3 = gf256_mul(u3, 2);

    uint8_t r0 = b0 ^ u0 ^ t;
    uint8_t r1 = b1 ^ u1 ^ t;
    uint8_t r2 = b2 ^ u2 ^ t;
    uint8_t r3 = b3 ^ u3 ^ t;

    return (uint32_t)r0 | ((uint32_t)r1 << 8) |
           ((uint32_t)r2 << 16) | ((uint32_t)r3 << 24);
}

/* AES state operations */
static void aes_sub_bytes(uint32_t state[4]) {
    state[0] = aes_sbox_word(state[0]);
    state[1] = aes_sbox_word(state[1]);
    state[2] = aes_sbox_word(state[2]);
    state[3] = aes_sbox_word(state[3]);
}

static void aes_shift_rows(uint32_t state[4]) {
    /* AES state is stored column-wise in little-endian format:
     * state[c] contains column c with bytes: row0 | (row1 << 8) | (row2 << 16) | (row3 << 24)
     *
     * We need to extract to byte array (column-major), apply row shifts, and reassemble
     */
    uint8_t s[16];
    uint8_t temp;

    /* Extract columns to byte array in column-major order
     * s[0-3] = column 0, s[4-7] = column 1, etc.
     */
    for (int c = 0; c < 4; c++) {
        s[c*4 + 0] = (uint8_t)(state[c] >> 0);   /* row 0 */
        s[c*4 + 1] = (uint8_t)(state[c] >> 8);   /* row 1 */
        s[c*4 + 2] = (uint8_t)(state[c] >> 16);  /* row 2 */
        s[c*4 + 3] = (uint8_t)(state[c] >> 24);  /* row 3 */
    }

    /* Apply ShiftRows on the byte array
     * Row 1: shift left by 1
     */
    temp = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = temp;

    /* Row 2: shift left by 2 */
    temp = s[2];
    s[2] = s[10];
    s[10] = temp;
    temp = s[6];
    s[6] = s[14];
    s[14] = temp;

    /* Row 3: shift left by 3 (same as shift right by 1) */
    temp = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = temp;

    /* Reassemble columns */
    for (int c = 0; c < 4; c++) {
        state[c] = (uint32_t)s[c*4 + 0] |
                   ((uint32_t)s[c*4 + 1] << 8) |
                   ((uint32_t)s[c*4 + 2] << 16) |
                   ((uint32_t)s[c*4 + 3] << 24);
    }
}

static void aes_mix_columns(uint32_t state[4]) {
    state[0] = aes_mix_column(state[0]);
    state[1] = aes_mix_column(state[1]);
    state[2] = aes_mix_column(state[2]);
    state[3] = aes_mix_column(state[3]);
}

static void aes_add_round_key(uint32_t state[4], const uint32_t* round_key) {
    state[0] ^= round_key[0];
    state[1] ^= round_key[1];
    state[2] ^= round_key[2];
    state[3] ^= round_key[3];
}

/* AES-256 key expansion */
void aes256_key_expand_scalar(const uint8_t key[32], uint32_t round_keys[60]) {
    /* Copy initial key */
    for (int i = 0; i < 8; i++) {
        round_keys[i] = soliton_le32(key + i * 4);
    }

    /* Expand key */
    for (int i = 8; i < 60; i++) {
        uint32_t temp = round_keys[i - 1];

        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            /* For little-endian, RotWord is rotate RIGHT by 8 bits */
            temp = SOLITON_ROTR32(temp, 8);
            temp = aes_sbox_word(temp);
            temp ^= (uint32_t)rcon[i / 8];  /* Rcon in LSB after rotation */
        } else if (i % 8 == 4) {
            /* SubWord only for AES-256 */
            temp = aes_sbox_word(temp);
        }

        round_keys[i] = round_keys[i - 8] ^ temp;
    }
}

/* AES-256 block encryption */
void aes256_encrypt_block_scalar(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]) {
    uint32_t state[4];

    /* Load input */
    state[0] = soliton_le32(in + 0);
    state[1] = soliton_le32(in + 4);
    state[2] = soliton_le32(in + 8);
    state[3] = soliton_le32(in + 12);

    /* Initial round key addition */
    aes_add_round_key(state, round_keys);

    /* Main rounds (13 for AES-256) */
    for (int round = 1; round < 14; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys + round * 4);
    }

    /* Final round (no MixColumns) */
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys + 14 * 4);

    /* Store output */
    soliton_put_le32(out + 0, state[0]);
    soliton_put_le32(out + 4, state[1]);
    soliton_put_le32(out + 8, state[2]);
    soliton_put_le32(out + 12, state[3]);
}

/* AES-CTR mode for multiple blocks */
void aes256_ctr_blocks_scalar(const uint32_t* round_keys, const uint8_t iv[16],
                              uint32_t counter, const uint8_t* in, uint8_t* out, size_t blocks) {
    uint8_t ctr_block[16];
    uint8_t keystream[16];

    /* Copy IV to counter block */
    for (int i = 0; i < 12; i++) {
        ctr_block[i] = iv[i];
    }

    for (size_t block = 0; block < blocks; block++) {
        /* Set counter value (big-endian) */
        soliton_put_be32(ctr_block + 12, counter + (uint32_t)block);

        /* Generate keystream */
        aes256_encrypt_block_scalar(round_keys, ctr_block, keystream);

        /* XOR with input */
        for (int i = 0; i < 16; i++) {
            out[block * 16 + i] = in[block * 16 + i] ^ keystream[i];
        }
    }

    /* Clear sensitive data */
    soliton_wipe(ctr_block, sizeof(ctr_block));
    soliton_wipe(keystream, sizeof(keystream));
}

/* External GHASH functions */
extern void ghash_init_scalar(uint8_t* h, const uint32_t* round_keys);
extern void ghash_update_scalar(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t len);

/* Backend functions for scalar AES */
soliton_backend_t backend_aes_scalar = {
    .aes_key_expand = (void (*)(const uint8_t*, uint32_t*))aes256_key_expand_scalar,
    .aes_encrypt_block = (void (*)(const uint32_t*, const uint8_t*, uint8_t*))aes256_encrypt_block_scalar,
    .aes_ctr_blocks = (void (*)(const uint32_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t))aes256_ctr_blocks_scalar,
    .ghash_init = (void (*)(uint8_t*, const uint32_t*))ghash_init_scalar,
    .ghash_update = (void (*)(uint8_t*, const uint8_t*, const uint8_t*, size_t))ghash_update_scalar,
    .chacha_blocks = NULL,
    .poly1305_init = NULL,
    .poly1305_update = NULL,
    .poly1305_final = NULL,
    .name = "scalar"
};