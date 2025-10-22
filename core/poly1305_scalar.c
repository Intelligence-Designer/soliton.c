/*
 * poly1305_scalar.c - Poly1305 message authentication code (RFC 8439)
 * Constant-time implementation using 32-bit arithmetic
 */

#include "common.h"
#include "ct_utils.h"

/* Poly1305 state using 32-bit limbs for 130-bit arithmetic */
typedef struct {
    uint32_t r[5];      /* Key part r (clamped) - 26 bits per limb */
    uint32_t s[4];      /* Key part s - 32 bits per limb */
    uint32_t h[5];      /* Accumulator - 26 bits per limb */
    uint8_t buffer[16]; /* Partial block buffer */
    size_t buffer_len;  /* Bytes in buffer */
    uint32_t final;     /* Final block flag */
} poly1305_state_scalar_t;

/* Load 4 bytes as uint32_t (little-endian) */
static SOLITON_INLINE uint32_t load32_le(const uint8_t* p) {
    return soliton_le32(p);
}

/* Store uint32_t as 4 bytes (little-endian) */
static SOLITON_INLINE void store32_le(uint8_t* p, uint32_t v) {
    soliton_put_le32(p, v);
}

/* Initialize Poly1305 with key */
void poly1305_init_scalar(poly1305_state_scalar_t* st, const uint8_t key[32]) {
    /* Clear state */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* Load r and clamp */
    uint32_t t0 = load32_le(key + 0);
    uint32_t t1 = load32_le(key + 4);
    uint32_t t2 = load32_le(key + 8);
    uint32_t t3 = load32_le(key + 12);

    /* Clamp r: clear top 4 bits of each 32-bit word, clear bottom 2 bits of first and last */
    t0 &= 0x0fffffff;
    t1 &= 0x0ffffffc;
    t2 &= 0x0ffffffc;
    t3 &= 0x0ffffffc;

    /* Store r in 26-bit limbs for efficient multiplication */
    st->r[0] = t0 & 0x03ffffff;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
    st->r[4] = (t3 >> 8) & 0x00ffffff;

    /* Load s */
    st->s[0] = load32_le(key + 16);
    st->s[1] = load32_le(key + 20);
    st->s[2] = load32_le(key + 24);
    st->s[3] = load32_le(key + 28);

    /* Clear buffer */
    st->buffer_len = 0;
    st->final = 0;
}

/* Process a single block */
static void poly1305_block_scalar(poly1305_state_scalar_t* st, const uint8_t data[16], uint32_t final) {
    uint32_t t0 = load32_le(data + 0);
    uint32_t t1 = load32_le(data + 4);
    uint32_t t2 = load32_le(data + 8);
    uint32_t t3 = load32_le(data + 12);

    /* Convert to 26-bit limbs and add 2^128 or 2^(8*len) */
    uint32_t m0 = t0 & 0x03ffffff;
    uint32_t m1 = ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
    uint32_t m2 = ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
    uint32_t m3 = ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
    uint32_t m4 = (t3 >> 8) | (final << 24);

    /* h += m */
    uint64_t h0 = (uint64_t)st->h[0] + m0;
    uint64_t h1 = (uint64_t)st->h[1] + m1;
    uint64_t h2 = (uint64_t)st->h[2] + m2;
    uint64_t h3 = (uint64_t)st->h[3] + m3;
    uint64_t h4 = (uint64_t)st->h[4] + m4;

    /* h *= r (mod 2^130 - 5) */
    uint64_t d0, d1, d2, d3, d4;
    uint64_t c;

    d0 = h0 * st->r[0] + h1 * st->r[4] * 5 + h2 * st->r[3] * 5 + h3 * st->r[2] * 5 + h4 * st->r[1] * 5;
    d1 = h0 * st->r[1] + h1 * st->r[0] + h2 * st->r[4] * 5 + h3 * st->r[3] * 5 + h4 * st->r[2] * 5;
    d2 = h0 * st->r[2] + h1 * st->r[1] + h2 * st->r[0] + h3 * st->r[4] * 5 + h4 * st->r[3] * 5;
    d3 = h0 * st->r[3] + h1 * st->r[2] + h2 * st->r[1] + h3 * st->r[0] + h4 * st->r[4] * 5;
    d4 = h0 * st->r[4] + h1 * st->r[3] + h2 * st->r[2] + h3 * st->r[1] + h4 * st->r[0];

    /* Reduce to 26-bit limbs */
    c = d0 >> 26; d0 &= 0x03ffffff;
    d1 += c;      c = d1 >> 26; d1 &= 0x03ffffff;
    d2 += c;      c = d2 >> 26; d2 &= 0x03ffffff;
    d3 += c;      c = d3 >> 26; d3 &= 0x03ffffff;
    d4 += c;      c = d4 >> 26; d4 &= 0x03ffffff;
    d0 += c * 5;  c = d0 >> 26; d0 &= 0x03ffffff;
    d1 += c;

    /* Store result */
    st->h[0] = (uint32_t)d0;
    st->h[1] = (uint32_t)d1;
    st->h[2] = (uint32_t)d2;
    st->h[3] = (uint32_t)d3;
    st->h[4] = (uint32_t)d4;
}

/* Update Poly1305 with data */
void poly1305_update_scalar(poly1305_state_scalar_t* st, const uint8_t* data, size_t len) {
    /* Handle buffered data */
    if (st->buffer_len > 0) {
        size_t need = 16 - st->buffer_len;
        if (len < need) {
            /* Not enough to fill buffer */
            for (size_t i = 0; i < len; i++) {
                st->buffer[st->buffer_len + i] = data[i];
            }
            st->buffer_len += len;
            return;
        }

        /* Fill buffer and process */
        for (size_t i = 0; i < need; i++) {
            st->buffer[st->buffer_len + i] = data[i];
        }
        poly1305_block_scalar(st, st->buffer, 1);
        data += need;
        len -= need;
        st->buffer_len = 0;
    }

    /* Process full blocks */
    while (len >= 16) {
        poly1305_block_scalar(st, data, 1);
        data += 16;
        len -= 16;
    }

    /* Buffer remaining data */
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            st->buffer[i] = data[i];
        }
        st->buffer_len = len;
    }
}

/* Finalize Poly1305 and output tag */
void poly1305_final_scalar(poly1305_state_scalar_t* st, uint8_t tag[16]) {
    /* Process final partial block if any */
    if (st->buffer_len > 0) {
        /* Pad with zeros */
        for (size_t i = st->buffer_len; i < 16; i++) {
            st->buffer[i] = 0;
        }
        /* Set final bit at position 8*len */
        poly1305_block_scalar(st, st->buffer, (st->buffer_len < 16) ? 1 : 0);
    }

    /* Fully reduce h */
    uint32_t h0 = st->h[0];
    uint32_t h1 = st->h[1];
    uint32_t h2 = st->h[2];
    uint32_t h3 = st->h[3];
    uint32_t h4 = st->h[4];

    uint32_t c;
    c = h1 >> 26; h1 &= 0x03ffffff;
    h2 += c;      c = h2 >> 26; h2 &= 0x03ffffff;
    h3 += c;      c = h3 >> 26; h3 &= 0x03ffffff;
    h4 += c;      c = h4 >> 26; h4 &= 0x03ffffff;
    h0 += c * 5;  c = h0 >> 26; h0 &= 0x03ffffff;
    h1 += c;      c = h1 >> 26; h1 &= 0x03ffffff;
    h2 += c;      c = h2 >> 26; h2 &= 0x03ffffff;
    h3 += c;      c = h3 >> 26; h3 &= 0x03ffffff;
    h4 += c;      c = h4 >> 26; h4 &= 0x03ffffff;
    h0 += c * 5;  c = h0 >> 26; h0 &= 0x03ffffff;
    h1 += c;

    /* Convert to 32-bit limbs */
    uint32_t g0 = h0 | (h1 << 26);
    uint32_t g1 = (h1 >> 6) | (h2 << 20);
    uint32_t g2 = (h2 >> 12) | (h3 << 14);
    uint32_t g3 = (h3 >> 18) | (h4 << 8);
    uint32_t g4 = h4 >> 24;

    /* Compute h - (2^130 - 5) */
    uint64_t t = (uint64_t)g0 + 5;
    g0 = (uint32_t)t;
    t = (uint64_t)g1 + (t >> 32);
    g1 = (uint32_t)t;
    t = (uint64_t)g2 + (t >> 32);
    g2 = (uint32_t)t;
    t = (uint64_t)g3 + (t >> 32);
    g3 = (uint32_t)t;
    t = (uint64_t)g4 + (t >> 32);
    g4 = (uint32_t)t;

    /* Select h if h < 2^130 - 5, else h - (2^130 - 5) */
    uint32_t mask = -(g4 >> 2);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;

    mask = ~mask;
    h0 = (h0 | (h1 << 26)) & mask;
    h1 = ((h1 >> 6) | (h2 << 20)) & mask;
    h2 = ((h2 >> 12) | (h3 << 14)) & mask;
    h3 = ((h3 >> 18) | (h4 << 8)) & mask;

    h0 |= g0;
    h1 |= g1;
    h2 |= g2;
    h3 |= g3;

    /* Add s */
    uint64_t f;
    f = (uint64_t)h0 + st->s[0];
    h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->s[1] + (f >> 32);
    h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->s[2] + (f >> 32);
    h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->s[3] + (f >> 32);
    h3 = (uint32_t)f;

    /* Store tag */
    store32_le(tag + 0, h0);
    store32_le(tag + 4, h1);
    store32_le(tag + 8, h2);
    store32_le(tag + 12, h3);

    /* Wipe state */
    soliton_wipe(st, sizeof(*st));
}

/* Poly1305 one-shot interface */
void poly1305_auth_scalar(uint8_t tag[16], const uint8_t* data, size_t len, const uint8_t key[32]) {
    poly1305_state_scalar_t st;
    poly1305_init_scalar(&st, key);
    poly1305_update_scalar(&st, data, len);
    poly1305_final_scalar(&st, tag);
}

/* ChaCha20-Poly1305 AEAD construction helpers */

/* Pad to 16-byte boundary */
static void poly1305_pad16(poly1305_state_scalar_t* st, size_t len) {
    size_t pad = (16 - (len % 16)) % 16;
    if (pad > 0) {
        uint8_t zeros[16] = {0};
        poly1305_update_scalar(st, zeros, pad);
    }
}

/* Process ChaCha20-Poly1305 AEAD */
void chacha20_poly1305_encrypt_scalar(
    uint8_t* ct, uint8_t tag[16],
    const uint8_t* pt, size_t pt_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12]) {

    poly1305_state_scalar_t poly_st;
    uint8_t poly_key[32];
    uint8_t lengths[16];

    /* Generate Poly1305 key from ChaCha20 */
    extern void chacha20_poly1305_key_gen_scalar(uint8_t*, const uint8_t*, const uint8_t*);
    chacha20_poly1305_key_gen_scalar(poly_key, key, nonce);

    /* Initialize Poly1305 */
    poly1305_init_scalar(&poly_st, poly_key);

    /* Process AAD */
    if (aad_len > 0) {
        poly1305_update_scalar(&poly_st, aad, aad_len);
        poly1305_pad16(&poly_st, aad_len);
    }

    /* Encrypt plaintext with ChaCha20 */
    extern void chacha20_xor_scalar(const uint8_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
    chacha20_xor_scalar(key, nonce, 1, pt, ct, pt_len);

    /* Process ciphertext */
    poly1305_update_scalar(&poly_st, ct, pt_len);
    poly1305_pad16(&poly_st, pt_len);

    /* Process lengths */
    soliton_put_le64(lengths, aad_len);
    soliton_put_le64(lengths + 8, pt_len);
    poly1305_update_scalar(&poly_st, lengths, 16);

    /* Finalize tag */
    poly1305_final_scalar(&poly_st, tag);

    /* Wipe key */
    soliton_wipe(poly_key, sizeof(poly_key));
}

/* Verify and decrypt ChaCha20-Poly1305 */
int chacha20_poly1305_decrypt_scalar(
    uint8_t* pt,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    const uint8_t* aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12]) {

    poly1305_state_scalar_t poly_st;
    uint8_t poly_key[32];
    uint8_t computed_tag[16];
    uint8_t lengths[16];

    /* Generate Poly1305 key from ChaCha20 */
    extern void chacha20_poly1305_key_gen_scalar(uint8_t*, const uint8_t*, const uint8_t*);
    chacha20_poly1305_key_gen_scalar(poly_key, key, nonce);

    /* Initialize Poly1305 */
    poly1305_init_scalar(&poly_st, poly_key);

    /* Process AAD */
    if (aad_len > 0) {
        poly1305_update_scalar(&poly_st, aad, aad_len);
        poly1305_pad16(&poly_st, aad_len);
    }

    /* Process ciphertext */
    poly1305_update_scalar(&poly_st, ct, ct_len);
    poly1305_pad16(&poly_st, ct_len);

    /* Process lengths */
    soliton_put_le64(lengths, aad_len);
    soliton_put_le64(lengths + 8, ct_len);
    poly1305_update_scalar(&poly_st, lengths, 16);

    /* Compute tag */
    poly1305_final_scalar(&poly_st, computed_tag);

    /* Verify tag (constant-time) */
    int valid = ct_memcmp(computed_tag, tag, 16) == 0;

    /* Decrypt if valid */
    if (valid) {
        extern void chacha20_xor_scalar(const uint8_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
        chacha20_xor_scalar(key, nonce, 1, ct, pt, ct_len);
    }

    /* Wipe sensitive data */
    soliton_wipe(poly_key, sizeof(poly_key));
    soliton_wipe(computed_tag, sizeof(computed_tag));

    return valid ? 0 : -1;
}

/* Backend registration for scalar Poly1305 */
extern soliton_backend_t backend_aes_scalar;

__attribute__((constructor))
static void register_poly1305_scalar(void) {
    backend_aes_scalar.poly1305_init = (void (*)(void*, const uint8_t*))poly1305_init_scalar;
    backend_aes_scalar.poly1305_update = (void (*)(void*, const uint8_t*, size_t))poly1305_update_scalar;
    backend_aes_scalar.poly1305_final = (void (*)(void*, uint8_t*))poly1305_final_scalar;
}