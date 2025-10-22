/*
 * Differential test: ghash_update_clmul8 vs single-block reference
 *
 * Tests that 8-way batched GHASH produces the same result as 8 sequential single-block updates.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* From core/ghash_clmul.c */
extern void ghash_update_clmul8(uint8_t* state, const uint8_t h_powers[8][16], const uint8_t* data, size_t len);
extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);

/* Domain transform helpers */
static inline __m128i to_lepoly_128(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

/* Single-block GHASH multiply (PCLMUL 4-partial) */
static __m128i ghash_mul_single(__m128i a, __m128i b) {
    /* 4-partial CLMUL */
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);

    /* Recombine */
    __m128i mid = _mm_xor_si128(p01, p10);
    __m128i lo = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
    __m128i hi = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));

    /* Reduce using 0xE1 polynomial (Intel method) */
    __m128i v1 = _mm_slli_epi64(hi, 1);
    __m128i v2 = _mm_slli_epi64(hi, 2);
    __m128i v7 = _mm_slli_epi64(hi, 7);
    lo = _mm_xor_si128(lo, _mm_xor_si128(v1, _mm_xor_si128(v2, v7)));

    __m128i hi_shift = _mm_slli_si128(hi, 8);
    v1 = _mm_slli_epi64(hi_shift, 1);
    v2 = _mm_slli_epi64(hi_shift, 2);
    v7 = _mm_slli_epi64(hi_shift, 7);
    lo = _mm_xor_si128(lo, _mm_xor_si128(v1, _mm_xor_si128(v2, v7)));

    __m128i t1 = _mm_srli_epi64(hi, 63);
    __m128i t2 = _mm_srli_epi64(hi, 62);
    __m128i t7 = _mm_srli_epi64(hi, 57);
    __m128i fold = _mm_xor_si128(t1, _mm_xor_si128(t2, t7));
    lo = _mm_xor_si128(lo, _mm_xor_si128(hi, fold));

    return lo;
}

/* Single-block reference: process blocks one at a time */
static void ghash_update_clmul_single(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t len) {
    __m128i Xi = _mm_loadu_si128((const __m128i*)state);
    __m128i H = _mm_loadu_si128((const __m128i*)h);

    while (len >= 16) {
        __m128i C = _mm_loadu_si128((const __m128i*)data);
        C = to_lepoly_128(C);
        Xi = _mm_xor_si128(Xi, C);
        Xi = ghash_mul_single(Xi, H);
        data += 16;
        len -= 16;
    }

    _mm_storeu_si128((__m128i*)state, Xi);
}

static void dump_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    printf("=== Differential Test: ghash_update_clmul8 vs Single-Block ===\n\n");

    /* Test case: H key from AES_K(0) with zero key */
    uint8_t h_spec[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
    };

    /* Precompute H powers (H^1 through H^16) */
    uint8_t h_powers[16][16];
    ghash_precompute_h_powers_clmul(h_powers, h_spec);

    printf("H (spec domain): ");
    dump_hex("", h_spec, 16);

    /* Test data: 8 blocks of ciphertext */
    uint8_t ciphertext[128];
    for (int i = 0; i < 128; i++) {
        ciphertext[i] = (uint8_t)(i * 17 + 42);  // Pseudo-random pattern
    }

    printf("\nCiphertext (8 blocks, 128 bytes):\n");
    for (int blk = 0; blk < 8; blk++) {
        printf("  Block %d: ", blk);
        dump_hex("", ciphertext + blk * 16, 16);
    }

    /* === Path 1: 8-way batched GHASH === */
    printf("\n8-way path:\n");
    printf("  H-powers used: H[0..7] = h_powers[7..0] = H^8..H^1\n");
    printf("  Formula: (Xi₀ ⊕ C₁)·H⁸ ⊕ C₂·H⁷ ⊕ ... ⊕ C₈·H¹\n");

    uint8_t state_8way[16] = {0};
    ghash_update_clmul8(state_8way, h_powers, ciphertext, 128);

    printf("  Result: ");
    dump_hex("", state_8way, 16);

    /* === Path 2: Single-block reference === */
    printf("\nSingle-block path:\n");
    printf("  Using H^1 (h_powers[0]) for all multiplies\n");
    printf("  Formula: Horner's rule with H¹\n");
    printf("  Y₁=(Xi₀⊕C₁)·H, Y₂=(Y₁⊕C₂)·H, ..., Y₈=(Y₇⊕C₈)·H\n");

    uint8_t state_single[16] = {0};
    ghash_update_clmul_single(state_single, h_powers[0], ciphertext, 128);

    printf("  Result: ");
    dump_hex("", state_single, 16);

    /* === Compute expected result manually === */
    printf("\nExpected formula expansion:\n");
    printf("  Y₈ = Xi₀·H⁸ ⊕ C₁·H⁸ ⊕ C₂·H⁷ ⊕ C₃·H⁶ ⊕ C₄·H⁵ ⊕ C₅·H⁴ ⊕ C₆·H³ ⊕ C₇·H² ⊕ C₈·H¹\n");
    printf("  (8-way should match this)\n");

    /* === Compare === */
    if (memcmp(state_8way, state_single, 16) == 0) {
        printf("\n✓ PASS: Results match\n");
        return 0;
    } else {
        printf("\n✗ FAIL: Results differ\n");

        /* Show byte-by-byte diff */
        printf("\nByte-by-byte comparison:\n");
        for (int i = 0; i < 16; i++) {
            printf("  [%2d] 8way=%02x single=%02x %s\n",
                   i, state_8way[i], state_single[i],
                   (state_8way[i] == state_single[i]) ? "✓" : "✗");
        }

        return 1;
    }
}
