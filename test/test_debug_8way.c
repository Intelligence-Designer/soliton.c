/*
 * Debug test: Step-by-step 8-way computation with instrumentation
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* From ghash_clmul.c */
extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);
extern void ghash_update_clmul(uint8_t* state, const uint8_t* h_bytes, const uint8_t* data, size_t len);

static void dump_m128i(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
    printf("\n");
}

static inline __m128i to_lepoly_128(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

/* Copy of clmul_x4_256 */
static inline void clmul_x4_256(__m128i a, __m128i b, __m128i *lo, __m128i *hi) {
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);

    __m128i mid = _mm_xor_si128(p01, p10);
    *lo = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
    *hi = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));
}

/* Copy of ghash_reduce_intel */
static inline __m128i ghash_reduce_intel(__m128i lo, __m128i hi) {
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

int main(void) {
    printf("=== Debug: Manual 8-way computation ===\n\n");

    uint8_t h_spec[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
    };

    uint8_t h_powers[16][16];
    ghash_precompute_h_powers_clmul(h_powers, h_spec);

    printf("H-powers (kernel domain):\n");
    for (int i = 0; i < 8; i++) {
        printf("  h_powers[%d] = H^%d: ", i, i+1);
        for (int j = 0; j < 16; j++) printf("%02x", h_powers[i][j]);
        printf("\n");
    }

    /* Test data */
    uint8_t ciphertext[128];
    for (int i = 0; i < 128; i++) {
        ciphertext[i] = (uint8_t)(i * 17 + 42);
    }

    /* Manual 8-way computation */
    printf("\n=== Manual 8-way (step-by-step) ===\n");

    __m128i Xi = _mm_setzero_si128();

    /* Load H powers */
    __m128i H[8];
    for (int i = 0; i < 8; i++) {
        H[i] = _mm_loadu_si128((const __m128i*)h_powers[7 - i]);
        printf("H[%d] = h_powers[%d] = H^%d\n", i, 7-i, 8-i);
    }

    /* Load ciphertext blocks */
    __m128i C[8];
    for (int i = 0; i < 8; i++) {
        C[i] = _mm_loadu_si128((const __m128i*)(ciphertext + i * 16));
        C[i] = to_lepoly_128(C[i]);
    }

    /* XOR state into first block */
    C[0] = _mm_xor_si128(C[0], Xi);
    dump_m128i("C[0] after XOR Xi", C[0]);

    /* Compute products */
    printf("\nComputing products:\n");
    for (int i = 0; i < 8; i++) {
        __m128i lo, hi;
        clmul_x4_256(C[i], H[i], &lo, &hi);
        __m128i reduced = ghash_reduce_intel(lo, hi);

        printf("  Product %d: C[%d] × H[%d]\n", i, i, i);
        dump_m128i("    C[i]    ", C[i]);
        dump_m128i("    H[i]    ", H[i]);
        dump_m128i("    reduced ", reduced);

        Xi = _mm_xor_si128(Xi, reduced);
        dump_m128i("    Xi (acc)", Xi);
    }

    printf("\nManual 8-way result: ");
    dump_m128i("", Xi);

    /* Compare with single-block */
    printf("\n=== Single-block reference ===\n");
    uint8_t state_single[16] = {0};
    ghash_update_clmul(state_single, h_powers[0], ciphertext, 128);

    printf("Single-block result: ");
    for (int i = 0; i < 16; i++) printf("%02x", state_single[i]);
    printf("\n");

    /* Compare */
    uint8_t manual[16];
    _mm_storeu_si128((__m128i*)manual, Xi);

    printf("\n=== Comparison ===\n");
    if (memcmp(manual, state_single, 16) == 0) {
        printf("✓ PASS: Manual 8-way matches single-block\n");
        return 0;
    } else {
        printf("✗ FAIL: Results differ\n");
        for (int i = 0; i < 16; i++) {
            printf("  [%2d] manual=%02x single=%02x %s\n",
                   i, manual[i], state_single[i],
                   (manual[i] == state_single[i]) ? "✓" : "✗");
        }
        return 1;
    }
}
