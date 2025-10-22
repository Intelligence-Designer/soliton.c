/*
 * Manual Horner computation to verify single-block path
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);

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

static inline void clmul_x4_256(__m128i a, __m128i b, __m128i *lo, __m128i *hi) {
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);

    __m128i mid = _mm_xor_si128(p01, p10);
    *lo = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
    *hi = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));
}

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

static inline __m128i ghash_mul(__m128i a, __m128i b) {
    __m128i lo, hi;
    clmul_x4_256(a, b, &lo, &hi);
    return ghash_reduce_intel(lo, hi);
}

int main(void) {
    printf("=== Manual Horner Iteration ===\n\n");

    uint8_t h_spec[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
    };

    uint8_t h_powers[16][16];
    ghash_precompute_h_powers_clmul(h_powers, h_spec);

    __m128i H1 = _mm_loadu_si128((const __m128i*)h_powers[0]);
    dump_m128i("H^1", H1);

    /* Test data */
    uint8_t ciphertext[128];
    for (int i = 0; i < 128; i++) {
        ciphertext[i] = (uint8_t)(i * 17 + 42);
    }

    /* Horner: Y₁ = C₁×H, Y₂ = (Y₁⊕C₂)×H, ... */
    printf("\nHorner iteration:\n");
    __m128i Y = _mm_setzero_si128();

    for (int i = 0; i < 8; i++) {
        __m128i C = _mm_loadu_si128((const __m128i*)(ciphertext + i * 16));
        C = to_lepoly_128(C);

        printf("\nStep %d:\n", i+1);
        dump_m128i("  C", C);
        dump_m128i("  Y (before)", Y);

        Y = _mm_xor_si128(Y, C);
        dump_m128i("  Y⊕C", Y);

        Y = ghash_mul(Y, H1);
        dump_m128i("  (Y⊕C)×H", Y);
    }

    printf("\nFinal Horner result: ");
    dump_m128i("", Y);

    printf("\nExpected (from power-sum): 121c6259d90d15c37a4e0765173c7f35\n");

    uint8_t y_bytes[16];
    _mm_storeu_si128((__m128i*)y_bytes, Y);
    uint8_t expected[] = {0x12,0x1c,0x62,0x59,0xd9,0x0d,0x15,0xc3,
                          0x7a,0x4e,0x07,0x65,0x17,0x3c,0x7f,0x35};

    if (memcmp(y_bytes, expected, 16) == 0) {
        printf("✓ PASS: Horner matches power-sum\n");
        return 0;
    } else {
        printf("✗ FAIL: Horner differs from power-sum\n");
        return 1;
    }
}
