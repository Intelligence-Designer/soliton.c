/*
 * Verify H-power table by recomputing via repeated multiplication
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);

static void dump_hex(const char* label, const uint8_t* data) {
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", data[i]);
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
    printf("=== H-Power Table Verification ===\n\n");

    uint8_t h_spec[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
    };

    /* Get precomputed table */
    uint8_t h_powers[16][16];
    ghash_precompute_h_powers_clmul(h_powers, h_spec);

    printf("Precomputed H-powers:\n");
    for (int i = 0; i < 8; i++) {
        printf("  h_powers[%d] (H^%d): ", i, i+1);
        for (int j = 0; j < 16; j++) printf("%02x", h_powers[i][j]);
        printf("\n");
    }

    /* Recompute via repeated multiplication */
    printf("\nRecomputing via repeated multiplication:\n");

    __m128i H1 = _mm_loadu_si128((const __m128i*)h_powers[0]);
    __m128i H_computed = H1;

    int failed = 0;
    for (int i = 1; i < 8; i++) {
        /* Compute H^(i+1) = H^i × H^1 */
        H_computed = ghash_mul(H_computed, H1);

        uint8_t computed[16];
        _mm_storeu_si128((__m128i*)computed, H_computed);

        printf("  H^%d computed: ", i+1);
        for (int j = 0; j < 16; j++) printf("%02x", computed[j]);

        if (memcmp(computed, h_powers[i], 16) == 0) {
            printf(" ✓ matches h_powers[%d]\n", i);
        } else {
            printf(" ✗ DIFFERS from h_powers[%d]\n", i);
            printf("       stored: ");
            for (int j = 0; j < 16; j++) printf("%02x", h_powers[i][j]);
            printf("\n");
            failed++;
        }
    }

    printf("\n");
    if (failed == 0) {
        printf("✓ All H-powers match (table is correct)\n");
        return 0;
    } else {
        printf("✗ %d H-powers differ (table is CORRUPTED)\n", failed);
        printf("\nThis means ghash_precompute_h_powers_clmul() is broken!\n");
        return 1;
    }
}
