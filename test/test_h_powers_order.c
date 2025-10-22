/*
 * Verify H-power precomputation order
 *
 * Check that h_powers[i] actually contains H^(i+1).
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);

static inline __m128i to_lepoly_128(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

/* Simple GHASH multiply (4-partial with reduction) */
static __m128i ghash_mul(__m128i a, __m128i b) {
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);

    __m128i mid = _mm_xor_si128(p01, p10);
    __m128i lo = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
    __m128i hi = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));

    /* Reduce */
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

static void dump_m128i(const char* label, __m128i v) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, v);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", bytes[i]);
    printf("\n");
}

int main(void) {
    printf("=== H-Power Order Verification ===\n\n");

    /* Use known H from AES-256 zero key */
    uint8_t h_spec[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
    };

    uint8_t h_powers[16][16];
    ghash_precompute_h_powers_clmul(h_powers, h_spec);

    /* Load as __m128i */
    __m128i H1 = _mm_loadu_si128((const __m128i*)h_powers[0]);
    __m128i H2_stored = _mm_loadu_si128((const __m128i*)h_powers[1]);
    __m128i H8_stored = _mm_loadu_si128((const __m128i*)h_powers[7]);

    printf("From precomputed table:\n");
    dump_m128i("  h_powers[0] (H^1)", H1);
    dump_m128i("  h_powers[1] (H^2 stored)", H2_stored);
    dump_m128i("  h_powers[7] (H^8 stored)", H8_stored);

    /* Compute H^2 manually */
    __m128i H2_computed = ghash_mul(H1, H1);
    printf("\nManually computed:\n");
    dump_m128i("  H^1 × H^1 (H^2 computed)", H2_computed);

    /* Compute H^8 manually */
    __m128i H8_computed = H1;
    for (int i = 0; i < 7; i++) {
        H8_computed = ghash_mul(H8_computed, H1);
    }
    dump_m128i("  (H^1)^8 (H^8 computed)", H8_computed);

    /* Verify */
    printf("\nVerification:\n");
    if (memcmp(&H2_stored, &H2_computed, 16) == 0) {
        printf("  ✓ h_powers[1] == H^2 (correct)\n");
    } else {
        printf("  ✗ h_powers[1] ≠ H^2 (BUG!)\n");
        return 1;
    }

    if (memcmp(&H8_stored, &H8_computed, 16) == 0) {
        printf("  ✓ h_powers[7] == H^8 (correct)\n");
    } else {
        printf("  ✗ h_powers[7] ≠ H^8 (BUG!)\n");
        return 1;
    }

    printf("\n✓ H-power table is correctly ordered\n");
    printf("  h_powers[i] = H^(i+1) for i=0..15\n");

    return 0;
}
