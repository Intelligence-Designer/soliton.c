/*
 * Minimal GHASH verification - single multiply test
 * This will reveal if the CLMUL path is algebraically correct
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

// Copy the exact functions from ghash_clmul.c for isolated testing
static void print_m128i(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    printf("%-30s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
    printf("\n");
}

// Boundary transformations (from ghash_clmul.c)
static inline __m128i to_lepoly_128(__m128i x_spec) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_spec, rev);
}

static inline __m128i from_lepoly_128(__m128i x_kernel) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_kernel, rev);
}

// Reduction (from ghash_clmul.c) - Intel whitepaper algorithm
static inline __m128i ghash_reduce_kerneldomain(__m128i lo, __m128i hi) {
    // Phase 1: left-shift taps <<1, <<2, <<7
    __m128i v1 = _mm_slli_epi64(hi, 1);
    __m128i v2 = _mm_slli_epi64(hi, 2);
    __m128i v7 = _mm_slli_epi64(hi, 7);
    lo = _mm_xor_si128(lo, _mm_xor_si128(v1, _mm_xor_si128(v2, v7)));

    // Phase 2: cross-lane shift
    __m128i hi_shift = _mm_slli_si128(hi, 8);
    v1 = _mm_slli_epi64(hi_shift, 1);
    v2 = _mm_slli_epi64(hi_shift, 2);
    v7 = _mm_slli_epi64(hi_shift, 7);
    lo = _mm_xor_si128(lo, _mm_xor_si128(v1, _mm_xor_si128(v2, v7)));

    // Phase 3: right-fold >>63, >>62, >>57
    __m128i t1 = _mm_srli_epi64(hi, 63);
    __m128i t2 = _mm_srli_epi64(hi, 62);
    __m128i t7 = _mm_srli_epi64(hi, 57);
    __m128i fold = _mm_xor_si128(t1, _mm_xor_si128(t2, t7));
    lo = _mm_xor_si128(lo, _mm_xor_si128(hi, fold));

    return lo;
}

// Karatsuba multiply (from ghash_clmul.c)
static __m128i ghash_mul_reflected(__m128i a, __m128i b) {
    __m128i l  = _mm_clmulepi64_si128(a, b, 0x00);  // a0*b0
    __m128i h  = _mm_clmulepi64_si128(a, b, 0x11);  // a1*b1
    __m128i m  = _mm_clmulepi64_si128(
                    _mm_xor_si128(a, _mm_srli_si128(a, 8)),
                    _mm_xor_si128(b, _mm_srli_si128(b, 8)), 0x00);
    m = _mm_xor_si128(m, _mm_xor_si128(l, h));

    __m128i mid_lo = _mm_slli_si128(m, 8);
    __m128i mid_hi = _mm_srli_si128(m, 8);
    l = _mm_xor_si128(l, mid_lo);
    h = _mm_xor_si128(h, mid_hi);

    return ghash_reduce_kerneldomain(l, h);
}

int main() {
    printf("=== Minimal GHASH Single Multiply Test ===\n\n");

    // Test data (from Python reference)
    uint8_t H_bytes[16], C_bytes[16];
    for (int i = 0; i < 16; i++) {
        sscanf("dc95c078a2408989ad48a21492842087" + i*2, "%2hhx", &H_bytes[i]);
        sscanf("cea7403d4d606b6e074ec5d3baf39d18" + i*2, "%2hhx", &C_bytes[i]);
    }

    printf("Test: Compute C × H in kernel domain\n\n");

    // Load in spec domain
    __m128i H_spec = _mm_loadu_si128((const __m128i*)H_bytes);
    __m128i C_spec = _mm_loadu_si128((const __m128i*)C_bytes);

    print_m128i("H_spec (input)", H_spec);
    print_m128i("C_spec (input)", C_spec);

    // Transform to kernel domain (NO multiply-by-x)
    __m128i H_kern = to_lepoly_128(H_spec);
    __m128i C_kern = to_lepoly_128(C_spec);

    print_m128i("H_kern (byte-swapped)", H_kern);
    print_m128i("C_kern (byte-swapped)", C_kern);

    // Multiply in kernel domain
    __m128i result_kern = ghash_mul_reflected(C_kern, H_kern);

    print_m128i("Result_kern (C × H)", result_kern);

    // Transform back to spec domain
    __m128i result_spec = from_lepoly_128(result_kern);

    print_m128i("Result_spec (swapped back)", result_spec);

    // Expected result (from Python reference)
    printf("\nExpected (Python):               fd6ab7586e556dba06d69cfe6223b262\n");

    uint8_t expected[16];
    for (int i = 0; i < 16; i++) {
        sscanf("fd6ab7586e556dba06d69cfe6223b262" + i*2, "%2hhx", &expected[i]);
    }

    uint8_t result_bytes[16];
    _mm_storeu_si128((__m128i*)result_bytes, result_spec);

    if (memcmp(result_bytes, expected, 16) == 0) {
        printf("\n✓✓✓ SINGLE MULTIPLY CORRECT! ✓✓✓\n");
        return 0;
    } else {
        printf("\n✗ Still incorrect - deeper investigation needed\n");

        // Show XOR difference
        printf("\nDifference (XOR):                ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", result_bytes[i] ^ expected[i]);
        }
        printf("\n");

        return 1;
    }
}
