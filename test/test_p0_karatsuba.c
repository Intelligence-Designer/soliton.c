/*
 * Gate P0: Karatsuba vs 4-Partial CLMUL Product Validation
 * Reference: 4-partial schoolbook CLMUL (definition-correct)
 * Test: Karatsuba 3-multiply CLMUL (optimization)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <time.h>

/* Random __m128i */
static __m128i random_m128i() {
    return _mm_set_epi64x(
        ((uint64_t)rand() << 32) | rand(),
        ((uint64_t)rand() << 32) | rand()
    );
}

/* Dump __m128i as hex */
static void dump_m128i(const char* label, __m128i v) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, v);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

/* =============================================================================
 * 4-Partial Schoolbook CLMUL Multiply (REFERENCE - Definition Correct)
 * Produces unreduced 256-bit product (lo, hi) in CLMUL domain
 * ============================================================================= */
static void clmul_product_4partial(__m128i a, __m128i b, __m128i* lo, __m128i* hi) {
    /* Four partial products using all selector combinations */
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);  // a_lo * b_lo
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);  // a_lo * b_hi
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);  // a_hi * b_lo
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);  // a_hi * b_hi

    /* Recombine into 256-bit result:
     * product = p11*x^128 + (p01 + p10)*x^64 + p00
     *
     * Split the cross terms:
     * p01[127:64] goes to hi[63:0]
     * p01[63:0] goes to lo[127:64]
     * p10[127:64] goes to hi[63:0]
     * p10[63:0] goes to lo[127:64]
     */

    *lo = p00;
    *lo = _mm_xor_si128(*lo, _mm_slli_si128(p01, 8));  // p01[63:0] << 64 → lo[127:64]
    *lo = _mm_xor_si128(*lo, _mm_slli_si128(p10, 8));  // p10[63:0] << 64 → lo[127:64]

    *hi = p11;
    *hi = _mm_xor_si128(*hi, _mm_srli_si128(p01, 8));  // p01[127:64] → hi[63:0]
    *hi = _mm_xor_si128(*hi, _mm_srli_si128(p10, 8));  // p10[127:64] → hi[63:0]
}

/* =============================================================================
 * Karatsuba 3-multiply CLMUL (OPTIMIZED - Under Test)
 * Produces unreduced 256-bit product (lo, hi) in CLMUL domain
 * ============================================================================= */
static void clmul_product_karatsuba(__m128i a, __m128i b, __m128i* lo, __m128i* hi) {
    /* Karatsuba: (a_hi*x^64 + a_lo) * (b_hi*x^64 + b_lo)
     * = a_hi*b_hi*x^128 + ((a_hi+a_lo)*(b_hi+b_lo) - a_hi*b_hi - a_lo*b_lo)*x^64 + a_lo*b_lo
     */

    __m128i p_lo = _mm_clmulepi64_si128(a, b, 0x00);  // a_lo * b_lo
    __m128i p_hi = _mm_clmulepi64_si128(a, b, 0x11);  // a_hi * b_hi

    /* Compute (a_lo + a_hi) and (b_lo + b_hi) */
    __m128i a_sum = _mm_xor_si128(a, _mm_srli_si128(a, 8));  // a_lo + a_hi (in low 64 bits)
    __m128i b_sum = _mm_xor_si128(b, _mm_srli_si128(b, 8));  // b_lo + b_hi (in low 64 bits)

    /* Middle product: (a_lo + a_hi) * (b_lo + b_hi) */
    __m128i p_mid_raw = _mm_clmulepi64_si128(a_sum, b_sum, 0x00);

    /* Correct middle term: p_mid = p_mid_raw - p_lo - p_hi */
    __m128i p_mid = _mm_xor_si128(p_mid_raw, p_lo);
    p_mid = _mm_xor_si128(p_mid, p_hi);

    /* Recombine into 256-bit result */
    *lo = _mm_xor_si128(p_lo, _mm_slli_si128(p_mid, 8));  // p_lo + (p_mid[63:0] << 64)
    *hi = _mm_xor_si128(p_hi, _mm_srli_si128(p_mid, 8));  // p_hi + (p_mid[127:64] >> 64)
}

/* =============================================================================
 * Gate P0 Tests
 * ============================================================================= */

/* Test 1: Unit vectors (isolate individual CLMUL partials) */
static int test_unit_vectors() {
    printf("=== Gate P0: Unit Vector Tests ===\n");
    int pass = 0, fail = 0;

    /* Test cases: (a, b) pairs where a has single bit set */
    __m128i test_vectors[] = {
        _mm_set_epi64x(0, 1),                      // Bit 0 (tests p00)
        _mm_set_epi64x(0, 1ULL << 63),             // Bit 63 (tests p00)
        _mm_set_epi64x(1, 0),                      // Bit 64 (tests p10)
        _mm_set_epi64x(1ULL << 63, 0)              // Bit 127 (tests p11)
    };
    __m128i b = _mm_set_epi64x(0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL);

    for (int i = 0; i < 4; i++) {
        __m128i a = test_vectors[i];

        __m128i lo_ref, hi_ref;
        __m128i lo_karat, hi_karat;

        clmul_product_4partial(a, b, &lo_ref, &hi_ref);
        clmul_product_karatsuba(a, b, &lo_karat, &hi_karat);

        /* Compare Karatsuba vs 4-partial reference */
        if (memcmp(&lo_ref, &lo_karat, 16) != 0 || memcmp(&hi_ref, &hi_karat, 16) != 0) {
            printf("FAIL: Unit vector %d (Karatsuba)\n", i);
            dump_m128i("  a", a);
            dump_m128i("  b", b);
            dump_m128i("  lo_4partial", lo_ref);
            dump_m128i("  lo_karatsuba", lo_karat);
            dump_m128i("  hi_4partial", hi_ref);
            dump_m128i("  hi_karatsuba", hi_karat);
            fail++;
        } else {
            pass++;
        }
    }

    printf("Unit vectors: %d/%d passed\n", pass, pass + fail);
    return (fail == 0);
}

/* Test 2: Random pairs (comprehensive validation) */
static int test_random_pairs() {
    printf("\n=== Gate P0: Random Pair Tests (256 cases) ===\n");
    int pass = 0;
    int fail = 0;

    for (int i = 0; i < 256; i++) {
        __m128i a = random_m128i();
        __m128i b = random_m128i();

        __m128i lo_ref, hi_ref;
        __m128i lo_karat, hi_karat;

        clmul_product_4partial(a, b, &lo_ref, &hi_ref);
        clmul_product_karatsuba(a, b, &lo_karat, &hi_karat);

        /* Compare Karatsuba vs 4-partial reference */
        if (memcmp(&lo_ref, &lo_karat, 16) != 0 || memcmp(&hi_ref, &hi_karat, 16) != 0) {
            printf("FAIL: Random pair %d (Karatsuba)\n", i);
            dump_m128i("  a", a);
            dump_m128i("  b", b);
            dump_m128i("  lo_4partial", lo_ref);
            dump_m128i("  lo_karatsuba", lo_karat);
            dump_m128i("  hi_4partial", hi_ref);
            dump_m128i("  hi_karatsuba", hi_karat);
            fail++;
            if (fail >= 5) break;  // Stop after 5 failures
        } else {
            pass++;
        }
    }

    printf("Karatsuba: %d/256 passed\n", pass);
    return (fail == 0);
}

int main() {
    srand(time(NULL));

    printf("Gate P0: Karatsuba vs 4-Partial CLMUL Validation\n");
    printf("=================================================\n\n");

    int all_pass = 1;

    if (!test_unit_vectors()) {
        all_pass = 0;
    }

    if (!test_random_pairs()) {
        all_pass = 0;
    }

    printf("\n");
    if (all_pass) {
        printf("✓ Gate P0 (Karatsuba): ALL TESTS PASSED\n");
        printf("  - Karatsuba 3-multiply == 4-partial schoolbook\n");
        printf("  - 256-bit unreduced products are bit-exact\n");
        return 0;
    } else {
        printf("✗ Gate P0 (Karatsuba): FAILURES DETECTED\n");
        return 1;
    }
}
