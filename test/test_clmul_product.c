/*
 * Gate P0 Extension: CLMUL 4-partial product validation
 * Tests that CLMUL 4-partial schoolbook produces correct 256-bit unreduced products
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <time.h>

/* Byte-swap for domain conversion */
static inline uint64_t bswap64(uint64_t x) {
    return __builtin_bswap64(x);
}

static inline __m128i to_lepoly_128(__m128i x) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, x);
    uint64_t lo = bswap64(*(uint64_t*)(bytes + 8));
    uint64_t hi = bswap64(*(uint64_t*)bytes);
    return _mm_set_epi64x(hi, lo);
}

static inline __m128i from_lepoly_128(__m128i x) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, x);
    uint64_t lo = bswap64(*(uint64_t*)(bytes + 8));
    uint64_t hi = bswap64(*(uint64_t*)bytes);
    return _mm_set_epi64x(hi, lo);
}

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
 * 4-Partial Schoolbook CLMUL Multiply (Reference Implementation)
 * Produces unreduced 256-bit product (lo, hi)
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
 * Karatsuba 3-multiply CLMUL (Optimized Implementation)
 * Produces unreduced 256-bit product (lo, hi)
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
 * Scalar 256-bit Polynomial Multiply (Ground Truth for Gate P0)
 * Produces unreduced 256-bit product (lo, hi)
 * ============================================================================= */
static void scalar_product_256bit(__m128i a, __m128i b, __m128i* lo_out, __m128i* hi_out) {
    /* Convert to spec domain (big-endian) */
    a = from_lepoly_128(a);
    b = from_lepoly_128(b);

    uint8_t a_bytes[16], b_bytes[16];
    _mm_storeu_si128((__m128i*)a_bytes, a);
    _mm_storeu_si128((__m128i*)b_bytes, b);

    /* Interpret as big-endian 128-bit polynomials */
    uint64_t a_hi = ((uint64_t)a_bytes[0] << 56) | ((uint64_t)a_bytes[1] << 48) |
                    ((uint64_t)a_bytes[2] << 40) | ((uint64_t)a_bytes[3] << 32) |
                    ((uint64_t)a_bytes[4] << 24) | ((uint64_t)a_bytes[5] << 16) |
                    ((uint64_t)a_bytes[6] << 8)  | ((uint64_t)a_bytes[7]);
    uint64_t a_lo = ((uint64_t)a_bytes[8] << 56) | ((uint64_t)a_bytes[9] << 48) |
                    ((uint64_t)a_bytes[10] << 40) | ((uint64_t)a_bytes[11] << 32) |
                    ((uint64_t)a_bytes[12] << 24) | ((uint64_t)a_bytes[13] << 16) |
                    ((uint64_t)a_bytes[14] << 8)  | ((uint64_t)a_bytes[15]);

    uint64_t b_hi = ((uint64_t)b_bytes[0] << 56) | ((uint64_t)b_bytes[1] << 48) |
                    ((uint64_t)b_bytes[2] << 40) | ((uint64_t)b_bytes[3] << 32) |
                    ((uint64_t)b_bytes[4] << 24) | ((uint64_t)b_bytes[5] << 16) |
                    ((uint64_t)b_bytes[6] << 8)  | ((uint64_t)b_bytes[7]);
    uint64_t b_lo = ((uint64_t)b_bytes[8] << 56) | ((uint64_t)b_bytes[9] << 48) |
                    ((uint64_t)b_bytes[10] << 40) | ((uint64_t)b_bytes[11] << 32) |
                    ((uint64_t)b_bytes[12] << 24) | ((uint64_t)b_bytes[13] << 16) |
                    ((uint64_t)b_bytes[14] << 8)  | ((uint64_t)b_bytes[15]);

    /* 256-bit product storage [bits 0-63, 64-127, 128-191, 192-255] */
    uint64_t result[4] = {0};

    /* Schoolbook multiply: for each bit in a, conditionally XOR shifted b */
    for (int i = 0; i < 128; i++) {
        uint64_t bit;
        if (i < 64) {
            bit = (a_hi >> (63 - i)) & 1;
        } else {
            bit = (a_lo >> (127 - i)) & 1;
        }

        if (bit) {
            /* XOR b shifted left by i positions into result */
            if (i < 64) {
                result[0] ^= b_lo << i;
                result[1] ^= (b_hi << i) | (b_lo >> (64 - i));
                result[2] ^= b_hi >> (64 - i);
            } else if (i == 64) {
                result[1] ^= b_lo;
                result[2] ^= b_hi;
            } else {
                int shift = i - 64;
                result[1] ^= b_lo << shift;
                result[2] ^= (b_hi << shift) | (b_lo >> (64 - shift));
                result[3] ^= b_hi >> (64 - shift);
            }
        }
    }

    /* Pack result as __m128i (spec domain, big-endian) */
    uint8_t lo_bytes[16], hi_bytes[16];
    for (int i = 0; i < 8; i++) {
        lo_bytes[i] = (result[1] >> (56 - i*8)) & 0xFF;
        lo_bytes[8+i] = (result[0] >> (56 - i*8)) & 0xFF;
        hi_bytes[i] = (result[3] >> (56 - i*8)) & 0xFF;
        hi_bytes[8+i] = (result[2] >> (56 - i*8)) & 0xFF;
    }

    __m128i lo_spec = _mm_loadu_si128((const __m128i*)lo_bytes);
    __m128i hi_spec = _mm_loadu_si128((const __m128i*)hi_bytes);

    /* Convert back to kernel domain (byte-swapped) for comparison */
    *lo_out = to_lepoly_128(lo_spec);
    *hi_out = to_lepoly_128(hi_spec);
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
        /* Convert test vectors to lepoly domain (what CLMUL functions expect) */
        __m128i a_le = to_lepoly_128(test_vectors[i]);
        __m128i b_le = to_lepoly_128(b);

        __m128i lo_scalar, hi_scalar;
        __m128i lo_4part, hi_4part;
        __m128i lo_karat, hi_karat;

        scalar_product_256bit(a_le, b_le, &lo_scalar, &hi_scalar);
        clmul_product_4partial(a_le, b_le, &lo_4part, &hi_4part);
        clmul_product_karatsuba(a_le, b_le, &lo_karat, &hi_karat);

        /* Compare 4-partial vs scalar */
        if (memcmp(&lo_scalar, &lo_4part, 16) != 0 || memcmp(&hi_scalar, &hi_4part, 16) != 0) {
            printf("FAIL: Unit vector %d (4-partial)\n", i);
            dump_m128i("  a", test_vectors[i]);
            dump_m128i("  b", b);
            dump_m128i("  lo_scalar", lo_scalar);
            dump_m128i("  lo_4part", lo_4part);
            dump_m128i("  hi_scalar", hi_scalar);
            dump_m128i("  hi_4part", hi_4part);
            fail++;
        } else {
            pass++;
        }

        /* Compare Karatsuba vs scalar */
        if (memcmp(&lo_scalar, &lo_karat, 16) != 0 || memcmp(&hi_scalar, &hi_karat, 16) != 0) {
            printf("FAIL: Unit vector %d (Karatsuba)\n", i);
            dump_m128i("  a", test_vectors[i]);
            dump_m128i("  b", b);
            dump_m128i("  lo_scalar", lo_scalar);
            dump_m128i("  lo_karat", lo_karat);
            dump_m128i("  hi_scalar", hi_scalar);
            dump_m128i("  hi_karat", hi_karat);
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
    int pass_4part = 0, pass_karat = 0;
    int fail_4part = 0, fail_karat = 0;

    for (int i = 0; i < 256; i++) {
        __m128i a_spec = random_m128i();
        __m128i b_spec = random_m128i();

        /* Convert to lepoly domain (what CLMUL functions expect) */
        __m128i a = to_lepoly_128(a_spec);
        __m128i b = to_lepoly_128(b_spec);

        __m128i lo_scalar, hi_scalar;
        __m128i lo_4part, hi_4part;
        __m128i lo_karat, hi_karat;

        scalar_product_256bit(a, b, &lo_scalar, &hi_scalar);
        clmul_product_4partial(a, b, &lo_4part, &hi_4part);
        clmul_product_karatsuba(a, b, &lo_karat, &hi_karat);

        /* Compare 4-partial vs scalar */
        if (memcmp(&lo_scalar, &lo_4part, 16) != 0 || memcmp(&hi_scalar, &hi_4part, 16) != 0) {
            printf("FAIL: Random pair %d (4-partial)\n", i);
            dump_m128i("  a_spec", a_spec);
            dump_m128i("  b_spec", b_spec);
            dump_m128i("  lo_scalar", lo_scalar);
            dump_m128i("  lo_4part", lo_4part);
            dump_m128i("  hi_scalar", hi_scalar);
            dump_m128i("  hi_4part", hi_4part);
            fail_4part++;
            if (fail_4part >= 5) break;  // Stop after 5 failures
        } else {
            pass_4part++;
        }

        /* Compare Karatsuba vs scalar */
        if (memcmp(&lo_scalar, &lo_karat, 16) != 0 || memcmp(&hi_scalar, &hi_karat, 16) != 0) {
            printf("FAIL: Random pair %d (Karatsuba)\n", i);
            dump_m128i("  a_spec", a_spec);
            dump_m128i("  b_spec", b_spec);
            dump_m128i("  lo_scalar", lo_scalar);
            dump_m128i("  lo_karat", lo_karat);
            dump_m128i("  hi_scalar", hi_scalar);
            dump_m128i("  hi_karat", hi_karat);
            fail_karat++;
            if (fail_karat >= 5) break;  // Stop after 5 failures
        } else {
            pass_karat++;
        }
    }

    printf("4-partial: %d/256 passed\n", pass_4part);
    printf("Karatsuba: %d/256 passed\n", pass_karat);
    return (fail_4part == 0 && fail_karat == 0);
}

int main() {
    srand(time(NULL));

    printf("Gate P0 Extension: CLMUL Product Validation\n");
    printf("=============================================\n\n");

    int all_pass = 1;

    if (!test_unit_vectors()) {
        all_pass = 0;
    }

    if (!test_random_pairs()) {
        all_pass = 0;
    }

    printf("\n");
    if (all_pass) {
        printf("✓ Gate P0 (CLMUL): ALL TESTS PASSED\n");
        printf("  - 4-partial schoolbook: CORRECT\n");
        printf("  - Karatsuba 3-multiply: CORRECT\n");
        return 0;
    } else {
        printf("✗ Gate P0 (CLMUL): FAILURES DETECTED\n");
        return 1;
    }
}
