/*
 * test_ghash_edges.c — GHASH Edge Case Tests (Gate A Extension)
 *
 * PROOF OBLIGATION:
 *   Test corner cases that stress specific code paths in the reducer:
 *   - All-zeros, all-ones
 *   - Single-bit vectors at polynomial tap positions
 *   - Overflow/carry propagation at lane boundaries
 *   - Maximum values (0xFF...FF)
 *
 * These tests complement the random/basis probes in test_commute.c
 *
 * Compile: cc -O2 -mpclmul -mssse3 -o test_ghash_edges test_ghash_edges.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* Scalar reference (same as test_commute.c) */
static uint64_t be64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | (uint64_t)p[7];
}

static void put_be64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)v;
}

static __m128i ghash_mul_spec_scalar(__m128i x, __m128i h) {
    const uint64_t R_hi = 0xE100000000000000ULL;
    uint8_t x_bytes[16], h_bytes[16];
    _mm_storeu_si128((__m128i*)x_bytes, x);
    _mm_storeu_si128((__m128i*)h_bytes, h);
    uint64_t x_hi = be64(x_bytes), x_lo = be64(x_bytes + 8);
    uint64_t h_hi = be64(h_bytes), h_lo = be64(h_bytes + 8);
    uint64_t z_h = 0, z_l = 0, v_h = h_hi, v_l = h_lo;

    for (int i = 0; i < 64; i++) {
        uint64_t bit = (x_hi >> (63 - i)) & 1;
        z_h ^= v_h & (-(uint64_t)bit);
        z_l ^= v_l & (-(uint64_t)bit);
        uint64_t lsb = v_l & 1;
        v_l = (v_l >> 1) | (v_h << 63);
        v_h = v_h >> 1;
        v_h ^= R_hi & (-(uint64_t)lsb);
    }
    for (int i = 0; i < 64; i++) {
        uint64_t bit = (x_lo >> (63 - i)) & 1;
        z_h ^= v_h & (-(uint64_t)bit);
        z_l ^= v_l & (-(uint64_t)bit);
        uint64_t lsb = v_l & 1;
        v_l = (v_l >> 1) | (v_h << 63);
        v_h = v_h >> 1;
        v_h ^= R_hi & (-(uint64_t)lsb);
    }

    uint8_t result[16];
    put_be64(result, z_h);
    put_be64(result + 8, z_l);
    return _mm_loadu_si128((const __m128i*)result);
}

/* Domain transformations */
static inline __m128i to_lepoly_128(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

static inline __m128i from_lepoly_128(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

extern __m128i ghash_mul_reflected(__m128i a_le, __m128i b_le);

/* Test infrastructure */
static void print_m128i(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    printf("  %-20s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int vectors_equal(__m128i a, __m128i b) {
    uint8_t a_bytes[16], b_bytes[16];
    _mm_storeu_si128((__m128i*)a_bytes, a);
    _mm_storeu_si128((__m128i*)b_bytes, b);
    return memcmp(a_bytes, b_bytes, 16) == 0;
}

static __m128i make_vector(const char* hex) {
    uint8_t buf[16];
    for (int i = 0; i < 16; i++) {
        sscanf(hex + i * 2, "%2hhx", &buf[i]);
    }
    return _mm_loadu_si128((const __m128i*)buf);
}

static int test_case(const char* name, __m128i X, __m128i H) {
    __m128i scalar = ghash_mul_spec_scalar(X, H);
    __m128i clmul = from_lepoly_128(
        ghash_mul_reflected(to_lepoly_128(X), to_lepoly_128(H))
    );

    if (vectors_equal(scalar, clmul)) {
        printf("✓ %s\n", name);
        return 0;
    } else {
        printf("✗ %s FAILED\n", name);
        print_m128i("X", X);
        print_m128i("H", H);
        print_m128i("Scalar", scalar);
        print_m128i("CLMUL", clmul);
        return 1;
    }
}

int main(void) {
    printf("==============================================\n");
    printf("  GHASH Edge Case Tests\n");
    printf("==============================================\n\n");

    int failures = 0;

    /* Identity tests */
    __m128i zero = _mm_setzero_si128();
    __m128i ones = make_vector("ffffffffffffffffffffffffffffffff");
    __m128i one = make_vector("00000000000000000000000000000001");
    __m128i H_random = make_vector("dc95c078a2408989ad48a21492842087");

    failures += test_case("X=0, H=random", zero, H_random);
    failures += test_case("X=random, H=0", H_random, zero);
    failures += test_case("X=0, H=0", zero, zero);
    failures += test_case("X=1, H=1", one, one);
    failures += test_case("X=1, H=random", one, H_random);
    failures += test_case("X=0xFF..FF, H=random", ones, H_random);
    failures += test_case("X=random, H=0xFF..FF", H_random, ones);

    /* Polynomial tap positions (x^7, x^2, x^1, x^0) */
    __m128i tap_7 = make_vector("00000000000000000000000000000080");   /* x^7 */
    __m128i tap_2 = make_vector("00000000000000000000000000000004");   /* x^2 */
    __m128i tap_1 = make_vector("00000000000000000000000000000002");   /* x^1 */

    failures += test_case("X=x^7, H=random", tap_7, H_random);
    failures += test_case("X=x^2, H=random", tap_2, H_random);
    failures += test_case("X=x^1, H=random", tap_1, H_random);

    /* Lane boundary tests (bit 31, 63, 95) */
    __m128i bit31 = make_vector("00000000000000000000000080000000");
    __m128i bit63 = make_vector("00000000000000008000000000000000");
    __m128i bit95 = make_vector("00000000800000000000000000000000");

    failures += test_case("X=bit[31], H=random", bit31, H_random);
    failures += test_case("X=bit[63], H=random", bit63, H_random);
    failures += test_case("X=bit[95], H=random", bit95, H_random);

    /* MSB and cross-lane carries */
    __m128i msb = make_vector("80000000000000000000000000000000");
    __m128i pattern1 = make_vector("0123456789abcdeffedcba9876543210");
    __m128i pattern2 = make_vector("aaaaaaaa55555555aaaaaaaa55555555");

    failures += test_case("X=MSB, H=random", msb, H_random);
    failures += test_case("X=pattern1, H=pattern2", pattern1, pattern2);
    failures += test_case("X=0xAA..55, H=0xAA..55", pattern2, pattern2);

    /* Known GCM test vector (from NIST) */
    __m128i H_nist = make_vector("dc95c078a2408989ad48a21492842087");
    __m128i C_nist = make_vector("cea7403d4d606b6e074ec5d3baf39d18");
    __m128i expected = make_vector("fd6ab7586e556dba06d69cfe6223b262");

    __m128i scalar = ghash_mul_spec_scalar(C_nist, H_nist);
    __m128i clmul = from_lepoly_128(
        ghash_mul_reflected(to_lepoly_128(C_nist), to_lepoly_128(H_nist))
    );

    if (vectors_equal(scalar, expected)) {
        printf("✓ Scalar produces known NIST result\n");
    } else {
        printf("✗ Scalar FAILED on NIST vector (ORACLE BROKEN!)\n");
        failures++;
    }

    if (vectors_equal(clmul, expected)) {
        printf("✓ CLMUL produces known NIST result\n");
    } else {
        printf("✗ CLMUL FAILED on NIST vector\n");
        print_m128i("Expected (NIST)", expected);
        print_m128i("Got (CLMUL)", clmul);
        failures++;
    }

    printf("\n==============================================\n");
    if (failures == 0) {
        printf("✓✓✓ ALL EDGE CASES PASSED ✓✓✓\n");
        printf("==============================================\n");
        return 0;
    } else {
        printf("✗ %d edge cases FAILED\n", failures);
        printf("==============================================\n");
        return 1;
    }
}
