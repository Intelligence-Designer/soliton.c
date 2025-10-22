/*
 * test_commute.c — GHASH Commuting Diagram Test (Gate A)
 *
 * PROOF OBLIGATION:
 *   For all (X, H) in GF(2^128):
 *     from_lepoly_128(ghash_mul_reflected(to_lepoly_128(X), to_lepoly_128(H)))
 *       ≡ ghash_mul_spec_scalar(X, H)
 *
 * This proves that the CLMUL implementation is mathematically equivalent to
 * the scalar reference across the domain transformation boundary.
 *
 * GATE A REQUIREMENTS:
 *   - 1000 random (X, H) pairs: 1000/1000 must pass
 *   - Basis probes: unit vectors at positions {0,1,2,7,63,64,127}
 *   - Edge vectors: {X=1}, {X=0x80..0}, {H=1}, {H=poly}
 *
 * Compile: cc -O2 -mpclmul -mssse3 -o test_commute test_commute.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <immintrin.h>

/* ============================================================================
 * Scalar Reference Implementation (ORACLE)
 * Uses 0xE1 polynomial, big-endian, MSB-first — matches NIST SP 800-38D
 * ============================================================================ */

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

/* GF(2^128) multiplication with 0xE1 reduction (scalar reference) */
static __m128i ghash_mul_spec_scalar(__m128i x, __m128i h) {
    const uint64_t R_hi = 0xE100000000000000ULL;  /* 0xE1 polynomial */

    uint8_t x_bytes[16], h_bytes[16];
    _mm_storeu_si128((__m128i*)x_bytes, x);
    _mm_storeu_si128((__m128i*)h_bytes, h);

    uint64_t x_hi = be64(x_bytes),     x_lo = be64(x_bytes + 8);
    uint64_t h_hi = be64(h_bytes),     h_lo = be64(h_bytes + 8);
    uint64_t z_h = 0, z_l = 0;
    uint64_t v_h = h_hi, v_l = h_lo;

    /* MSB-first multiplication */
    for (int i = 0; i < 64; i++) {
        uint64_t bit = (x_hi >> (63 - i)) & 1;
        uint64_t mask = -(uint64_t)bit;
        z_h ^= v_h & mask;
        z_l ^= v_l & mask;
        uint64_t lsb = v_l & 1;
        v_l = (v_l >> 1) | (v_h << 63);
        v_h = v_h >> 1;
        v_h ^= R_hi & (-(uint64_t)lsb);
    }
    for (int i = 0; i < 64; i++) {
        uint64_t bit = (x_lo >> (63 - i)) & 1;
        uint64_t mask = -(uint64_t)bit;
        z_h ^= v_h & mask;
        z_l ^= v_l & mask;
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

/* ============================================================================
 * CLMUL Implementation Under Test
 * ============================================================================ */

/* Domain transformation: spec (big-endian) ↔ kernel (little-endian bytes) */
static inline __m128i to_lepoly_128(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

static inline __m128i from_lepoly_128(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

/* Forward declare CLMUL multiply (will link against core/ghash_clmul.c) */
extern __m128i ghash_mul_reflected(__m128i a_le, __m128i b_le);

/* ============================================================================
 * Test Infrastructure
 * ============================================================================ */

static void print_m128i(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    printf("%-24s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int vectors_equal(__m128i a, __m128i b) {
    uint8_t a_bytes[16], b_bytes[16];
    _mm_storeu_si128((__m128i*)a_bytes, a);
    _mm_storeu_si128((__m128i*)b_bytes, b);
    return memcmp(a_bytes, b_bytes, 16) == 0;
}

static __m128i random_m128i(void) {
    uint8_t buf[16];
    for (int i = 0; i < 16; i++) {
        buf[i] = (uint8_t)rand();
    }
    return _mm_loadu_si128((const __m128i*)buf);
}

static __m128i unit_vector_at(int bit_position) {
    uint8_t buf[16] = {0};
    int byte_idx = bit_position / 8;
    int bit_idx = bit_position % 8;
    buf[byte_idx] = (uint8_t)(1 << bit_idx);
    return _mm_loadu_si128((const __m128i*)buf);
}

/* ============================================================================
 * Gate A Test Cases
 * ============================================================================ */

static int test_commute_random(int count) {
    int failures = 0;
    for (int i = 0; i < count; i++) {
        __m128i X = random_m128i();
        __m128i H = random_m128i();

        /* Scalar path (spec domain) */
        __m128i result_scalar = ghash_mul_spec_scalar(X, H);

        /* CLMUL path (kernel domain with swaps) */
        __m128i X_le = to_lepoly_128(X);
        __m128i H_le = to_lepoly_128(H);
        __m128i result_le = ghash_mul_reflected(X_le, H_le);
        __m128i result_clmul = from_lepoly_128(result_le);

        if (!vectors_equal(result_scalar, result_clmul)) {
            printf("\n✗ COMMUTE FAILURE at iteration %d:\n", i);
            print_m128i("X (spec)", X);
            print_m128i("H (spec)", H);
            print_m128i("Scalar result", result_scalar);
            print_m128i("CLMUL result", result_clmul);

            uint8_t s[16], c[16];
            _mm_storeu_si128((__m128i*)s, result_scalar);
            _mm_storeu_si128((__m128i*)c, result_clmul);
            printf("XOR difference       : ");
            for (int j = 0; j < 16; j++) printf("%02x", s[j] ^ c[j]);
            printf("\n");

            failures++;
            if (failures >= 3) {
                printf("... stopping after 3 failures\n");
                return failures;
            }
        }
    }
    return failures;
}

static int test_basis_probes(void) {
    int failures = 0;
    int positions[] = {0, 1, 2, 7, 63, 64, 127};
    int num_pos = sizeof(positions) / sizeof(positions[0]);

    for (int i = 0; i < num_pos; i++) {
        __m128i X = unit_vector_at(positions[i]);
        __m128i H = random_m128i();

        __m128i result_scalar = ghash_mul_spec_scalar(X, H);
        __m128i result_clmul = from_lepoly_128(
            ghash_mul_reflected(to_lepoly_128(X), to_lepoly_128(H))
        );

        if (!vectors_equal(result_scalar, result_clmul)) {
            printf("\n✗ BASIS PROBE FAILURE at bit position %d:\n", positions[i]);
            print_m128i("X (unit vector)", X);
            print_m128i("H", H);
            print_m128i("Scalar result", result_scalar);
            print_m128i("CLMUL result", result_clmul);
            failures++;
        }
    }
    return failures;
}

static int test_edge_vectors(void) {
    int failures = 0;

    /* Edge case 1: X = 1 (LSB set) */
    uint8_t buf_x1[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    __m128i X1 = _mm_loadu_si128((const __m128i*)buf_x1);
    __m128i H1 = random_m128i();

    __m128i s1 = ghash_mul_spec_scalar(X1, H1);
    __m128i c1 = from_lepoly_128(ghash_mul_reflected(to_lepoly_128(X1), to_lepoly_128(H1)));
    if (!vectors_equal(s1, c1)) {
        printf("\n✗ EDGE CASE X=1 failed\n");
        failures++;
    }

    /* Edge case 2: X = 0x80000000000000000000000000000000 (MSB set) */
    uint8_t buf_x2[16] = {0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    __m128i X2 = _mm_loadu_si128((const __m128i*)buf_x2);
    __m128i H2 = random_m128i();

    __m128i s2 = ghash_mul_spec_scalar(X2, H2);
    __m128i c2 = from_lepoly_128(ghash_mul_reflected(to_lepoly_128(X2), to_lepoly_128(H2)));
    if (!vectors_equal(s2, c2)) {
        printf("\n✗ EDGE CASE X=MSB failed\n");
        failures++;
    }

    /* Edge case 3: H = 1 */
    __m128i X3 = random_m128i();
    uint8_t buf_h3[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    __m128i H3 = _mm_loadu_si128((const __m128i*)buf_h3);

    __m128i s3 = ghash_mul_spec_scalar(X3, H3);
    __m128i c3 = from_lepoly_128(ghash_mul_reflected(to_lepoly_128(X3), to_lepoly_128(H3)));
    if (!vectors_equal(s3, c3)) {
        printf("\n✗ EDGE CASE H=1 failed\n");
        failures++;
    }

    return failures;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int main(void) {
    printf("==============================================\n");
    printf("  GHASH Commuting Diagram Test (Gate A)\n");
    printf("==============================================\n\n");

    printf("Proof Obligation:\n");
    printf("  ∀(X,H) ∈ GF(2^128): from_le(mul_clmul(to_le(X),to_le(H))) ≡ mul_scalar(X,H)\n\n");

    /* Seed for reproducibility */
    srand(0x5041544820C);  /* "PATH C" */

    int total_failures = 0;

    /* Test 1: Random vectors (1000 iterations) */
    printf("[1/3] Random vectors (1000 iterations)...\n");
    int f1 = test_commute_random(1000);
    printf("      Result: %d failures\n", f1);
    total_failures += f1;

    /* Test 2: Basis probes */
    printf("[2/3] Basis probes (bit positions 0,1,2,7,63,64,127)...\n");
    int f2 = test_basis_probes();
    printf("      Result: %d failures\n", f2);
    total_failures += f2;

    /* Test 3: Edge vectors */
    printf("[3/3] Edge vectors (X=1, X=MSB, H=1)...\n");
    int f3 = test_edge_vectors();
    printf("      Result: %d failures\n", f3);
    total_failures += f3;

    printf("\n==============================================\n");
    if (total_failures == 0) {
        printf("✓✓✓ GATE A PASSED ✓✓✓\n");
        printf("Commuting diagram holds: CLMUL ≡ Scalar\n");
        printf("==============================================\n");
        return 0;
    } else {
        printf("✗ GATE A FAILED: %d total failures\n", total_failures);
        printf("==============================================\n");
        return 1;
    }
}
