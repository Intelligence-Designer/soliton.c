/*
 * test_mul_product.c - Gate P0: Product Equivalence Harness
 *
 * CRITICAL: Test 256-bit CLMUL product BEFORE reduction
 * This is the "product-first" gate that prevents reducer safari.
 *
 * Session 5 breakthrough: The bug was in the multiply, not the reducer.
 * This test catches multiply bugs by comparing raw 256-bit products.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* Helper to print __m128i as hex */
static void print_m128i(const char* label, __m128i v) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, v);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

/* Byte-swap: Spec (big-endian) <-> Kernel (little-endian)
 * This is the ONLY transformation needed for PCLMULQDQ (Linux kernel approach)
 * NO bit-reflection within bytes!
 */
static __m128i byte_swap(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

/* Schoolbook 4-partial CLMUL (kernel domain input/output) */
static void clmul_product_256(__m128i a, __m128i b, __m128i* lo_out, __m128i* hi_out) {
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00); // a_lo × b_lo
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01); // a_lo × b_hi
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10); // a_hi × b_lo
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11); // a_hi × b_hi

    __m128i cross = _mm_xor_si128(p01, p10);
    *lo_out = _mm_xor_si128(p00, _mm_slli_si128(cross, 8)); // << 64 bits
    *hi_out = _mm_xor_si128(p11, _mm_srli_si128(cross, 8)); // >> 64 bits
}

/* Scalar 256-bit carry-less multiply in spec domain (big-endian) */
static void scalar_product_256(__m128i a_spec, __m128i b_spec,
                                __m128i* lo_spec, __m128i* hi_spec) {
    /* Extract bytes */
    uint8_t a_bytes[16], b_bytes[16];
    _mm_storeu_si128((__m128i*)a_bytes, a_spec);
    _mm_storeu_si128((__m128i*)b_bytes, b_spec);

    /* 256-bit result in big-endian byte order */
    uint8_t result[32] = {0};

    /* Polynomial multiply in GF(2)[x]
     * Big-endian convention: byte i bit j maps to degree (15-i)*8 + (7-j)
     * Example: byte 0 bit 7 = deg 127, byte 15 bit 0 = deg 0
     */
    for (int a_byte = 0; a_byte < 16; a_byte++) {
        if (a_bytes[a_byte] == 0) continue;  /* Skip zero bytes */

        for (int a_bit = 0; a_bit < 8; a_bit++) {
            if (!((a_bytes[a_byte] >> a_bit) & 1)) continue;

            /* Degree of this bit in a */
            int a_deg = (15 - a_byte) * 8 + a_bit;

            /* XOR b << a_deg into result */
            for (int b_byte = 0; b_byte < 16; b_byte++) {
                if (b_bytes[b_byte] == 0) continue;

                for (int b_bit = 0; b_bit < 8; b_bit++) {
                    if (!((b_bytes[b_byte] >> b_bit) & 1)) continue;

                    /* Degree of this bit in b */
                    int b_deg = (15 - b_byte) * 8 + b_bit;
                    int res_deg = a_deg + b_deg;

                    /* Map degree to byte and bit in 256-bit result (big-endian)
                     * Degree d → byte (31 - d/8), bit (d % 8)
                     */
                    int res_byte = 31 - (res_deg / 8);
                    int res_bit = res_deg % 8;
                    result[res_byte] ^= (1 << res_bit);
                }
            }
        }
    }

    /* Split into high and low 128-bit halves (big-endian byte order) */
    *hi_spec = _mm_loadu_si128((const __m128i*)(result));      /* bytes 0-15 = high 128 bits */
    *lo_spec = _mm_loadu_si128((const __m128i*)(result + 16)); /* bytes 16-31 = low 128 bits */
}

/* Gate P0: Test CLMUL product against scalar spec multiply */
static int test_product_equivalence(const char* name, __m128i a_spec, __m128i b_spec) {
    /* CLMUL path: byte-swap to kernel domain (Linux kernel approach) */
    __m128i a_kern = byte_swap(a_spec);
    __m128i b_kern = byte_swap(b_spec);

    __m128i clmul_lo_kern, clmul_hi_kern;
    clmul_product_256(a_kern, b_kern, &clmul_lo_kern, &clmul_hi_kern);

    /* Scalar path: multiply in spec domain */
    __m128i scalar_lo_spec, scalar_hi_spec;
    scalar_product_256(a_spec, b_spec, &scalar_lo_spec, &scalar_hi_spec);

    /* Transform scalar results to kernel domain for comparison */
    __m128i scalar_lo_kern = byte_swap(scalar_lo_spec);
    __m128i scalar_hi_kern = byte_swap(scalar_hi_spec);

    /* Compare 256-bit products in kernel domain */
    __m128i diff_lo = _mm_xor_si128(clmul_lo_kern, scalar_lo_kern);
    __m128i diff_hi = _mm_xor_si128(clmul_hi_kern, scalar_hi_kern);

    int lo_match = _mm_test_all_zeros(diff_lo, diff_lo);
    int hi_match = _mm_test_all_zeros(diff_hi, diff_hi);

    if (!lo_match || !hi_match) {
        printf("FAIL: %s\n", name);
        print_m128i("  a_spec", a_spec);
        print_m128i("  b_spec", b_spec);
        print_m128i("  CLMUL lo (spec)", byte_swap(clmul_lo_kern));
        print_m128i("  Scalar lo (spec)", scalar_lo_spec);
        print_m128i("  CLMUL hi (spec)", byte_swap(clmul_hi_kern));
        print_m128i("  Scalar hi (spec)", scalar_hi_spec);
        return 0;
    }

    return 1;
}

/* Helper to create __m128i from hex string (big-endian) */
static __m128i hex_to_m128i(const char* hex) {
    uint8_t bytes[16];
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        sscanf(hex + i*2, "%2x", &byte);
        bytes[i] = (uint8_t)byte;
    }
    return _mm_loadu_si128((const __m128i*)bytes);
}

int main(void) {
    printf("=== Gate P0: 256-bit Product Equivalence Test ===\n\n");

    int passed = 0;
    int total = 0;

    /* Unit vectors - force every tap path */
    printf("Testing unit vectors (tap path coverage)...\n");

    /* Zero test */
    {
        __m128i a = hex_to_m128i("00000000000000000000000000000000");
        __m128i h = hex_to_m128i("dc95c078a2408989ad48a21492842087");
        total++;
        if (test_product_equivalence("Unit: 0 × H", a, h)) passed++;
    }

    /* Single bit positions (spec domain: byte 0 = MSB) */
    const char* bit_tests[][3] = {
        {"00000000000000000000000000000001", "dc95c078a2408989ad48a21492842087", "bit 0 (LSB)"},
        {"00000000000000000000000000000080", "dc95c078a2408989ad48a21492842087", "bit 7"},
        {"00000000000000008000000000000000", "dc95c078a2408989ad48a21492842087", "bit 63"},
        {"80000000000000000000000000000000", "dc95c078a2408989ad48a21492842087", "bit 127 (MSB)"},
        {"01000000000000000000000000000000", "dc95c078a2408989ad48a21492842087", "bit 120"},
    };

    for (int i = 0; i < 5; i++) {
        __m128i a = hex_to_m128i(bit_tests[i][0]);
        __m128i h = hex_to_m128i(bit_tests[i][1]);
        char name[64];
        snprintf(name, sizeof(name), "Unit: %s", bit_tests[i][2]);
        total++;
        if (test_product_equivalence(name, a, h)) passed++;
    }

    /* Random vectors - 256 random pairs */
    printf("\nTesting 256 random (X,H) pairs...\n");

    uint64_t seed = 0x123456789ABCDEF0ULL;
    for (int i = 0; i < 256; i++) {
        /* Generate random 128-bit values */
        uint64_t rnd[4];
        for (int j = 0; j < 4; j++) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            rnd[j] = seed;
        }

        /* Create in big-endian (spec domain) */
        uint8_t a_bytes[16], b_bytes[16];
        for (int j = 0; j < 8; j++) {
            a_bytes[j] = (rnd[0] >> ((7-j) * 8)) & 0xFF;
            a_bytes[8+j] = (rnd[1] >> ((7-j) * 8)) & 0xFF;
            b_bytes[j] = (rnd[2] >> ((7-j) * 8)) & 0xFF;
            b_bytes[8+j] = (rnd[3] >> ((7-j) * 8)) & 0xFF;
        }

        __m128i a = _mm_loadu_si128((const __m128i*)a_bytes);
        __m128i b = _mm_loadu_si128((const __m128i*)b_bytes);

        char name[64];
        snprintf(name, sizeof(name), "Random %d", i);

        total++;
        if (test_product_equivalence(name, a, b)) {
            passed++;
        } else if (passed < total - 1) {
            /* Stop after first 3 failures to avoid spam */
            if (total - passed > 3) break;
        }

        if ((i + 1) % 64 == 0) {
            printf("  Progress: %d/%d (passed: %d)\n", i + 1, 256, passed - 6);
        }
    }

    printf("\n=== Gate P0 Results ===\n");
    printf("Passed: %d/%d\n", passed, total);

    if (passed == total) {
        printf("✓ GATE P0 PASSED: 256-bit product is correct\n");
        return 0;
    } else {
        printf("✗ GATE P0 FAILED: CLMUL product does not match scalar\n");
        printf("\nFirst failure shows the bug in the multiply layer.\n");
        return 1;
    }
}
