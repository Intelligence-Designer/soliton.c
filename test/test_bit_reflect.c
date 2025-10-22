/*
 * test_bit_reflect.c - Diagnose PCLMULQDQ bit-ordering convention
 *
 * Test whether PCLMULQDQ needs:
 * 1. Byte-swap only (current hypothesis)
 * 2. Byte-swap + bit-reflection within each byte
 * 3. Full bit-reversal (bit-reflect + byte-swap = bit-reverse entire 128 bits)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* Print __m128i as hex and binary */
static void print_detailed(__m128i v) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, v);

    printf("  Hex: ");
    for (int i = 0; i < 16; i++) printf("%02x", bytes[i]);
    printf("\n");

    printf("  Binary (byte 0): ");
    for (int bit = 7; bit >= 0; bit--) {
        printf("%d", (bytes[0] >> bit) & 1);
    }
    printf("\n");
}

/* Byte-swap */
static __m128i byte_swap(__m128i x) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x, rev);
}

/* Bit-reflect within each byte */
static __m128i bit_reflect_bytes(__m128i x) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, x);

    for (int i = 0; i < 16; i++) {
        uint8_t b = bytes[i];
        uint8_t r = 0;
        for (int j = 0; j < 8; j++) {
            r |= ((b >> j) & 1) << (7 - j);
        }
        bytes[i] = r;
    }

    return _mm_loadu_si128((const __m128i*)bytes);
}

int main(void) {
    printf("=== PCLMULQDQ Bit-Ordering Diagnostic ===\n\n");

    /* Test case: multiply 0x01 (lowest bit) × 0x02 (second-lowest bit) */
    /* Expected in GF(2)[x]: x^0 × x^1 = x^1, so result should be 0x02 */

    __m128i a_spec = _mm_set_epi64x(0, 1);  // x^0 in spec domain
    __m128i b_spec = _mm_set_epi64x(0, 2);  // x^1 in spec domain

    printf("Test 1: 0x01 × 0x02 (should give 0x02)\n");
    printf("a_spec:\n");
    print_detailed(a_spec);
    printf("b_spec:\n");
    print_detailed(b_spec);

    /* Variant 1: Just byte-swap */
    printf("\n--- Variant 1: Byte-swap only ---\n");
    __m128i a1 = byte_swap(a_spec);
    __m128i b1 = byte_swap(b_spec);
    __m128i result1 = _mm_clmulepi64_si128(a1, b1, 0x00);
    result1 = byte_swap(result1);  // Swap back to spec domain
    printf("Result (swapped back):\n");
    print_detailed(result1);

    /* Variant 2: Byte-swap + bit-reflect */
    printf("\n--- Variant 2: Byte-swap + bit-reflect ---\n");
    __m128i a2 = byte_swap(a_spec);
    __m128i b2 = byte_swap(b_spec);
    a2 = bit_reflect_bytes(a2);
    b2 = bit_reflect_bytes(b2);
    __m128i result2 = _mm_clmulepi64_si128(a2, b2, 0x00);
    result2 = bit_reflect_bytes(result2);  // Reflect back
    result2 = byte_swap(result2);           // Swap back
    printf("Result (reflected+swapped back):\n");
    print_detailed(result2);

    /* Variant 3: Direct PCLMUL (no transforms) */
    printf("\n--- Variant 3: Direct PCLMUL (no transforms) ---\n");
    __m128i result3 = _mm_clmulepi64_si128(a_spec, b_spec, 0x00);
    printf("Result (direct):\n");
    print_detailed(result3);

    printf("\n");

    /* Test case 2: Single bit in different positions */
    printf("\n=== Test 2: Single bit positions ===\n");

    __m128i h_spec = _mm_set_epi64x(0xdc95c078a2408989ULL, 0xad48a21492842087ULL);
    printf("\nH (spec domain):\n");
    print_detailed(h_spec);

    /* Bit 0 set (LSB of spec domain = rightmost bit) */
    __m128i x0_spec = _mm_set_epi64x(0, 1);

    printf("\n--- X = 0x01 (bit 0) ---\n");

    /* Direct PCLMUL */
    __m128i r_direct = _mm_clmulepi64_si128(x0_spec, h_spec, 0x00);
    printf("Direct PCLMUL result:\n");
    print_detailed(r_direct);

    /* Byte-swap only */
    __m128i x0_bs = byte_swap(x0_spec);
    __m128i h_bs = byte_swap(h_spec);
    __m128i r_bs = _mm_clmulepi64_si128(x0_bs, h_bs, 0x00);
    r_bs = byte_swap(r_bs);
    printf("Byte-swap result:\n");
    print_detailed(r_bs);

    /* Byte-swap + bit-reflect */
    __m128i x0_br = byte_swap(x0_spec);
    __m128i h_br = byte_swap(h_spec);
    x0_br = bit_reflect_bytes(x0_br);
    h_br = bit_reflect_bytes(h_br);
    __m128i r_br = _mm_clmulepi64_si128(x0_br, h_br, 0x00);
    r_br = bit_reflect_bytes(r_br);
    r_br = byte_swap(r_br);
    printf("Byte-swap + bit-reflect result:\n");
    print_detailed(r_br);

    printf("\n=== Analysis ===\n");
    printf("If 'Direct PCLMUL' matches expected: PCLMUL uses spec domain natively\n");
    printf("If 'Byte-swap' matches expected: PCLMUL needs byte-swap only\n");
    printf("If 'Byte-swap + bit-reflect' matches expected: PCLMUL needs both\n");

    return 0;
}
