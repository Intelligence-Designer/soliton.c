/*
 * Differential test: ghash_update_clmul8 vs ghash_update_clmul
 *
 * Compares 8-way batched GHASH against the ACTUAL single-block implementation
 * from ghash_clmul.c (not a test-local reference).
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* From core/ghash_clmul.c */
extern void ghash_update_clmul8(uint8_t* state, const uint8_t h_powers[8][16], const uint8_t* data, size_t len);
extern void ghash_update_clmul(uint8_t* state, const uint8_t* h_bytes, const uint8_t* data, size_t len);
extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);

static void dump_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    printf("=== Differential: 8-way vs Single-Block (ACTUAL functions) ===\n\n");

    /* H key from AES_K(0) with zero key */
    uint8_t h_spec[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
    };

    /* Precompute H powers */
    uint8_t h_powers[16][16];
    ghash_precompute_h_powers_clmul(h_powers, h_spec);

    printf("H (spec domain): ");
    dump_hex("", h_spec, 16);

    /* Test data: 8 blocks */
    uint8_t ciphertext[128];
    for (int i = 0; i < 128; i++) {
        ciphertext[i] = (uint8_t)(i * 17 + 42);
    }

    printf("\nCiphertext (8 blocks, 128 bytes):\n");
    for (int blk = 0; blk < 8; blk++) {
        printf("  Block %d: ", blk);
        dump_hex("", ciphertext + blk * 16, 16);
    }

    /* === Path 1: 8-way batched GHASH === */
    printf("\n8-way batched path:\n");
    printf("  Uses: ghash_update_clmul8() from ghash_clmul.c\n");
    printf("  Formula: Power-sum with H^8..H^1\n");

    uint8_t state_8way[16] = {0};
    ghash_update_clmul8(state_8way, h_powers, ciphertext, 128);

    printf("  Result: ");
    dump_hex("", state_8way, 16);

    /* === Path 2: Single-block GHASH (actual implementation) === */
    printf("\nSingle-block path:\n");
    printf("  Uses: ghash_update_clmul() from ghash_clmul.c\n");
    printf("  Formula: Horner's rule with H^1 (8 iterations)\n");

    uint8_t state_single[16] = {0};
    ghash_update_clmul(state_single, h_powers[0], ciphertext, 128);

    printf("  Result: ");
    dump_hex("", state_single, 16);

    /* === Compare === */
    printf("\n");
    if (memcmp(state_8way, state_single, 16) == 0) {
        printf("✓ PASS: 8-way matches single-block\n");
        printf("\nBoth implementations produce identical GHASH state.\n");
        printf("This validates that the power-sum formula equals Horner expansion.\n");
        return 0;
    } else {
        printf("✗ FAIL: Results differ\n\n");

        /* Byte-by-byte diff */
        printf("Byte-by-byte comparison:\n");
        for (int i = 0; i < 16; i++) {
            printf("  [%2d] 8way=%02x single=%02x %s\n",
                   i, state_8way[i], state_single[i],
                   (state_8way[i] == state_single[i]) ? "✓" : "✗");
        }

        printf("\nThis indicates a bug in ghash_update_clmul8 aggregation logic.\n");
        return 1;
    }
}
