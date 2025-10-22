/*
 * test_suite.c - Comprehensive test suite for soliton.c
 * Tests all algorithms with official test vectors and edge cases
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "soliton.h"
#include "test_vectors.h"

/* Color codes for output */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

/* Test statistics */
static struct {
    int total;
    int passed;
    int failed;
    int skipped;
} test_stats = {0, 0, 0, 0};

/* Print hex string for debugging */
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    if (data == NULL || len == 0) {
        printf("(empty)");
    } else {
        for (size_t i = 0; i < len; i++) {
            printf("%02x", data[i]);
        }
    }
    printf("\n");
}

/* Compare two byte arrays */
static int compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    if (len == 0) return 0;
    if (a == NULL || b == NULL) return -1;
    return memcmp(a, b, len);
}

/* Test AES-GCM encryption */
static int test_aes_gcm_encrypt(const test_vector_t* vec) {
    uint8_t ctx_buffer[1024];
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;
    uint8_t* ciphertext = NULL;
    uint8_t tag[16];
    soliton_status status;
    int result = 0;

    /* Allocate ciphertext buffer */
    if (vec->plaintext_len > 0) {
        ciphertext = malloc(vec->plaintext_len);
        if (!ciphertext) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Memory allocation failed\n");
            return -1;
        }
    }

    /* Initialize */
    status = soliton_aesgcm_init(ctx, vec->key, vec->iv, vec->iv_len);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Init failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Process AAD */
    if (vec->aad_len > 0) {
        status = soliton_aesgcm_aad_update(ctx, vec->aad, vec->aad_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " AAD update failed: %d\n", status);
            result = -1;
            goto cleanup;
        }
    }

    /* Encrypt */
    if (vec->plaintext_len > 0) {
        status = soliton_aesgcm_encrypt_update(ctx, vec->plaintext, ciphertext, vec->plaintext_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Encrypt failed: %d\n", status);
            result = -1;
            goto cleanup;
        }

        /* Verify ciphertext */
        if (compare_bytes(ciphertext, vec->ciphertext, vec->plaintext_len) != 0) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Ciphertext mismatch\n");
            print_hex("      Expected", vec->ciphertext, vec->plaintext_len);
            print_hex("      Got     ", ciphertext, vec->plaintext_len);
            result = -1;
            goto cleanup;
        }
    }

    /* Finalize */
    status = soliton_aesgcm_encrypt_final(ctx, tag);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Final failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Verify tag */
    if (compare_bytes(tag, vec->tag, 16) != 0) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Tag mismatch\n");
        print_hex("      Expected", vec->tag, 16);
        print_hex("      Got     ", tag, 16);
        result = -1;
        goto cleanup;
    }

    printf("    " COLOR_GREEN "✓" COLOR_RESET " Encryption passed\n");

cleanup:
    if (ciphertext) free(ciphertext);
    soliton_aesgcm_context_wipe(ctx);
    return result;
}

/* Test AES-GCM decryption */
static int test_aes_gcm_decrypt(const test_vector_t* vec) {
    uint8_t ctx_buffer[1024];
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;
    uint8_t* plaintext = NULL;
    soliton_status status;
    int result = 0;

    /* Allocate plaintext buffer */
    if (vec->plaintext_len > 0) {
        plaintext = malloc(vec->plaintext_len);
        if (!plaintext) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Memory allocation failed\n");
            return -1;
        }
    }

    /* Initialize */
    status = soliton_aesgcm_init(ctx, vec->key, vec->iv, vec->iv_len);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Init failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Process AAD */
    if (vec->aad_len > 0) {
        status = soliton_aesgcm_aad_update(ctx, vec->aad, vec->aad_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " AAD update failed: %d\n", status);
            result = -1;
            goto cleanup;
        }
    }

    /* Decrypt */
    if (vec->plaintext_len > 0) {
        status = soliton_aesgcm_decrypt_update(ctx, vec->ciphertext, plaintext, vec->plaintext_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Decrypt failed: %d\n", status);
            result = -1;
            goto cleanup;
        }
    }

    /* Verify tag */
    status = soliton_aesgcm_decrypt_final(ctx, vec->tag);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Tag verification failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Verify plaintext */
    if (vec->plaintext_len > 0) {
        if (compare_bytes(plaintext, vec->plaintext, vec->plaintext_len) != 0) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Plaintext mismatch\n");
            print_hex("      Expected", vec->plaintext, vec->plaintext_len);
            print_hex("      Got     ", plaintext, vec->plaintext_len);
            result = -1;
            goto cleanup;
        }
    }

    printf("    " COLOR_GREEN "✓" COLOR_RESET " Decryption passed\n");

cleanup:
    if (plaintext) free(plaintext);
    soliton_aesgcm_context_wipe(ctx);
    return result;
}

/* Test ChaCha20-Poly1305 encryption */
static int test_chacha_encrypt(const test_vector_t* vec) {
    uint8_t ctx_buffer[1024];
    soliton_chacha_ctx* ctx = (soliton_chacha_ctx*)ctx_buffer;
    uint8_t* ciphertext = NULL;
    uint8_t tag[16];
    soliton_status status;
    int result = 0;

    /* Allocate ciphertext buffer */
    if (vec->plaintext_len > 0) {
        ciphertext = malloc(vec->plaintext_len);
        if (!ciphertext) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Memory allocation failed\n");
            return -1;
        }
    }

    /* Initialize */
    status = soliton_chacha_init(ctx, vec->key, vec->iv);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Init failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Process AAD */
    if (vec->aad_len > 0) {
        status = soliton_chacha_aad_update(ctx, vec->aad, vec->aad_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " AAD update failed: %d\n", status);
            result = -1;
            goto cleanup;
        }
    }

    /* Encrypt */
    if (vec->plaintext_len > 0) {
        status = soliton_chacha_encrypt_update(ctx, vec->plaintext, ciphertext, vec->plaintext_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Encrypt failed: %d\n", status);
            result = -1;
            goto cleanup;
        }

        /* Verify ciphertext */
        if (compare_bytes(ciphertext, vec->ciphertext, vec->plaintext_len) != 0) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Ciphertext mismatch\n");
            print_hex("      Expected", vec->ciphertext, vec->plaintext_len);
            print_hex("      Got     ", ciphertext, vec->plaintext_len);
            result = -1;
            goto cleanup;
        }
    }

    /* Finalize */
    status = soliton_chacha_encrypt_final(ctx, tag);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Final failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Verify tag */
    if (compare_bytes(tag, vec->tag, 16) != 0) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Tag mismatch\n");
        print_hex("      Expected", vec->tag, 16);
        print_hex("      Got     ", tag, 16);
        result = -1;
        goto cleanup;
    }

    printf("    " COLOR_GREEN "✓" COLOR_RESET " Encryption passed\n");

cleanup:
    if (ciphertext) free(ciphertext);
    soliton_chacha_context_wipe(ctx);
    return result;
}

/* Test ChaCha20-Poly1305 decryption */
static int test_chacha_decrypt(const test_vector_t* vec) {
    uint8_t ctx_buffer[1024];
    soliton_chacha_ctx* ctx = (soliton_chacha_ctx*)ctx_buffer;
    uint8_t* plaintext = NULL;
    soliton_status status;
    int result = 0;

    /* Allocate plaintext buffer */
    if (vec->plaintext_len > 0) {
        plaintext = malloc(vec->plaintext_len);
        if (!plaintext) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Memory allocation failed\n");
            return -1;
        }
    }

    /* Initialize */
    status = soliton_chacha_init(ctx, vec->key, vec->iv);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Init failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Process AAD */
    if (vec->aad_len > 0) {
        status = soliton_chacha_aad_update(ctx, vec->aad, vec->aad_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " AAD update failed: %d\n", status);
            result = -1;
            goto cleanup;
        }
    }

    /* Decrypt */
    if (vec->plaintext_len > 0) {
        status = soliton_chacha_decrypt_update(ctx, vec->ciphertext, plaintext, vec->plaintext_len);
        if (status != SOLITON_OK) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Decrypt failed: %d\n", status);
            result = -1;
            goto cleanup;
        }
    }

    /* Verify tag */
    status = soliton_chacha_decrypt_final(ctx, vec->tag);
    if (status != SOLITON_OK) {
        printf("    " COLOR_RED "✗" COLOR_RESET " Tag verification failed: %d\n", status);
        result = -1;
        goto cleanup;
    }

    /* Verify plaintext */
    if (vec->plaintext_len > 0) {
        if (compare_bytes(plaintext, vec->plaintext, vec->plaintext_len) != 0) {
            printf("    " COLOR_RED "✗" COLOR_RESET " Plaintext mismatch\n");
            print_hex("      Expected", vec->plaintext, vec->plaintext_len);
            print_hex("      Got     ", plaintext, vec->plaintext_len);
            result = -1;
            goto cleanup;
        }
    }

    printf("    " COLOR_GREEN "✓" COLOR_RESET " Decryption passed\n");

cleanup:
    if (plaintext) free(plaintext);
    soliton_chacha_context_wipe(ctx);
    return result;
}

/* Test constant-time properties */
static int test_constant_time(void) {
    printf("\n" COLOR_BLUE "Testing Constant-Time Properties:" COLOR_RESET "\n");
    printf("  Testing timing independence...\n");

    /* Test AES-GCM constant-time tag verification */
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t tag1[16] = {0};
    uint8_t tag2[16];
    uint8_t ctx_buffer[1024];
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    /* Generate two different tags */
    for (int i = 0; i < 16; i++) {
        tag2[i] = 0xFF;
    }

    /* Measure timing for correct tag */
    clock_t start1 = clock();
    for (int i = 0; i < 1000; i++) {
        soliton_aesgcm_init(ctx, key, iv, 12);
        soliton_aesgcm_decrypt_final(ctx, tag1);
    }
    clock_t end1 = clock();

    /* Measure timing for incorrect tag */
    clock_t start2 = clock();
    for (int i = 0; i < 1000; i++) {
        soliton_aesgcm_init(ctx, key, iv, 12);
        soliton_aesgcm_decrypt_final(ctx, tag2);
    }
    clock_t end2 = clock();

    double time1 = ((double)(end1 - start1)) / CLOCKS_PER_SEC;
    double time2 = ((double)(end2 - start2)) / CLOCKS_PER_SEC;
    double ratio = time1 / time2;

    printf("    Correct tag time:   %.6f s\n", time1);
    printf("    Incorrect tag time: %.6f s\n", time2);
    printf("    Timing ratio:       %.2f\n", ratio);

    /* Check if times are similar (within 20%) */
    if (ratio >= 0.8 && ratio <= 1.2) {
        printf("  " COLOR_GREEN "✓" COLOR_RESET " Constant-time verification passed\n");
        return 0;
    } else {
        printf("  " COLOR_RED "✗" COLOR_RESET " Timing difference detected\n");
        return -1;
    }
}

/* Test random round-trip */
static int test_random_roundtrip(void) {
    printf("\n" COLOR_BLUE "Testing Random Round-Trip:" COLOR_RESET "\n");

    uint8_t key[32];
    uint8_t iv[12];
    uint8_t aad[64];
    uint8_t plaintext[256];
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    uint8_t tag[16];
    uint8_t ctx_buffer[1024];
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    /* Generate random data */
    srand(time(NULL));
    for (int i = 0; i < 32; i++) key[i] = rand() & 0xFF;
    for (int i = 0; i < 12; i++) iv[i] = rand() & 0xFF;
    for (int i = 0; i < 64; i++) aad[i] = rand() & 0xFF;
    for (int i = 0; i < 256; i++) plaintext[i] = rand() & 0xFF;

    /* Encrypt */
    soliton_aesgcm_init(ctx, key, iv, 12);
    soliton_aesgcm_aad_update(ctx, aad, 64);
    soliton_aesgcm_encrypt_update(ctx, plaintext, ciphertext, 256);
    soliton_aesgcm_encrypt_final(ctx, tag);

    /* Decrypt */
    soliton_aesgcm_init(ctx, key, iv, 12);
    soliton_aesgcm_aad_update(ctx, aad, 64);
    soliton_aesgcm_decrypt_update(ctx, ciphertext, decrypted, 256);
    soliton_status status = soliton_aesgcm_decrypt_final(ctx, tag);

    if (status != SOLITON_OK) {
        printf("  " COLOR_RED "✗" COLOR_RESET " Tag verification failed\n");
        return -1;
    }

    if (memcmp(plaintext, decrypted, 256) != 0) {
        printf("  " COLOR_RED "✗" COLOR_RESET " Plaintext mismatch\n");
        return -1;
    }

    printf("  " COLOR_GREEN "✓" COLOR_RESET " Random round-trip passed\n");
    return 0;
}

/* Run all tests */
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("=====================================\n");
    printf("   soliton.c Comprehensive Test Suite\n");
    printf("=====================================\n");

    /* Show version and capabilities */
    printf("\n" COLOR_BLUE "Version:" COLOR_RESET " %s\n", soliton_version_string());

    soliton_caps caps;
    soliton_query_caps(&caps);
    printf(COLOR_BLUE "CPU Features:" COLOR_RESET " 0x%016lx\n", caps.bits);

    /* Test AES-GCM */
    printf("\n" COLOR_BLUE "Testing AES-256-GCM:" COLOR_RESET "\n");
    for (size_t i = 0; i < NUM_AES_GCM_VECTORS; i++) {
        const test_vector_t* vec = &aes_gcm_vectors[i];
        printf("  %s:\n", vec->name);

        test_stats.total += 2;

        if (test_aes_gcm_encrypt(vec) == 0) {
            test_stats.passed++;
        } else {
            test_stats.failed++;
        }

        if (test_aes_gcm_decrypt(vec) == 0) {
            test_stats.passed++;
        } else {
            test_stats.failed++;
        }
    }

    /* Test ChaCha20-Poly1305 */
    printf("\n" COLOR_BLUE "Testing ChaCha20-Poly1305:" COLOR_RESET "\n");
    for (size_t i = 0; i < NUM_CHACHA_VECTORS; i++) {
        const test_vector_t* vec = &chacha_vectors[i];
        printf("  %s:\n", vec->name);

        test_stats.total += 2;

        if (test_chacha_encrypt(vec) == 0) {
            test_stats.passed++;
        } else {
            test_stats.failed++;
        }

        if (test_chacha_decrypt(vec) == 0) {
            test_stats.passed++;
        } else {
            test_stats.failed++;
        }
    }

    /* Additional tests */
    test_stats.total++;
    if (test_constant_time() == 0) {
        test_stats.passed++;
    } else {
        test_stats.failed++;
    }

    test_stats.total++;
    if (test_random_roundtrip() == 0) {
        test_stats.passed++;
    } else {
        test_stats.failed++;
    }

    /* Print summary */
    printf("\n");
    printf("=====================================\n");
    printf("              Test Summary\n");
    printf("=====================================\n");
    printf("  Total:   %d\n", test_stats.total);
    printf("  " COLOR_GREEN "Passed:" COLOR_RESET "  %d\n", test_stats.passed);
    printf("  " COLOR_RED "Failed:" COLOR_RESET "  %d\n", test_stats.failed);
    if (test_stats.skipped > 0) {
        printf("  " COLOR_YELLOW "Skipped:" COLOR_RESET " %d\n", test_stats.skipped);
    }
    printf("=====================================\n");

    if (test_stats.failed == 0) {
        printf(COLOR_GREEN "All tests passed!\n" COLOR_RESET);
        return 0;
    } else {
        printf(COLOR_RED "Some tests failed!\n" COLOR_RESET);
        return 1;
    }
}