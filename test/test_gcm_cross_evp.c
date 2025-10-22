/*
 * test_gcm_cross_evp.c — Gate C: Cross-EVP Fuzzing vs OpenSSL
 *
 * PROOF OBLIGATION:
 *   For N random (key, iv, aad, pt) tuples, soliton.c and OpenSSL EVP
 *   must produce identical (ciphertext, tag) pairs.
 *
 * GATE C REQUIREMENTS:
 *   - 10,000 random test cases
 *   - Variable lengths: PT [0, 4096], AAD [0, 256]
 *   - 96-bit IVs (standard GCM)
 *   - AES-256-GCM mode
 *   - 100% match rate (10000/10000)
 *
 * Compile: cc -O2 -o test_gcm_cross_evp test_gcm_cross_evp.c -L. -lsoliton_core -lcrypto
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../include/soliton.h"

/* Test parameters */
#define NUM_TESTS 10000
#define MAX_PT_LEN 4096
#define MAX_AAD_LEN 256
#define IV_LEN 12  /* Standard 96-bit IV */

static int tests_passed = 0;
static int tests_failed = 0;

/* OpenSSL AES-256-GCM encrypt */
static int openssl_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag[16]
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, ct_len = 0;

    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Set IV length (96 bits) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Initialize key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Provide AAD */
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    /* Encrypt plaintext */
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        ct_len = len;
    }

    /* Finalize */
    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len += len;

    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

/* Soliton AES-256-GCM encrypt */
static void soliton_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag[16]
) {
    uint8_t ctx_buffer[2048];
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    soliton_aesgcm_init(ctx, key, iv, 12);

    if (aad_len > 0) {
        soliton_aesgcm_aad_update(ctx, aad, aad_len);
    }

    if (pt_len > 0) {
        soliton_aesgcm_encrypt_update(ctx, pt, ct, pt_len);
    }

    soliton_aesgcm_encrypt_final(ctx, tag);
}

/* Compare results */
static int run_test(int test_num, size_t pt_len, size_t aad_len) {
    uint8_t key[32], iv[12];
    uint8_t* pt = NULL;
    uint8_t* aad = NULL;
    uint8_t* ct_openssl = NULL;
    uint8_t* ct_soliton = NULL;
    uint8_t tag_openssl[16], tag_soliton[16];
    int result = 0;

    /* Allocate buffers */
    if (pt_len > 0) {
        pt = malloc(pt_len);
        ct_openssl = malloc(pt_len);
        ct_soliton = malloc(pt_len);
        if (!pt || !ct_openssl || !ct_soliton) goto cleanup;
    }

    if (aad_len > 0) {
        aad = malloc(aad_len);
        if (!aad) goto cleanup;
    }

    /* Generate random inputs */
    RAND_bytes(key, 32);
    RAND_bytes(iv, 12);
    if (pt_len > 0) RAND_bytes(pt, pt_len);
    if (aad_len > 0) RAND_bytes(aad, aad_len);

    /* Run OpenSSL */
    int ssl_result = openssl_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len,
                                          ct_openssl, tag_openssl);
    if (ssl_result < 0) {
        fprintf(stderr, "Test %d: OpenSSL failed\n", test_num);
        goto cleanup;
    }

    /* Run Soliton */
    soliton_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len,
                        ct_soliton, tag_soliton);

    /* Compare ciphertext */
    if (pt_len > 0 && memcmp(ct_openssl, ct_soliton, pt_len) != 0) {
        fprintf(stderr, "Test %d FAILED: CT mismatch (PT=%zu, AAD=%zu)\n",
                test_num, pt_len, aad_len);
        result = -1;
        goto cleanup;
    }

    /* Compare tag */
    if (memcmp(tag_openssl, tag_soliton, 16) != 0) {
        fprintf(stderr, "Test %d FAILED: Tag mismatch (PT=%zu, AAD=%zu)\n",
                test_num, pt_len, aad_len);
        fprintf(stderr, "  OpenSSL tag: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", tag_openssl[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  Soliton tag: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", tag_soliton[i]);
        fprintf(stderr, "\n");
        result = -1;
        goto cleanup;
    }

    result = 0;  /* Success */

cleanup:
    free(pt);
    free(aad);
    free(ct_openssl);
    free(ct_soliton);
    return result;
}

int main(void) {
    printf("==============================================\n");
    printf("  Gate C: Cross-EVP Fuzzing vs OpenSSL\n");
    printf("==============================================\n");
    printf("Running %d random test cases...\n\n", NUM_TESTS);

    /* Seed OpenSSL RNG */
    unsigned int seed = (unsigned int)time(NULL);
    RAND_seed(&seed, sizeof(seed));
    srand(seed);

    /* Progress reporting */
    int last_progress = 0;

    for (int i = 0; i < NUM_TESTS; i++) {
        /* Random lengths */
        size_t pt_len = rand() % (MAX_PT_LEN + 1);
        size_t aad_len = rand() % (MAX_AAD_LEN + 1);

        /* Run test */
        if (run_test(i + 1, pt_len, aad_len) == 0) {
            tests_passed++;
        } else {
            tests_failed++;
            /* Early exit on first failure for debugging */
            if (tests_failed >= 5) {
                printf("\n⚠️  Stopping after 5 failures for debugging\n");
                break;
            }
        }

        /* Progress indicator */
        int progress = (i * 100) / NUM_TESTS;
        if (progress >= last_progress + 10) {
            printf("  Progress: %d%% (%d/%d)\n", progress, i + 1, NUM_TESTS);
            last_progress = progress;
        }
    }

    printf("\n==============================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_passed + tests_failed);

    if (tests_failed == 0) {
        printf("✓✓✓ GATE C PASSED ✓✓✓\n");
        printf("100%% match with OpenSSL EVP\n");
        printf("==============================================\n");
        return 0;
    } else {
        printf("✗ GATE C FAILED: %d tests failed\n", tests_failed);
        printf("==============================================\n");
        return 1;
    }
}
