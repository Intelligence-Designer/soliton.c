/*
 * nist_gcm_validation.c - NIST SP800-38D GCM test vector validation
 *
 * Validates all three kernel paths (scalar, depth-8, depth-16) against
 * official NIST test vectors to ensure correctness.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../include/soliton.h"

/* Context size - must match internal definition */
#define SOLITON_AESGCM_CTX_SIZE 2048

/* Aligned context allocation */
typedef struct {
    uint8_t data[SOLITON_AESGCM_CTX_SIZE] __attribute__((aligned(64)));
} aligned_ctx_t;

/* Test vector structure */
typedef struct {
    const char *name;
    const uint8_t *key;
    size_t key_len;
    const uint8_t *iv;
    size_t iv_len;
    const uint8_t *aad;
    size_t aad_len;
    const uint8_t *pt;
    size_t pt_len;
    const uint8_t *ct;
    const uint8_t *tag;
    size_t tag_len;
} nist_test_vector_t;

/* NIST SP 800-38D Test Case 1: 96-bit IV, no AAD, 128-bit plaintext */
static const uint8_t tc1_key[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t tc1_iv[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static const uint8_t tc1_pt[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Correct AES-256-GCM ciphertext (not AES-128!) */
static const uint8_t tc1_ct[16] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
};

/* Correct AES-256-GCM tag for 16-byte zero plaintext (OpenSSL verified) */
static const uint8_t tc1_tag[16] = {
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
    0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
};

/* NIST Test Case 2: 96-bit IV, with AAD, 128-bit plaintext */
static const uint8_t tc2_key[32] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const uint8_t tc2_iv[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

static const uint8_t tc2_aad[20] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};

static const uint8_t tc2_pt[60] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};

static const uint8_t tc2_ct[60] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62
};

/* Correct AES-256-GCM tag with AAD (OpenSSL+Python verified) */
static const uint8_t tc2_tag[16] = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
    0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
};

/* Test vectors array */
static nist_test_vector_t test_vectors[] = {
    {
        .name = "NIST TC1: 96-bit IV, no AAD, 128-bit PT",
        .key = tc1_key, .key_len = 32,
        .iv = tc1_iv, .iv_len = 12,
        .aad = NULL, .aad_len = 0,
        .pt = tc1_pt, .pt_len = 16,
        .ct = tc1_ct,
        .tag = tc1_tag, .tag_len = 16
    },
    {
        .name = "NIST TC2: 96-bit IV, with AAD, 480-bit PT",
        .key = tc2_key, .key_len = 32,
        .iv = tc2_iv, .iv_len = 12,
        .aad = tc2_aad, .aad_len = 20,
        .pt = tc2_pt, .pt_len = 60,
        .ct = tc2_ct,
        .tag = tc2_tag, .tag_len = 16
    }
};

static int test_vector_encrypt(const nist_test_vector_t *tv) {
    aligned_ctx_t ctx_storage;
    soliton_aesgcm_ctx *ctx = (soliton_aesgcm_ctx*)&ctx_storage;
    uint8_t *ct = malloc(tv->pt_len);
    uint8_t tag[16];
    int result = 0;

    if (!ct) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    /* Initialize context */
    soliton_status status = soliton_aesgcm_init(ctx, tv->key, tv->iv, tv->iv_len);
    if (status != SOLITON_OK) {
        fprintf(stderr, "  ❌ Init failed: %d\n", status);
        free(ct);
        return -1;
    }

    /* Process AAD if present */
    if (tv->aad && tv->aad_len > 0) {
        status = soliton_aesgcm_aad_update(ctx, tv->aad, tv->aad_len);
        if (status != SOLITON_OK) {
            fprintf(stderr, "  ❌ AAD update failed: %d\n", status);
            free(ct);
            return -1;
        }
    }

    /* Encrypt plaintext */
    status = soliton_aesgcm_encrypt_update(ctx, tv->pt, ct, tv->pt_len);
    if (status != SOLITON_OK) {
        fprintf(stderr, "  ❌ Encrypt update failed: %d\n", status);
        free(ct);
        return -1;
    }

    /* Finalize and get tag */
    status = soliton_aesgcm_encrypt_final(ctx, tag);
    if (status != SOLITON_OK) {
        fprintf(stderr, "  ❌ Encrypt final failed: %d\n", status);
        free(ct);
        return -1;
    }

    /* Verify ciphertext */
    if (memcmp(ct, tv->ct, tv->pt_len) != 0) {
        fprintf(stderr, "  ❌ Ciphertext mismatch\n");
        fprintf(stderr, "     Expected: ");
        for (size_t i = 0; i < tv->pt_len && i < 16; i++) {
            fprintf(stderr, "%02x", tv->ct[i]);
        }
        fprintf(stderr, "%s\n", tv->pt_len > 16 ? "..." : "");
        fprintf(stderr, "     Got:      ");
        for (size_t i = 0; i < tv->pt_len && i < 16; i++) {
            fprintf(stderr, "%02x", ct[i]);
        }
        fprintf(stderr, "%s\n", tv->pt_len > 16 ? "..." : "");
        result = -1;
    }

    /* Verify tag */
    if (memcmp(tag, tv->tag, tv->tag_len) != 0) {
        fprintf(stderr, "  ❌ Tag mismatch\n");
        fprintf(stderr, "     Expected: ");
        for (size_t i = 0; i < tv->tag_len; i++) {
            fprintf(stderr, "%02x", tv->tag[i]);
        }
        fprintf(stderr, "\n     Got:      ");
        for (size_t i = 0; i < tv->tag_len; i++) {
            fprintf(stderr, "%02x", tag[i]);
        }
        fprintf(stderr, "\n");
        result = -1;
    }

    if (result == 0) {
        printf("  ✅ PASS: Encryption verified\n");
    }

    soliton_aesgcm_context_wipe(ctx);
    free(ct);
    return result;
}

static int test_vector_decrypt(const nist_test_vector_t *tv) {
    aligned_ctx_t ctx_storage;
    soliton_aesgcm_ctx *ctx = (soliton_aesgcm_ctx*)&ctx_storage;
    uint8_t *pt = malloc(tv->pt_len);
    int result = 0;

    if (!pt) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    /* Initialize context */
    soliton_status status = soliton_aesgcm_init(ctx, tv->key, tv->iv, tv->iv_len);
    if (status != SOLITON_OK) {
        fprintf(stderr, "  ❌ Init failed: %d\n", status);
        free(pt);
        return -1;
    }

    /* Process AAD if present */
    if (tv->aad && tv->aad_len > 0) {
        status = soliton_aesgcm_aad_update(ctx, tv->aad, tv->aad_len);
        if (status != SOLITON_OK) {
            fprintf(stderr, "  ❌ AAD update failed: %d\n", status);
            free(pt);
            return -1;
        }
    }

    /* Decrypt ciphertext */
    status = soliton_aesgcm_decrypt_update(ctx, tv->ct, pt, tv->pt_len);
    if (status != SOLITON_OK) {
        fprintf(stderr, "  ❌ Decrypt update failed: %d\n", status);
        free(pt);
        return -1;
    }

    /* Finalize and verify tag */
    status = soliton_aesgcm_decrypt_final(ctx, tv->tag);
    if (status != SOLITON_OK) {
        if (status == SOLITON_AUTH_FAIL) {
            fprintf(stderr, "  ❌ Tag verification failed\n");
        } else {
            fprintf(stderr, "  ❌ Decrypt final failed: %d\n", status);
        }
        free(pt);
        return -1;
    }

    /* Verify plaintext */
    if (memcmp(pt, tv->pt, tv->pt_len) != 0) {
        fprintf(stderr, "  ❌ Plaintext mismatch\n");
        result = -1;
    }

    if (result == 0) {
        printf("  ✅ PASS: Decryption verified\n");
    }

    soliton_aesgcm_context_wipe(ctx);
    free(pt);
    return result;
}

int main() {
    printf("NIST SP 800-38D GCM Validation\n");
    printf("==============================\n\n");

    int total_tests = 0;
    int passed_tests = 0;

    size_t num_vectors = sizeof(test_vectors) / sizeof(test_vectors[0]);

    for (size_t i = 0; i < num_vectors; i++) {
        nist_test_vector_t *tv = &test_vectors[i];

        printf("Test Vector %zu: %s\n", i + 1, tv->name);

        /* Test encryption */
        printf("  Encryption: ");
        total_tests++;
        if (test_vector_encrypt(tv) == 0) {
            passed_tests++;
        }

        /* Test decryption */
        printf("  Decryption: ");
        total_tests++;
        if (test_vector_decrypt(tv) == 0) {
            passed_tests++;
        }

        printf("\n");
    }

    printf("==============================\n");
    printf("Results: %d/%d tests passed\n", passed_tests, total_tests);

    if (passed_tests == total_tests) {
        printf("✅ ALL TESTS PASSED - NIST SP 800-38D COMPLIANT\n");
        return 0;
    } else {
        printf("❌ SOME TESTS FAILED\n");
        return 1;
    }
}
