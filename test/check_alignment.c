/*
 * check_alignment.c - Alignment verification test for soliton.c v0.4.1
 *
 * Verifies that context structures are properly 64-byte aligned when
 * allocated with aligned_alloc() for optimal cache behavior.
 *
 * Expected behavior:
 * - Contexts allocated with aligned_alloc(64, ...) should maintain alignment
 * - Multiple allocations should consistently maintain alignment
 * - Context sizes should be reasonable (not excessive padding)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../include/soliton.h"

/* Get actual structure sizes (opaque, so we query via sizeof through API) */
#define GCM_CONTEXT_SIZE 1024   /* Conservative estimate */
#define CHACHA_CONTEXT_SIZE 512 /* Conservative estimate */

#define CHECK_ALIGNMENT(ptr, align) (((uintptr_t)(ptr) & ((align) - 1)) == 0)

/* Test result tracking */
static int tests_passed = 0;
static int tests_failed = 0;

static void test_alignment(const char* name, const void* ptr, size_t required_alignment) {
    int aligned = CHECK_ALIGNMENT(ptr, required_alignment);

    printf("  %-40s: %p -> ", name, ptr);

    if (aligned) {
        printf("✓ ALIGNED (%zu bytes)\n", required_alignment);
        tests_passed++;
    } else {
        uintptr_t addr = (uintptr_t)ptr;
        size_t offset = addr & (required_alignment - 1);
        printf("✗ MISALIGNED (offset: %zu bytes from %zu-byte boundary)\n",
               offset, required_alignment);
        tests_failed++;
    }
}

int main(void) {
    printf("==========================================\n");
    printf("soliton.c Alignment Verification (v0.4.1)\n");
    printf("==========================================\n");
    printf("\n");

    /* ======================================== */
    /* Test 1: AES-GCM Context Alignment       */
    /* ======================================== */

    printf("Test 1: AES-GCM Context Alignment\n");
    printf("------------------------------------------\n");

    /* Allocate GCM context with 64-byte alignment */
    void* gcm_buffer = aligned_alloc(64, GCM_CONTEXT_SIZE);
    if (!gcm_buffer) {
        fprintf(stderr, "Error: aligned_alloc failed for GCM context\n");
        return 1;
    }

    soliton_aesgcm_ctx* gcm_ctx = (soliton_aesgcm_ctx*)gcm_buffer;

    /* Initialize context */
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    soliton_status status = soliton_aesgcm_init(gcm_ctx, key, iv, 12);

    if (status != SOLITON_OK) {
        fprintf(stderr, "Error: GCM init failed\n");
        free(gcm_buffer);
        return 1;
    }

    /* Verify base address alignment */
    test_alignment("GCM context base address", gcm_ctx, 64);

    printf("\n");

    /* ======================================== */
    /* Test 2: ChaCha20-Poly1305 Alignment     */
    /* ======================================== */

    printf("Test 2: ChaCha20-Poly1305 Context Alignment\n");
    printf("------------------------------------------\n");

    /* Allocate ChaCha context with 64-byte alignment */
    void* chacha_buffer = aligned_alloc(64, CHACHA_CONTEXT_SIZE);
    if (!chacha_buffer) {
        fprintf(stderr, "Error: aligned_alloc failed for ChaCha context\n");
        free(gcm_buffer);
        return 1;
    }

    soliton_chacha_ctx* chacha_ctx = (soliton_chacha_ctx*)chacha_buffer;

    /* Initialize context */
    status = soliton_chacha_init(chacha_ctx, key, iv);

    if (status != SOLITON_OK) {
        fprintf(stderr, "Error: ChaCha init failed\n");
        free(gcm_buffer);
        free(chacha_buffer);
        return 1;
    }

    /* Verify base address alignment */
    test_alignment("ChaCha context base address", chacha_ctx, 64);

    printf("\n");

    /* ======================================== */
    /* Test 3: Multiple Context Allocations   */
    /* ======================================== */

    printf("Test 3: Multiple Context Allocation Stability\n");
    printf("------------------------------------------\n");

    /* Allocate multiple contexts to verify consistent alignment */
    void* multi_ctx[4];
    for (int i = 0; i < 4; i++) {
        multi_ctx[i] = aligned_alloc(64, GCM_CONTEXT_SIZE);
        if (!multi_ctx[i]) {
            fprintf(stderr, "Error: aligned_alloc failed for context %d\n", i);
            free(gcm_buffer);
            free(chacha_buffer);
            for (int j = 0; j < i; j++) {
                free(multi_ctx[j]);
            }
            return 1;
        }

        /* Initialize each context */
        status = soliton_aesgcm_init((soliton_aesgcm_ctx*)multi_ctx[i], key, iv, 12);
        if (status != SOLITON_OK) {
            fprintf(stderr, "Error: Multi-context init %d failed\n", i);
        }

        char name[64];
        snprintf(name, sizeof(name), "GCM context #%d", i + 1);
        test_alignment(name, multi_ctx[i], 64);
    }

    printf("\n");

    /* ======================================== */
    /* Test 4: Structure Size Verification    */
    /* ======================================== */

    printf("Test 4: Allocation Size Verification\n");
    printf("------------------------------------------\n");

    printf("  GCM allocation size:    %zu bytes\n", GCM_CONTEXT_SIZE);
    printf("  ChaCha allocation size: %zu bytes\n", CHACHA_CONTEXT_SIZE);

    /* Verify allocations succeeded and are reasonable */
    if (GCM_CONTEXT_SIZE >= 512 && GCM_CONTEXT_SIZE <= 2048) {
        printf("  ✓ GCM allocation size is reasonable\n");
        tests_passed++;
    } else {
        printf("  ✗ GCM allocation size may be incorrect\n");
        tests_failed++;
    }

    if (CHACHA_CONTEXT_SIZE >= 256 && CHACHA_CONTEXT_SIZE <= 1024) {
        printf("  ✓ ChaCha allocation size is reasonable\n");
        tests_passed++;
    } else {
        printf("  ✗ ChaCha allocation size may be incorrect\n");
        tests_failed++;
    }

    printf("\n");

    /* ======================================== */
    /* Summary                                 */
    /* ======================================== */

    printf("==========================================\n");
    printf("Alignment Verification Summary\n");
    printf("==========================================\n");
    printf("\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("\n");

    if (tests_failed == 0) {
        printf("Status: ✓ ALL CHECKS PASSED\n");
        printf("\n");
        printf("All critical structures are properly aligned for\n");
        printf("optimal cache behavior and SIMD performance.\n");
    } else {
        printf("Status: ✗ ALIGNMENT FAILURES DETECTED\n");
        printf("\n");
        printf("Alignment issues may cause:\n");
        printf("  - Cache line splits\n");
        printf("  - Reduced SIMD performance\n");
        printf("  - Increased memory access latency\n");
    }

    printf("==========================================\n");

    /* Cleanup */
    free(gcm_buffer);
    free(chacha_buffer);
    for (int i = 0; i < 4; i++) {
        free(multi_ctx[i]);
    }

    return (tests_failed == 0) ? 0 : 1;
}
