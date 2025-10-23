/*
 * test_reset_amortization.c - Demonstrate context reuse benefit (v0.4.4)
 *
 * Measures the amortization benefit of soliton_aesgcm_reset() over
 * repeated soliton_aesgcm_init() for multiple messages with same key.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#include "soliton.h"

/* Cycle counter using rdtscp (serializing) */
static inline uint64_t rdtscp(void) {
    uint32_t aux;
    return __rdtscp(&aux);
}

#define NUM_MESSAGES 10
#define MESSAGE_SIZE 4096

int main(void) {
    uint8_t key[32] = {0};
    uint8_t iv_base[12] = {0};
    uint8_t pt[MESSAGE_SIZE];
    uint8_t ct[MESSAGE_SIZE];
    uint8_t tag[16];

    memset(pt, 0xAA, MESSAGE_SIZE);

    /* Allocate context */
    uint8_t ctx_buffer[2048] __attribute__((aligned(64)));
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    printf("==========================================\n");
    printf("Context Reuse Amortization Test (v0.4.4)\n");
    printf("==========================================\n");
    printf("\n");
    printf("Messages: %d × %d bytes\n", NUM_MESSAGES, MESSAGE_SIZE);
    printf("\n");

    /* ============================================ */
    /* Test 1: Full init for each message          */
    /* ============================================ */

    printf("Test 1: Full init per message\n");
    printf("------------------------------------------\n");

    uint64_t start = rdtscp();
    for (int i = 0; i < NUM_MESSAGES; i++) {
        /* Unique IV for each message */
        uint8_t iv[12];
        memcpy(iv, iv_base, 12);
        iv[11] = (uint8_t)i;

        /* Full init (expensive: key expansion + H-powers) */
        soliton_aesgcm_init(ctx, key, iv, 12);
        soliton_aesgcm_encrypt_update(ctx, pt, ct, MESSAGE_SIZE);
        soliton_aesgcm_encrypt_final(ctx, tag);
    }
    uint64_t end = rdtscp();

    uint64_t init_cycles = end - start;
    uint64_t init_per_msg = init_cycles / NUM_MESSAGES;

    printf("  Total cycles:  %lu\n", init_cycles);
    printf("  Per message:   %lu cycles\n", init_per_msg);
    printf("  cpb (stream):  %.6f\n\n", (double)init_cycles / (NUM_MESSAGES * MESSAGE_SIZE));

    /* ============================================ */
    /* Test 2: Init once + reset for each message  */
    /* ============================================ */

    printf("Test 2: Init once + reset per message\n");
    printf("------------------------------------------\n");

    start = rdtscp();

    /* First message: full init */
    uint8_t iv0[12];
    memcpy(iv0, iv_base, 12);
    iv0[11] = 0;
    soliton_aesgcm_init(ctx, key, iv0, 12);
    soliton_aesgcm_encrypt_update(ctx, pt, ct, MESSAGE_SIZE);
    soliton_aesgcm_encrypt_final(ctx, tag);

    /* Subsequent messages: fast reset */
    for (int i = 1; i < NUM_MESSAGES; i++) {
        uint8_t iv[12];
        memcpy(iv, iv_base, 12);
        iv[11] = (uint8_t)i;

        /* Fast reset (cheap: reuse keys/H-powers) */
        soliton_aesgcm_reset(ctx, iv, 12);
        soliton_aesgcm_encrypt_update(ctx, pt, ct, MESSAGE_SIZE);
        soliton_aesgcm_encrypt_final(ctx, tag);
    }

    end = rdtscp();

    uint64_t reset_cycles = end - start;
    uint64_t reset_per_msg = reset_cycles / NUM_MESSAGES;

    printf("  Total cycles:  %lu\n", reset_cycles);
    printf("  Per message:   %lu cycles\n", reset_per_msg);
    printf("  cpb (stream):  %.6f\n\n", (double)reset_cycles / (NUM_MESSAGES * MESSAGE_SIZE));

    /* ============================================ */
    /* Summary                                      */
    /* ============================================ */

    printf("==========================================\n");
    printf("Amortization Benefit\n");
    printf("==========================================\n");
    printf("\n");

    uint64_t cycles_saved = init_cycles - reset_cycles;
    double speedup = (double)init_cycles / reset_cycles;
    double percent_faster = ((double)cycles_saved / init_cycles) * 100.0;

    printf("  Cycles saved:  %lu (%.1f%% faster)\n", cycles_saved, percent_faster);
    printf("  Speedup:       %.2fx\n", speedup);
    printf("\n");

    if (speedup > 1.1) {
        printf("Status: ✓ SIGNIFICANT BENEFIT\n");
        printf("\nContext reuse provides meaningful performance gain.\n");
        printf("Recommended for applications processing multiple\n");
        printf("messages with the same key.\n");
    } else {
        printf("Status: ⚠ MARGINAL BENEFIT\n");
        printf("\nContext reuse provides minimal gain.\n");
        printf("May not be worth the API complexity.\n");
    }

    printf("==========================================\n");

    return 0;
}
