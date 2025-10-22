/*
 * profile_process_only.c - Measure ONLY processing (init once, reuse context)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#include "../include/soliton.h"

#define CTX_SIZE 1024
#define ITERATIONS 10000

static inline uint64_t rdtscp(void) {
    uint32_t aux;
    return __rdtscp(&aux);
}

int main(void) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};

    size_t sizes[] = {64, 256, 1024, 4096, 16384};
    int num_sizes = 5;

    void* ctx_buffer = aligned_alloc(64, CTX_SIZE);
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    fprintf(stderr, "[PROFILE] Processing ONLY (init once, NO re-init)\n\n");

    for (int s = 0; s < num_sizes; s++) {
        size_t size = sizes[s];
        uint8_t* pt = malloc(size);
        uint8_t* ct = malloc(size);
        uint8_t tag[16];

        memset(pt, 0xAA, size);

        /* Init ONCE before measurement */
        soliton_aesgcm_init(ctx, key, iv, 12);

        /* Warmup */
        for (int i = 0; i < 100; i++) {
            /* Reset state manually to reuse context (HACK for testing) */
            ctx->state = 0;  // Reset to INIT state
            ctx->ct_len = 0;
            ctx->aad_len = 0;
            ctx->counter = 2;
            memset(ctx->ghash_state, 0, 16);

            soliton_aesgcm_encrypt_update(ctx, pt, ct, size);
            soliton_aesgcm_encrypt_final(ctx, tag);
        }

        /* Measure */
        uint64_t start = rdtscp();
        for (int i = 0; i < ITERATIONS; i++) {
            /* Reset state manually */
            ctx->state = 0;
            ctx->ct_len = 0;
            ctx->aad_len = 0;
            ctx->counter = 2;
            memset(ctx->ghash_state, 0, 16);

            soliton_aesgcm_encrypt_update(ctx, pt, ct, size);
            soliton_aesgcm_encrypt_final(ctx, tag);
        }
        uint64_t end = rdtscp();
        uint64_t processing_cycles = (end - start) / ITERATIONS;
        double cpb = (double)processing_cycles / size;

        fprintf(stderr, "[%5zuB] Process: %6lu cyc | %.2f cpb\n",
                size, processing_cycles, cpb);

        free(pt);
        free(ct);
    }

    free(ctx_buffer);
    return 0;
}
