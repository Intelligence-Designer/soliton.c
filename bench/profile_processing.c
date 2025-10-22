/*
 * profile_processing.c - Measure processing (excluding init)
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

    /* Test different message sizes */
    size_t sizes[] = {64, 256, 1024, 4096, 16384};
    int num_sizes = 5;

    void* ctx_buffer = aligned_alloc(64, CTX_SIZE);
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    fprintf(stderr, "[PROFILE] Processing overhead (excluding init)\n\n");

    for (int s = 0; s < num_sizes; s++) {
        size_t size = sizes[s];
        uint8_t* pt = malloc(size);
        uint8_t* ct = malloc(size);
        uint8_t tag[16];

        memset(pt, 0xAA, size);

        /* Init once */
        soliton_aesgcm_init(ctx, key, iv, 12);

        /* Warmup */
        for (int i = 0; i < 100; i++) {
            soliton_aesgcm_init(ctx, key, iv, 12);
            soliton_aesgcm_encrypt_update(ctx, pt, ct, size);
            soliton_aesgcm_encrypt_final(ctx, tag);
        }

        /* Measure processing only (with init, but we'll subtract it) */
        uint64_t start = rdtscp();
        for (int i = 0; i < ITERATIONS; i++) {
            soliton_aesgcm_init(ctx, key, iv, 12);
            soliton_aesgcm_encrypt_update(ctx, pt, ct, size);
            soliton_aesgcm_encrypt_final(ctx, tag);
        }
        uint64_t end = rdtscp();
        uint64_t total_cycles = (end - start) / ITERATIONS;

        /* Subtract init overhead */
        uint64_t init_overhead = 11580;  /* From previous profiling */
        uint64_t processing_cycles = total_cycles - init_overhead;
        double cpb = (double)processing_cycles / size;

        fprintf(stderr, "[%5zuB] Total: %6lu cyc | Init: %5lu cyc | Process: %6lu cyc | %.2f cpb\n",
                size, total_cycles, init_overhead, processing_cycles, cpb);

        free(pt);
        free(ct);
    }

    free(ctx_buffer);
    return 0;
}
