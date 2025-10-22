/*
 * profile_init.c - Focused benchmark for init overhead profiling
 * Usage: perf stat -e cycles,instructions,branches,branch-misses ./bench/profile_init
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#include "../include/soliton.h"

#define CTX_SIZE 1024
#define ITERATIONS 100000

static inline uint64_t rdtscp(void) {
    uint32_t aux;
    return __rdtscp(&aux);
}

int main(void) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};

    /* Allocate context */
    void* ctx_buffer = aligned_alloc(64, CTX_SIZE);
    if (!ctx_buffer) {
        fprintf(stderr, "Context allocation failed\n");
        return 1;
    }
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    fprintf(stderr, "[PROFILE] Init-only benchmark: %d iterations\n", ITERATIONS);

    /* Warmup */
    for (int i = 0; i < 1000; i++) {
        soliton_aesgcm_init(ctx, key, iv, 12);
    }

    /* Measure */
    uint64_t start = rdtscp();
    for (int i = 0; i < ITERATIONS; i++) {
        soliton_aesgcm_init(ctx, key, iv, 12);
    }
    uint64_t end = rdtscp();

    uint64_t avg_cycles = (end - start) / ITERATIONS;
    fprintf(stderr, "[PROFILE] Average init cycles: %lu\n", avg_cycles);
    fprintf(stderr, "[PROFILE] Total cycles: %lu\n", end - start);

    free(ctx_buffer);
    return 0;
}
