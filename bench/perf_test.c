/*
 * perf_test.c - Simple benchmark for microarchitectural profiling
 * Usage: perf stat -e <events> ./bench/perf_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../include/soliton.h"

#define CTX_SIZE 1024
#define ITERATIONS 10000

int main(void) {
    /* 8KB + 8KB mixed workload (representative of real usage) */
    const size_t PT_SIZE = 8192;
    const size_t AAD_SIZE = 8192;

    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t* pt = malloc(PT_SIZE);
    uint8_t* aad = malloc(AAD_SIZE);
    uint8_t* ct = malloc(PT_SIZE);
    uint8_t tag[16];

    if (!pt || !aad || !ct) {
        fprintf(stderr, "Allocation failed\n");
        return 1;
    }

    memset(pt, 0xAA, PT_SIZE);
    memset(aad, 0xBB, AAD_SIZE);

    /* Allocate context */
    void* ctx_buffer = aligned_alloc(64, CTX_SIZE);
    if (!ctx_buffer) {
        fprintf(stderr, "Context allocation failed\n");
        return 1;
    }
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    fprintf(stderr, "[PERF TEST] Running %d iterations of 8KB+8KB mixed workload\n", ITERATIONS);

    /* Run workload */
    for (int i = 0; i < ITERATIONS; i++) {
        soliton_aesgcm_init(ctx, key, iv, 12);
        soliton_aesgcm_aad_update(ctx, aad, AAD_SIZE);
        soliton_aesgcm_encrypt_update(ctx, pt, ct, PT_SIZE);
        soliton_aesgcm_encrypt_final(ctx, tag);
    }

    fprintf(stderr, "[PERF TEST] Complete\n");

    free(pt);
    free(aad);
    free(ct);
    free(ctx_buffer);

    return 0;
}
