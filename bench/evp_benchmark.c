/*
 * EVP Benchmark: soliton.c vs OpenSSL 3.x (v0.3.1)
 *
 * Measures AES-256-GCM performance using cycle-accurate timing (rdtscp).
 * Sweeps message sizes and AAD/CT workload mixes.
 *
 * v0.3.1 change: Separates init overhead from steady-state throughput.
 * - init_cycles: Key expansion + H-power precomputation (one-time)
 * - steady_cycles: Encrypt + GHASH processing (amortized)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <x86intrin.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "../include/soliton.h"

/* Context size (1024 bytes to be safe) */
#define CTX_SIZE 1024

/* Cycle counter using rdtscp (serializing) */
static inline uint64_t rdtscp(void) {
    uint32_t aux;
    return __rdtscp(&aux);
}

/* Benchmark configuration */
typedef struct {
    size_t pt_size;
    size_t aad_size;
    const char* label;
} bench_config_t;

/* Benchmark results structure */
typedef struct {
    uint64_t init_cycles;     /* One-time init overhead */
    uint64_t steady_cycles;   /* Per-operation steady-state */
} bench_result_t;

static const bench_config_t configs[] = {
    /* CT-only workloads */
    {64, 0, "64B CT-only"},
    {256, 0, "256B CT-only"},
    {1024, 0, "1KB CT-only"},
    {4096, 0, "4KB CT-only"},
    {16384, 0, "16KB CT-only"},
    {65536, 0, "64KB CT-only"},

    /* AAD-only workloads */
    {0, 64, "64B AAD-only"},
    {0, 256, "256B AAD-only"},
    {0, 1024, "1KB AAD-only"},

    /* Mixed workloads (1:1 AAD:CT) */
    {128, 128, "128B+128B mixed"},
    {512, 512, "512B+512B mixed"},
    {2048, 2048, "2KB+2KB mixed"},
    {8192, 8192, "8KB+8KB mixed"},
};

#define NUM_CONFIGS (sizeof(configs) / sizeof(configs[0]))
#define WARMUP_ITERS 100
#define MEASURE_ITERS 1000

/* OpenSSL EVP benchmark - v0.3.1: separate init from steady-state */
static bench_result_t bench_openssl_evp(const bench_config_t* cfg) {
    bench_result_t result = {0};
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;

    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t* pt = malloc(cfg->pt_size);
    uint8_t* aad = malloc(cfg->aad_size);
    uint8_t* ct = malloc(cfg->pt_size + 16);
    uint8_t tag[16];

    if (!pt || !aad || !ct) {
        free(pt); free(aad); free(ct);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    memset(pt, 0xAA, cfg->pt_size);
    memset(aad, 0xBB, cfg->aad_size);

    /* Measure full-init cost (includes key expansion + process) */
    uint64_t init_start = rdtscp();
    for (int i = 0; i < MEASURE_ITERS; i++) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
        if (cfg->aad_size > 0) {
            int len;
            EVP_EncryptUpdate(ctx, NULL, &len, aad, cfg->aad_size);
        }
        if (cfg->pt_size > 0) {
            int len;
            EVP_EncryptUpdate(ctx, ct, &len, pt, cfg->pt_size);
        }
        int len;
        EVP_EncryptFinal_ex(ctx, ct, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    }
    uint64_t init_end = rdtscp();
    result.init_cycles = (init_end - init_start) / MEASURE_ITERS;

    /* Warmup steady-state (key expansion done once, then lightweight IV resets) */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, NULL);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);  /* Lightweight IV reset */
        if (cfg->aad_size > 0) {
            int len;
            EVP_EncryptUpdate(ctx, NULL, &len, aad, cfg->aad_size);
        }
        if (cfg->pt_size > 0) {
            int len;
            EVP_EncryptUpdate(ctx, ct, &len, pt, cfg->pt_size);
        }
        int len;
        EVP_EncryptFinal_ex(ctx, ct, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    }

    /* Measure steady-state (amortized cost without key expansion) */
    uint64_t steady_start = rdtscp();
    for (int i = 0; i < MEASURE_ITERS; i++) {
        EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);  /* Lightweight IV reset */
        if (cfg->aad_size > 0) {
            int len;
            EVP_EncryptUpdate(ctx, NULL, &len, aad, cfg->aad_size);
        }
        if (cfg->pt_size > 0) {
            int len;
            EVP_EncryptUpdate(ctx, ct, &len, pt, cfg->pt_size);
        }
        int len;
        EVP_EncryptFinal_ex(ctx, ct, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    }
    uint64_t steady_end = rdtscp();
    result.steady_cycles = (steady_end - steady_start) / MEASURE_ITERS;

    free(pt);
    free(aad);
    free(ct);
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

/* soliton.c benchmark - v0.3.1: separate init from steady-state */
static bench_result_t bench_soliton(const bench_config_t* cfg) {
    bench_result_t result = {0};
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t* pt = malloc(cfg->pt_size);
    uint8_t* aad = malloc(cfg->aad_size);
    uint8_t* ct = malloc(cfg->pt_size);
    uint8_t tag[16];

    if (!pt || !aad || !ct) {
        free(pt); free(aad); free(ct);
        return result;
    }

    memset(pt, 0xAA, cfg->pt_size);
    memset(aad, 0xBB, cfg->aad_size);

    /* Allocate context */
    void* ctx_buffer = aligned_alloc(64, CTX_SIZE);
    if (!ctx_buffer) {
        free(pt); free(aad); free(ct);
        return result;
    }
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        soliton_aesgcm_init(ctx, key, iv, 12);
        if (cfg->aad_size > 0) {
            soliton_aesgcm_aad_update(ctx, aad, cfg->aad_size);
        }
        if (cfg->pt_size > 0) {
            soliton_aesgcm_encrypt_update(ctx, pt, ct, cfg->pt_size);
        }
        soliton_aesgcm_encrypt_final(ctx, tag);
    }

    /* Measure full-init cost (includes key expansion + H-powers + process)
     * Note: soliton currently lacks lightweight IV-reset API */
    uint64_t init_start = rdtscp();
    for (int i = 0; i < MEASURE_ITERS; i++) {
        soliton_aesgcm_init(ctx, key, iv, 12);
        if (cfg->aad_size > 0) {
            soliton_aesgcm_aad_update(ctx, aad, cfg->aad_size);
        }
        if (cfg->pt_size > 0) {
            soliton_aesgcm_encrypt_update(ctx, pt, ct, cfg->pt_size);
        }
        soliton_aesgcm_encrypt_final(ctx, tag);
    }
    uint64_t init_end = rdtscp();
    result.init_cycles = (init_end - init_start) / MEASURE_ITERS;

    /* Steady-state: same as init for soliton (no lightweight IV-reset yet)
     * Future: add soliton_aesgcm_reset_iv() for amortized perf */
    result.steady_cycles = result.init_cycles;

    free(pt);
    free(aad);
    free(ct);
    free(ctx_buffer);

    return result;
}

/* Calculate cycles per byte */
static double calc_cpb(uint64_t cycles, size_t bytes) {
    if (bytes == 0) return 0.0;
    return (double)cycles / bytes;
}

int main(void) {
    printf("===================================================================================\n");
    printf("  EVP Benchmark: soliton.c vs OpenSSL 3.x (v0.3.1)\n");
    printf("===================================================================================\n\n");

    printf("Configuration:\n");
    printf("  Warmup iterations: %d\n", WARMUP_ITERS);
    printf("  Measurement iterations: %d\n", MEASURE_ITERS);
    printf("  Timing method: rdtscp (cycle-accurate)\n");
    printf("  Methodology:\n");
    printf("    - 'Full-init': Complete operation with key expansion (realistic single-use)\n");
    printf("    - 'Steady': Amortized perf with lightweight IV reset (OpenSSL) or N/A (soliton)\n\n");

    /* CSV header */
    FILE* csv = fopen("results/evp_benchmark_v031.csv", "w");
    if (csv) {
        fprintf(csv, "workload,pt_bytes,aad_bytes,total_bytes,");
        fprintf(csv, "ssl_full_init_cyc,sol_full_init_cyc,");
        fprintf(csv, "ssl_steady_cyc,sol_steady_cyc,");
        fprintf(csv, "ssl_full_cpb,sol_full_cpb,ssl_steady_cpb,sol_steady_cpb,");
        fprintf(csv, "full_speedup,steady_speedup\n");
    }

    printf("%-20s %8s | %8s %8s | %8s %8s | Full-init speedup\n",
           "Workload", "Size",
           "SSL cpb", "Sol cpb", "SSL-SS", "Sol-SS");
    printf("%-20s %8s | %8s %8s | %8s %8s | %s\n",
           "--------------------", "--------",
           "--------", "--------", "--------", "--------", "-----------------");

    for (size_t i = 0; i < NUM_CONFIGS; i++) {
        const bench_config_t* cfg = &configs[i];

        bench_result_t ssl_result = bench_openssl_evp(cfg);
        bench_result_t sol_result = bench_soliton(cfg);

        size_t total_bytes = cfg->pt_size + cfg->aad_size;

        /* Full-init comparison (apples-to-apples) */
        double ssl_full_cpb = calc_cpb(ssl_result.init_cycles, total_bytes);
        double sol_full_cpb = calc_cpb(sol_result.init_cycles, total_bytes);
        double full_speedup = (double)sol_result.init_cycles / ssl_result.init_cycles;

        /* Steady-state (OpenSSL only for now) */
        double ssl_steady_cpb = calc_cpb(ssl_result.steady_cycles, total_bytes);
        double sol_steady_cpb = calc_cpb(sol_result.steady_cycles, total_bytes);

        printf("%-20s %8zu | %8.2f %8.2f | %8.2f %8.2f | %6.2fx slower\n",
               cfg->label, total_bytes,
               ssl_full_cpb, sol_full_cpb,
               ssl_steady_cpb, sol_steady_cpb,
               full_speedup);

        if (csv) {
            fprintf(csv, "%s,%zu,%zu,%zu,%lu,%lu,%lu,%lu,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
                    cfg->label, cfg->pt_size, cfg->aad_size, total_bytes,
                    ssl_result.init_cycles, sol_result.init_cycles,
                    ssl_result.steady_cycles, sol_result.steady_cycles,
                    ssl_full_cpb, sol_full_cpb,
                    ssl_steady_cpb, sol_steady_cpb,
                    full_speedup,
                    (double)sol_result.steady_cycles / ssl_result.steady_cycles);
        }
    }

    if (csv) fclose(csv);

    printf("\n===================================================================================\n");
    printf("Results saved to: results/evp_benchmark_v031.csv\n");
    printf("\nLEGEND:\n");
    printf("  SSL/Sol cpb:  Full-init cycles per byte (apples-to-apples comparison)\n");
    printf("  SSL-SS:       OpenSSL steady-state with lightweight IV reset (target for soliton)\n");
    printf("  Sol-SS:       Currently same as full-init (needs lightweight IV-reset API)\n");
    printf("===================================================================================\n");

    return 0;
}
