/*
 * profile_init_breakdown.c - Measure each component of init
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#define ITERATIONS 100000

static inline uint64_t rdtscp(void) {
    uint32_t aux;
    return __rdtscp(&aux);
}

/* External function declarations */
extern void aes256_key_expand_vaes(const uint8_t key[32], uint32_t* round_keys);
extern void ghash_init_clmul(uint8_t h[16], const uint32_t* round_keys);
extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);

int main(void) {
    uint8_t key[32] = {0};
    uint8_t h[16] = {0};
    uint8_t h_powers[16][16] __attribute__((aligned(64)));
    uint32_t round_keys[60];

    fprintf(stderr, "[PROFILE] Init breakdown: %d iterations each\n\n", ITERATIONS);

    /* 1. Measure AES key expansion */
    uint64_t start = rdtscp();
    for (int i = 0; i < ITERATIONS; i++) {
        aes256_key_expand_vaes(key, round_keys);
    }
    uint64_t end = rdtscp();
    uint64_t key_expand_cycles = (end - start) / ITERATIONS;
    fprintf(stderr, "[1] AES key expansion: %lu cycles\n", key_expand_cycles);

    /* 2. Measure GHASH init (H = AES_K(0)) */
    aes256_key_expand_vaes(key, round_keys);
    start = rdtscp();
    for (int i = 0; i < ITERATIONS; i++) {
        ghash_init_clmul(h, round_keys);
    }
    end = rdtscp();
    uint64_t ghash_init_cycles = (end - start) / ITERATIONS;
    fprintf(stderr, "[2] GHASH init (H=AES_K(0)): %lu cycles\n", ghash_init_cycles);

    /* 3. Measure H-power precomputation */
    ghash_init_clmul(h, round_keys);
    start = rdtscp();
    for (int i = 0; i < ITERATIONS; i++) {
        ghash_precompute_h_powers_clmul(h_powers, h);
    }
    end = rdtscp();
    uint64_t h_powers_cycles = (end - start) / ITERATIONS;
    fprintf(stderr, "[3] H-power precomputation (H^1..H^16): %lu cycles\n", h_powers_cycles);

    /* Total */
    uint64_t total_core_cycles = key_expand_cycles + ghash_init_cycles + h_powers_cycles;
    fprintf(stderr, "\n[TOTAL CORE]: %lu cycles\n", total_core_cycles);
    fprintf(stderr, "[OVERHEAD]: ~%lu cycles (context setup, IV, plan selection)\n",
            11580 - total_core_cycles);

    /* Breakdown percentages */
    fprintf(stderr, "\nBreakdown:\n");
    fprintf(stderr, "  AES key expansion:    %5.1f%%  (%lu cycles)\n",
            100.0 * key_expand_cycles / total_core_cycles, key_expand_cycles);
    fprintf(stderr, "  GHASH init:           %5.1f%%  (%lu cycles)\n",
            100.0 * ghash_init_cycles / total_core_cycles, ghash_init_cycles);
    fprintf(stderr, "  H-power precompute:   %5.1f%%  (%lu cycles)  <-- BOTTLENECK?\n",
            100.0 * h_powers_cycles / total_core_cycles, h_powers_cycles);

    return 0;
}
