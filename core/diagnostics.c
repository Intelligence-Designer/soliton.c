/*
 * diagnostics.c - Performance diagnostic implementation
 */

#include "diagnostics.h"

#ifdef SOLITON_DIAGNOSTICS

#include <stdio.h>
#include <string.h>

/* Global diagnostics storage */
soliton_diag_t soliton_diag = {0};

/* Print comprehensive diagnostics report */
void soliton_diag_print(void) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  soliton.c Performance Diagnostics Report\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /* Backend selection */
    printf("Backend Configuration:\n");
    printf("  Selected backend: %s\n", soliton_diag.selected_backend[0] ?
           soliton_diag.selected_backend : "unknown");
    printf("\n");

    /* GCM operation counts */
    printf("GCM Operation Counts:\n");
    printf("  init():           %12lu\n", soliton_diag.gcm_init_calls);
    printf("  aad_update():     %12lu\n", soliton_diag.gcm_aad_calls);
    printf("  encrypt_update(): %12lu\n", soliton_diag.gcm_encrypt_calls);
    printf("  decrypt_update(): %12lu\n", soliton_diag.gcm_decrypt_calls);
    printf("  final():          %12lu\n", soliton_diag.gcm_final_calls);
    printf("\n");

    /* Batch size distribution */
    printf("Batch Size Distribution:\n");
    printf("  8-block batches:  %12lu (optimal)\n", soliton_diag.batch_8block_hits);
    printf("  >8 block batches: %12lu (good)\n", soliton_diag.batch_large_hits);
    printf("  <8 block batches: %12lu (suboptimal)\n", soliton_diag.batch_partial_hits);
    printf("  Total blocks:     %12lu\n", soliton_diag.total_blocks_processed);

    if (soliton_diag.batch_8block_hits + soliton_diag.batch_large_hits + soliton_diag.batch_partial_hits > 0) {
        uint64_t total = soliton_diag.batch_8block_hits + soliton_diag.batch_large_hits + soliton_diag.batch_partial_hits;
        double pct_optimal = (100.0 * soliton_diag.batch_8block_hits) / total;
        double pct_suboptimal = (100.0 * soliton_diag.batch_partial_hits) / total;
        printf("  Optimal ratio:    %12.1f%%\n", pct_optimal);
        printf("  Suboptimal ratio: %12.1f%%\n", pct_suboptimal);

        if (pct_suboptimal > 20.0) {
            printf("  ⚠️  WARNING: High suboptimal batch rate - FFI coalescing needed!\n");
        }
    }
    printf("\n");

    /* GHASH path selection */
    printf("GHASH Path Selection:\n");
    printf("  8-way CLMUL:      %12lu calls\n", soliton_diag.ghash_clmul8_calls);
    printf("  Scalar fallback:  %12lu calls\n", soliton_diag.ghash_scalar_calls);
    printf("  Total bytes:      %12lu (%.2f MB)\n",
           soliton_diag.ghash_total_bytes,
           soliton_diag.ghash_total_bytes / (1024.0 * 1024.0));

    if (soliton_diag.ghash_clmul8_calls + soliton_diag.ghash_scalar_calls > 0) {
        uint64_t total = soliton_diag.ghash_clmul8_calls + soliton_diag.ghash_scalar_calls;
        double pct_optimized = (100.0 * soliton_diag.ghash_clmul8_calls) / total;
        printf("  Optimized ratio:  %12.1f%%\n", pct_optimized);

        if (pct_optimized < 80.0) {
            printf("  ⚠️  WARNING: Low optimized GHASH usage!\n");
        }
    }
    printf("\n");

    /* AES path selection */
    printf("AES Path Selection:\n");
    printf("  VAES calls:       %12lu\n", soliton_diag.aes_vaes_calls);
    printf("  Scalar calls:     %12lu\n", soliton_diag.aes_scalar_calls);
    printf("  Total blocks:     %12lu\n", soliton_diag.aes_total_blocks);
    printf("\n");

    /* Tail handling */
    printf("Tail Handling:\n");
    printf("  Partial blocks:   %12lu\n", soliton_diag.tail_partial_blocks);
    printf("  Sub-block bytes:  %12lu\n", soliton_diag.tail_sub_block_bytes);
    printf("\n");

    /* Provider overhead analysis */
    printf("Provider Update Analysis:\n");
    printf("  Total updates:    %12lu\n", soliton_diag.provider_update_calls);
    printf("  Small (<128B):    %12lu\n", soliton_diag.provider_small_updates);
    printf("  Medium (≤8KB):    %12lu\n", soliton_diag.provider_medium_updates);
    printf("  Large (>8KB):     %12lu\n", soliton_diag.provider_large_updates);

    if (soliton_diag.provider_update_calls > 0) {
        double pct_small = (100.0 * soliton_diag.provider_small_updates) / soliton_diag.provider_update_calls;
        double avg_blocks = (double)soliton_diag.total_blocks_processed / soliton_diag.provider_update_calls;
        printf("  Small update %%:   %12.1f%%\n", pct_small);
        printf("  Avg blocks/call:  %12.1f\n", avg_blocks);

        if (pct_small > 30.0) {
            printf("  ⚠️  WARNING: High small update rate - coalescing strongly recommended!\n");
        }
        if (avg_blocks < 6.0) {
            printf("  ⚠️  WARNING: Low average batch size - not utilizing 8-way kernel!\n");
        }
    }
    printf("\n");

    /* Memory alignment */
    printf("Memory Alignment:\n");
    printf("  Aligned (32B):    %12lu\n", soliton_diag.aligned_loads);
    printf("  Unaligned:        %12lu\n", soliton_diag.unaligned_loads);

    if (soliton_diag.aligned_loads + soliton_diag.unaligned_loads > 0) {
        uint64_t total = soliton_diag.aligned_loads + soliton_diag.unaligned_loads;
        double pct_aligned = (100.0 * soliton_diag.aligned_loads) / total;
        printf("  Aligned ratio:    %12.1f%%\n", pct_aligned);
    }
    printf("\n");

    /* Summary and recommendations */
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Performance Recommendations:\n");

    int warnings = 0;

    /* Check batch utilization */
    if (soliton_diag.batch_8block_hits + soliton_diag.batch_large_hits + soliton_diag.batch_partial_hits > 0) {
        uint64_t total = soliton_diag.batch_8block_hits + soliton_diag.batch_large_hits + soliton_diag.batch_partial_hits;
        double pct_suboptimal = (100.0 * soliton_diag.batch_partial_hits) / total;
        if (pct_suboptimal > 20.0) {
            printf("  [%d] Implement FFI coalescing to increase 8-block batch rate\n", ++warnings);
        }
    }

    /* Check provider update sizes */
    if (soliton_diag.provider_update_calls > 0) {
        double pct_small = (100.0 * soliton_diag.provider_small_updates) / soliton_diag.provider_update_calls;
        if (pct_small > 30.0) {
            printf("  [%d] Provider receiving many small updates - add accumulation buffer\n", ++warnings);
        }
    }

    /* Check GHASH path */
    if (soliton_diag.ghash_clmul8_calls + soliton_diag.ghash_scalar_calls > 0) {
        uint64_t total = soliton_diag.ghash_clmul8_calls + soliton_diag.ghash_scalar_calls;
        double pct_optimized = (100.0 * soliton_diag.ghash_clmul8_calls) / total;
        if (pct_optimized < 80.0) {
            printf("  [%d] GHASH not using 8-way path - check batch sizes\n", ++warnings);
        }
    }

    if (warnings == 0) {
        printf("  ✓ No major performance issues detected\n");
    }

    printf("═══════════════════════════════════════════════════════════════\n\n");
}

/* Reset all diagnostics counters */
void soliton_diag_reset(void) {
    memset(&soliton_diag, 0, sizeof(soliton_diag));
}

#endif /* SOLITON_DIAGNOSTICS */
