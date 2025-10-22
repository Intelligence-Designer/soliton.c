/*
 * diagnostics.h - Performance diagnostic instrumentation
 * Compile with -DSOLITON_DIAGNOSTICS to enable
 */

#ifndef SOLITON_DIAGNOSTICS_H
#define SOLITON_DIAGNOSTICS_H

#include <stdint.h>
#include <stddef.h>

#ifdef SOLITON_DIAGNOSTICS

/* Diagnostic counters structure */
typedef struct {
    /* GCM operation counters */
    uint64_t gcm_init_calls;
    uint64_t gcm_aad_calls;
    uint64_t gcm_encrypt_calls;
    uint64_t gcm_decrypt_calls;
    uint64_t gcm_final_calls;

    /* Batch size distribution */
    uint64_t batch_8block_hits;      /* Full 8-block batches */
    uint64_t batch_partial_hits;     /* 1-7 blocks */
    uint64_t batch_large_hits;       /* >8 blocks */
    uint64_t total_blocks_processed;

    /* GHASH path selection */
    uint64_t ghash_clmul8_calls;     /* 8-way optimized path */
    uint64_t ghash_scalar_calls;     /* Scalar fallback */
    uint64_t ghash_total_bytes;

    /* AES path selection */
    uint64_t aes_vaes_calls;
    uint64_t aes_scalar_calls;
    uint64_t aes_total_blocks;

    /* Tail handling */
    uint64_t tail_partial_blocks;
    uint64_t tail_sub_block_bytes;

    /* Provider overhead */
    uint64_t provider_update_calls;
    uint64_t provider_small_updates;  /* <128 bytes */
    uint64_t provider_medium_updates; /* 128-8192 bytes */
    uint64_t provider_large_updates;  /* >8192 bytes */

    /* Memory alignment */
    uint64_t unaligned_loads;
    uint64_t aligned_loads;

    /* Backend selection */
    char selected_backend[32];
} soliton_diag_t;

/* Global diagnostics (zero-initialized) */
extern soliton_diag_t soliton_diag;

/* Macros for instrumentation */
#define DIAG_INC(counter) do { __atomic_fetch_add(&soliton_diag.counter, 1, __ATOMIC_RELAXED); } while(0)
#define DIAG_ADD(counter, val) do { __atomic_fetch_add(&soliton_diag.counter, (val), __ATOMIC_RELAXED); } while(0)
#define DIAG_SET_BACKEND(name) do { \
    for (int i = 0; i < 31 && name[i]; i++) soliton_diag.selected_backend[i] = name[i]; \
} while(0)

/* Batch size classification */
static inline void diag_record_batch(size_t blocks) {
    if (blocks == 8) {
        DIAG_INC(batch_8block_hits);
    } else if (blocks > 8) {
        DIAG_INC(batch_large_hits);
    } else {
        DIAG_INC(batch_partial_hits);
    }
    DIAG_ADD(total_blocks_processed, blocks);
}

/* Provider update size classification */
static inline void diag_record_provider_update(size_t bytes) {
    DIAG_INC(provider_update_calls);
    if (bytes < 128) {
        DIAG_INC(provider_small_updates);
    } else if (bytes <= 8192) {
        DIAG_INC(provider_medium_updates);
    } else {
        DIAG_INC(provider_large_updates);
    }
}

/* Alignment check */
static inline void diag_check_alignment(const void* ptr) {
    if (((uintptr_t)ptr & 31) == 0) {
        DIAG_INC(aligned_loads);
    } else {
        DIAG_INC(unaligned_loads);
    }
}

/* Print diagnostics report */
void soliton_diag_print(void);

/* Reset diagnostics */
void soliton_diag_reset(void);

#else /* !SOLITON_DIAGNOSTICS */

/* No-op macros when diagnostics disabled */
#define DIAG_INC(counter) do { } while(0)
#define DIAG_ADD(counter, val) do { } while(0)
#define DIAG_SET_BACKEND(name) do { } while(0)
#define diag_record_batch(blocks) do { } while(0)
#define diag_record_provider_update(bytes) do { } while(0)
#define diag_check_alignment(ptr) do { } while(0)

static inline void soliton_diag_print(void) { }
static inline void soliton_diag_reset(void) { }

#endif /* SOLITON_DIAGNOSTICS */

#endif /* SOLITON_DIAGNOSTICS_H */
