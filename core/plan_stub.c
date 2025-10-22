/*
 * plan_stub.c - Stub implementations for scheduler functions
 *
 * These are placeholder implementations until the full scheduler
 * (sched/) is implemented. For v0.4.1, we use simple defaults.
 */

#include "common.h"

/* Query hardware capabilities */
void soliton_plan_query_hw_caps(soliton_hw_caps_t *caps) {
    caps->has_vaes = 0;
    caps->has_vpclmul = 0;
    caps->has_avx2 = 0;
    caps->has_avx512 = 0;
    caps->core_count = 1;

#ifdef __x86_64__
    /* Simple CPUID check for now */
    #ifdef __VAES__
        caps->has_vaes = 1;
    #endif
    #ifdef __VPCLMULQDQ__
        caps->has_vpclmulqdq = 1;
    #endif
    #ifdef __AVX2__
        caps->has_avx2 = 1;
    #endif
    #ifdef __AVX512F__
        caps->has_avx512 = 1;
    #endif
#endif
}

/* Initialize workload with default parameters */
void soliton_workload_default(soliton_workload_t *work, size_t msg_size) {
    work->msg_size = msg_size;
    work->stream_count = 1;
    work->is_batch = 0;
    work->high_throughput = (msg_size >= 4096) ? 1 : 0;
}

/* Initialize workload for batch processing */
void soliton_workload_batch(soliton_workload_t *work, size_t avg_msg_size, uint32_t stream_count) {
    work->msg_size = avg_msg_size;
    work->stream_count = stream_count;
    work->is_batch = 1;
    work->high_throughput = 1;
}

/* Select execution plan based on hardware and workload */
void soliton_plan_select(soliton_plan_t *plan, const soliton_hw_caps_t *hw, const soliton_workload_t *work) {
    /* Default plan for v0.4.1 */
    plan->lane_depth = 8;          /* 8-block batches */
    plan->overlap = 0;             /* No wave overlap yet */
    plan->accumulators = 2;        /* 2 GHASH accumulators */
    plan->store_mode = 0;          /* Cached stores */
    plan->ffi_chunking = 16384;    /* 16KB FFI chunks */
    plan->io_burst = 4096;         /* 4KB I/O bursts */
    plan->rx_pad = 0;              /* No padding */

    /* Adjust for VAES if available */
    if (hw->has_vaes && work->msg_size >= 16384) {
        plan->lane_depth = 16;     /* 16-block batches for VAES */
        plan->accumulators = 4;    /* 4 accumulators for deeper pipeline */
    }

    /* Streaming stores for very large messages */
    if (work->msg_size >= 65536) {
        plan->store_mode = 1;      /* Non-temporal stores */
    }
}
