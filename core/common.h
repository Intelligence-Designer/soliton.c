/*
 * common.h - Internal common definitions for soliton.c
 * Freestanding C17 - no libc dependencies
 */

#ifndef SOLITON_COMMON_H
#define SOLITON_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include "soliton.h"

/* Ensure we're in freestanding mode for core files */
#ifdef __STDC_HOSTED__
  #if __STDC_HOSTED__ == 1
    #error "Core files must be compiled in freestanding mode (-ffreestanding)"
  #endif
#endif

/* Alignment macros */
#define SOLITON_ALIGN(n) __attribute__((aligned(n)))
#define SOLITON_CACHE_LINE 64

/* Likely/unlikely branch hints */
#define SOLITON_LIKELY(x) __builtin_expect(!!(x), 1)
#define SOLITON_UNLIKELY(x) __builtin_expect(!!(x), 0)

/* Force inline for hot paths */
#define SOLITON_INLINE __attribute__((always_inline)) inline

/* No inline for debugging */
#define SOLITON_NOINLINE __attribute__((noinline))

/* Restrict pointer aliasing */
#define SOLITON_RESTRICT restrict

/* Memory barriers for constant-time operations */
#define SOLITON_BARRIER() __asm__ volatile("" ::: "memory")

/* Constant-time memory comparison */
static SOLITON_INLINE int soliton_ct_memcmp(const void* a, const void* b, size_t n) {
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    uint8_t diff = 0;

    for (size_t i = 0; i < n; i++) {
        diff |= pa[i] ^ pb[i];
    }

    return diff;
}

/* Constant-time conditional copy */
static SOLITON_INLINE void soliton_ct_cond_copy(void* dst, const void* src, size_t n, int condition) {
    uint8_t* pd = (uint8_t*)dst;
    const uint8_t* ps = (const uint8_t*)src;
    uint8_t mask = (uint8_t)(-condition);

    for (size_t i = 0; i < n; i++) {
        pd[i] = (pd[i] & ~mask) | (ps[i] & mask);
    }
}

/* Secure memory wipe */
static SOLITON_INLINE void soliton_wipe(void* ptr, size_t n) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (n--) {
        *p++ = 0;
    }
    SOLITON_BARRIER();
}

/* Byte order operations */
static SOLITON_INLINE uint32_t soliton_le32(const uint8_t* p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static SOLITON_INLINE void soliton_put_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static SOLITON_INLINE uint64_t soliton_le64(const uint8_t* p) {
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static SOLITON_INLINE void soliton_put_le64(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static SOLITON_INLINE uint32_t soliton_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

static SOLITON_INLINE void soliton_put_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static SOLITON_INLINE uint64_t soliton_be64(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) |
           ((uint64_t)p[7]);
}

static SOLITON_INLINE void soliton_put_be64(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

/* Rotate operations */
#define SOLITON_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define SOLITON_ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SOLITON_ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define SOLITON_ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* Min/Max without branches */
static SOLITON_INLINE size_t soliton_min(size_t a, size_t b) {
    return b ^ ((a ^ b) & -(a < b));
}

static SOLITON_INLINE size_t soliton_max(size_t a, size_t b) {
    return a ^ ((a ^ b) & -(a < b));
}

/* Round up to multiple */
static SOLITON_INLINE size_t soliton_round_up(size_t x, size_t multiple) {
    return ((x + multiple - 1) / multiple) * multiple;
}

/* Check if pointer is aligned */
static SOLITON_INLINE int soliton_is_aligned(const void* ptr, size_t alignment) {
    return ((uintptr_t)ptr & (alignment - 1)) == 0;
}

/* Backend function pointers */
typedef struct {
    /* AES functions */
    void (*aes_key_expand)(const uint8_t key[32], uint32_t* round_keys);
    void (*aes_encrypt_block)(const uint32_t* round_keys, const uint8_t in[16], uint8_t out[16]);
    void (*aes_ctr_blocks)(const uint32_t* round_keys, const uint8_t iv[16],
                          uint32_t counter, const uint8_t* in, uint8_t* out, size_t blocks);

    /* GHASH functions */
    void (*ghash_init)(uint8_t h[16], const uint32_t* round_keys);
    void (*ghash_update)(uint8_t* state, const uint8_t* h, const uint8_t* data, size_t len);

    /* ChaCha functions */
    void (*chacha_blocks)(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, const uint8_t* in, uint8_t* out, size_t blocks);

    /* Poly1305 functions */
    void (*poly1305_init)(void* ctx, const uint8_t key[32]);
    void (*poly1305_update)(void* ctx, const uint8_t* data, size_t len);
    void (*poly1305_final)(void* ctx, uint8_t tag[16]);

    /* Backend name for debugging */
    const char* name;
} soliton_backend_t;

/* Global backend selection */
extern const soliton_backend_t* soliton_get_backend(void);

/* Plan structure (v1.8.1 lattice) */
typedef struct {
    uint32_t lane_depth;      /* 8 or 16 blocks per batch */
    uint32_t overlap;         /* 0=no overlap, 1=phase-locked wave */
    uint32_t accumulators;    /* 2, 3, or 4 GHASH accumulators */
    uint32_t store_mode;      /* 0=cached, 1=streaming (NT stores) */
    uint32_t ffi_chunking;    /* FFI batch size in bytes */
    uint32_t io_burst;        /* Reactor I/O burst size */
    uint32_t rx_pad;          /* Frame padding */
} soliton_plan_t;

/* Workload characteristics */
typedef struct {
    size_t   msg_size;
    uint32_t stream_count;
    uint32_t is_batch;
    uint32_t high_throughput;
} soliton_workload_t;

/* Hardware capabilities */
typedef struct {
    uint32_t has_vaes;
    uint32_t has_vpclmul;
    uint32_t has_avx2;
    uint32_t has_avx512;
    uint32_t core_count;
} soliton_hw_caps_t;

/* Plan selection functions (from sched/plan.c) */
extern void soliton_plan_query_hw_caps(soliton_hw_caps_t *caps);
extern void soliton_plan_select(soliton_plan_t *plan, const soliton_hw_caps_t *hw, const soliton_workload_t *work);
extern void soliton_workload_default(soliton_workload_t *work, size_t msg_size);
extern void soliton_workload_batch(soliton_workload_t *work, size_t avg_msg_size, uint32_t stream_count);

/* Plan logging functions (from sched/plan_log.c) */
extern void soliton_log_plan(const soliton_plan_t *plan, const char *path);
extern void soliton_log_plan_timestamped(const soliton_plan_t *plan, const char *path, const char *label);
extern void soliton_clear_plan_log(const char *path);

/* Internal context structures (full definitions) */

/* AES-GCM context state enum */
typedef enum {
    AES_STATE_INIT,
    AES_STATE_AAD,
    AES_STATE_UPDATE,
    AES_STATE_FINAL
} aes_state_t;

/* AES-GCM context structure */
struct soliton_aesgcm_ctx {
    uint32_t round_keys[60];       /* AES-256 expanded keys (15 rounds * 4 words) */
    uint8_t  h[16];                /* GHASH key H = AES_K(0) */
    uint8_t  h_powers[16][16] SOLITON_ALIGN(64);  /* H^16...H^1 (64B aligned for fused kernel) */
    uint8_t  j0[16];               /* Initial counter block */
    uint8_t  ghash_state[16];      /* Running GHASH accumulator */
    uint8_t  buffer[16];           /* Partial block buffer */
    uint64_t aad_len;              /* AAD byte count */
    uint64_t ct_len;               /* Ciphertext byte count */
    uint32_t counter;              /* CTR mode counter */
    size_t   buffer_len;           /* Bytes in buffer */
    aes_state_t state;             /* State machine state */
    int      h_powers_ready;       /* H-powers computed flag (lazy init) */
    const soliton_backend_t* backend; /* Selected backend */
    soliton_plan_t plan;           /* Cached execution plan (v1.8.1) */
};

/* ChaCha20-Poly1305 context state enum */
typedef enum {
    CHACHA_STATE_INIT,
    CHACHA_STATE_AAD,
    CHACHA_STATE_UPDATE,
    CHACHA_STATE_FINAL
} chacha_state_t;

/* Poly1305 internal state */
typedef struct {
    uint32_t r[5];                 /* Key part r (clamped) */
    uint32_t s[4];                 /* Key part s */
    uint32_t h[5];                 /* Accumulator */
    uint8_t  buffer[16];           /* Partial block buffer */
    size_t   buffer_len;           /* Bytes in buffer */
} poly1305_state_t;

/* ChaCha20-Poly1305 context structure */
struct soliton_chacha_ctx {
    uint8_t  key[32];              /* ChaCha20 key */
    uint8_t  nonce[12];            /* Nonce */
    poly1305_state_t poly;         /* Poly1305 state */
    uint8_t  buffer[64];           /* Partial block buffer */
    uint64_t aad_len;              /* AAD byte count */
    uint64_t ct_len;               /* Ciphertext byte count */
    uint32_t counter;              /* ChaCha20 counter */
    size_t   buffer_len;           /* Bytes in buffer */
    chacha_state_t state;          /* State machine state */
    const soliton_backend_t* backend; /* Selected backend */
};

/* Batch context structure */
struct soliton_batch_ctx {
    void* worker_state;            /* Platform-specific worker state */
    size_t max_batch;              /* Maximum batch size */
    const soliton_backend_t* backend; /* Selected backend */
};

#endif /* SOLITON_COMMON_H */