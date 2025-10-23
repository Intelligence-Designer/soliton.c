/*
 * soliton.h - Public API for soliton.c cryptographic engine
 *
 * Freestanding C17 implementation of AES-256-GCM and ChaCha20-Poly1305
 * Compliant with NIST SP 800-38D and RFC 8439
 */

#ifndef SOLITON_H
#define SOLITON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version information */
#define SOLITON_VERSION_MAJOR 0
#define SOLITON_VERSION_MINOR 4
#define SOLITON_VERSION_PATCH 0

/* Version string function */
const char* soliton_version_string(void);

/* Feature capability bits */
enum {
    SOLITON_FEAT_VAES    = 1u << 0,  /* Intel VAES instructions */
    SOLITON_FEAT_VPCLMUL = 1u << 1,  /* Intel VPCLMULQDQ */
    SOLITON_FEAT_AVX2    = 1u << 2,  /* Intel AVX2 */
    SOLITON_FEAT_AVX512F = 1u << 3,  /* Intel AVX-512 Foundation */
    SOLITON_FEAT_NEON    = 1u << 4,  /* ARM NEON */
    SOLITON_FEAT_PMULL   = 1u << 5,  /* ARM polynomial multiply */
    SOLITON_FEAT_AESNI   = 1u << 6,  /* Intel AES-NI */
    SOLITON_FEAT_PCLMUL  = 1u << 7   /* Intel PCLMULQDQ */
};

/* Capability structure */
typedef struct {
    uint64_t bits;
} soliton_caps;

/* Query runtime capabilities - MUST be pure */
void soliton_query_caps(soliton_caps* out);

/* Status codes */
typedef enum {
    SOLITON_OK = 0,
    SOLITON_INVALID_INPUT,
    SOLITON_AUTH_FAIL,
    SOLITON_UNSUPPORTED,
    SOLITON_INTERNAL_ERROR
} soliton_status;

/* ========================= AES-256-GCM API ========================= */

#define SOLITON_AESGCM_KEY_BYTES 32u
#define SOLITON_AESGCM_TAG_BYTES 16u

/* Opaque context structure */
typedef struct soliton_aesgcm_ctx soliton_aesgcm_ctx;

/* Initialize AES-GCM context
 * key: 32-byte key
 * iv: initialization vector (12 bytes preferred)
 * iv_len: IV length in bytes */
soliton_status soliton_aesgcm_init(
    soliton_aesgcm_ctx* ctx,
    const uint8_t key[SOLITON_AESGCM_KEY_BYTES],
    const uint8_t* iv, size_t iv_len);

/* Reset AES-GCM context for new message (v0.4.4+)
 * Reuses key expansion and H-powers, only updates IV/counter
 * Amortizes expensive init cost across multiple messages
 * iv: new initialization vector (12 bytes preferred)
 * iv_len: IV length in bytes
 *
 * Usage pattern for multiple messages with same key:
 *   soliton_aesgcm_init(ctx, key, iv1, 12);      // First message (full init)
 *   // ... encrypt message 1 ...
 *   soliton_aesgcm_reset(ctx, iv2, 12);           // Subsequent messages (fast)
 *   // ... encrypt message 2 ...
 */
soliton_status soliton_aesgcm_reset(
    soliton_aesgcm_ctx* ctx,
    const uint8_t* iv, size_t iv_len);

/* Process additional authenticated data (AAD)
 * Can be called multiple times before encrypt/decrypt_update */
soliton_status soliton_aesgcm_aad_update(
    soliton_aesgcm_ctx* ctx,
    const uint8_t* aad, size_t aad_len);

/* Encrypt data
 * pt: plaintext input
 * ct: ciphertext output (can be same as pt for in-place)
 * len: data length in bytes */
soliton_status soliton_aesgcm_encrypt_update(
    soliton_aesgcm_ctx* ctx,
    const uint8_t* pt, uint8_t* ct, size_t len);

/* Finalize encryption and output authentication tag
 * tag: 16-byte authentication tag output */
soliton_status soliton_aesgcm_encrypt_final(
    soliton_aesgcm_ctx* ctx,
    uint8_t tag[SOLITON_AESGCM_TAG_BYTES]);

/* Decrypt data
 * ct: ciphertext input
 * pt: plaintext output (can be same as ct for in-place)
 * len: data length in bytes */
soliton_status soliton_aesgcm_decrypt_update(
    soliton_aesgcm_ctx* ctx,
    const uint8_t* ct, uint8_t* pt, size_t len);

/* Finalize decryption and verify authentication tag
 * tag: 16-byte authentication tag to verify
 * Returns SOLITON_AUTH_FAIL if tag verification fails
 * On failure, decrypted plaintext MUST be treated as undefined */
soliton_status soliton_aesgcm_decrypt_final(
    soliton_aesgcm_ctx* ctx,
    const uint8_t tag[SOLITON_AESGCM_TAG_BYTES]);

/* Securely wipe context */
void soliton_aesgcm_context_wipe(soliton_aesgcm_ctx* ctx);

/* ==================== ChaCha20-Poly1305 API ====================== */

#define SOLITON_CHACHA_KEY_BYTES   32u
#define SOLITON_CHACHA_NONCE_BYTES 12u
#define SOLITON_CHACHA_TAG_BYTES   16u

/* Opaque context structure */
typedef struct soliton_chacha_ctx soliton_chacha_ctx;

/* Initialize ChaCha20-Poly1305 context
 * key: 32-byte key
 * nonce: 12-byte nonce */
soliton_status soliton_chacha_init(
    soliton_chacha_ctx* ctx,
    const uint8_t key[SOLITON_CHACHA_KEY_BYTES],
    const uint8_t nonce[SOLITON_CHACHA_NONCE_BYTES]);

/* Process additional authenticated data (AAD) */
soliton_status soliton_chacha_aad_update(
    soliton_chacha_ctx* ctx,
    const uint8_t* aad, size_t aad_len);

/* Encrypt data */
soliton_status soliton_chacha_encrypt_update(
    soliton_chacha_ctx* ctx,
    const uint8_t* pt, uint8_t* ct, size_t len);

/* Finalize encryption and output authentication tag */
soliton_status soliton_chacha_encrypt_final(
    soliton_chacha_ctx* ctx,
    uint8_t tag[SOLITON_CHACHA_TAG_BYTES]);

/* Decrypt data */
soliton_status soliton_chacha_decrypt_update(
    soliton_chacha_ctx* ctx,
    const uint8_t* ct, uint8_t* pt, size_t len);

/* Finalize decryption and verify authentication tag */
soliton_status soliton_chacha_decrypt_final(
    soliton_chacha_ctx* ctx,
    const uint8_t tag[SOLITON_CHACHA_TAG_BYTES]);

/* Securely wipe context */
void soliton_chacha_context_wipe(soliton_chacha_ctx* ctx);

/* ================== Superlane Coalescing API (v1.1) ================== */

/* Span structure for batch processing */
typedef struct {
    const uint8_t* in;    /* Input buffer (pt for encrypt, ct for decrypt) */
    uint8_t* out;         /* Output buffer (ct for encrypt, pt for decrypt) */
    size_t len;           /* Length in bytes (may be zero) */
} soliton_span;

/* Opaque batch context structure */
typedef struct soliton_batch_ctx soliton_batch_ctx;

/* Initialize per-core batch context (no heap allocation, CT) */
soliton_status soliton_batch_init(soliton_batch_ctx* bctx);

/* Process multiple AES-GCM streams in a single batch
 * bctx: batch context
 * ctxs: array of N pointers to per-stream contexts
 * spans: array of N input/output spans
 * N: number of streams (implementation supports at least 16)
 *
 * Semantics: Each stream's result MUST match per-stream API output */
soliton_status soliton_aesgcm_batch_update(
    soliton_batch_ctx* bctx,
    soliton_aesgcm_ctx** ctxs,
    soliton_span* spans,
    size_t N);

/* Process multiple ChaCha20-Poly1305 streams in a single batch */
soliton_status soliton_chacha_batch_update(
    soliton_batch_ctx* bctx,
    soliton_chacha_ctx** ctxs,
    soliton_span* spans,
    size_t N);

/* Wipe batch context */
void soliton_batch_context_wipe(soliton_batch_ctx* bctx);

/* Maximum batch size supported by implementation */
#define SOLITON_MAX_BATCH_SIZE 256u

/* ======================== Policy Notes ========================= */

/*
 * - All functions MUST be constant-time with respect to secret data
 * - Callers MAY pass unaligned buffers; aligned fast paths SHOULD be auto-selected
 * - No dynamic allocation in core; contexts are POD
 * - On AUTH_FAIL, plaintext from decrypt_update MUST be treated as undefined
 * - Contexts are single-stream, not thread-safe; parallelism via multiple contexts
 * - Total processed size limited by size_t; counters follow spec semantics
 */

#ifdef __cplusplus
}
#endif

#endif /* SOLITON_H */