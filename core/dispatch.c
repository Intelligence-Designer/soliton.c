/*
 * dispatch.c - Runtime feature detection and backend selection
 * Selects optimal implementation based on CPU capabilities
 */

#include "common.h"
#include "ct_utils.h"
#include "diagnostics.h"

/* Path logging for v0.3.1 (only in hosted builds with stdio) */
#if defined(__STDC_HOSTED__) && __STDC_HOSTED__ == 1
#include <stdio.h>
#define GHASH_PATH_LOG(msg) do { \
    static int logged = 0; \
    if (!logged) { fprintf(stderr, msg); logged = 1; } \
} while(0)
#else
#define GHASH_PATH_LOG(msg) do { } while(0)
#endif

/* SIMD intrinsics for tag XOR */
#ifdef __SSSE3__
#include <tmmintrin.h>  /* For _mm_shuffle_epi8 */
#endif

/* CPU feature detection */
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>

static void detect_x86_features(soliton_caps* caps) {
    unsigned int eax, ebx, ecx, edx;

    /* Check for AVX2 support */
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        if (ebx & (1 << 5)) {
            caps->bits |= SOLITON_FEAT_AVX2;
        }

        /* Check for VAES and VPCLMULQDQ */
        if (ecx & (1 << 9)) {  /* VAES */
            caps->bits |= SOLITON_FEAT_VAES;
        }
        if (ecx & (1 << 10)) { /* VPCLMULQDQ */
            caps->bits |= SOLITON_FEAT_VPCLMUL;
        }
    }

    /* Check for AES-NI and PCLMUL */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1 << 25)) {  /* AES-NI */
            caps->bits |= SOLITON_FEAT_AESNI;
        }
        if (ecx & (1 << 1)) {  /* PCLMULQDQ */
            caps->bits |= SOLITON_FEAT_PCLMUL;
        }
    }

    /* Check for AVX-512 Foundation */
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        if (ebx & (1 << 16)) {
            caps->bits |= SOLITON_FEAT_AVX512F;
        }
    }
}

#elif defined(__aarch64__) || defined(__arm__)
#ifdef __linux__
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

static void detect_arm_features(soliton_caps* caps) {
#ifdef __linux__
    unsigned long hwcap = getauxval(AT_HWCAP);

    /* Check for NEON (always present on ARMv8) */
#ifdef __aarch64__
    caps->bits |= SOLITON_FEAT_NEON;

    /* Check for crypto extensions */
    if (hwcap & HWCAP_AES) {
        caps->bits |= SOLITON_FEAT_NEON;
    }
    if (hwcap & HWCAP_PMULL) {
        caps->bits |= SOLITON_FEAT_PMULL;
    }
#endif
#endif
}
#endif

/* Query runtime capabilities */
void soliton_query_caps(soliton_caps* out) {
    out->bits = 0;

#if defined(__x86_64__) || defined(__i386__)
    detect_x86_features(out);
#elif defined(__aarch64__) || defined(__arm__)
    detect_arm_features(out);
#endif
}

/* Backend declarations */
extern soliton_backend_t backend_aes_scalar;
extern soliton_backend_t backend_chacha_scalar;

#ifdef __x86_64__
#ifdef __AVX2__
extern soliton_backend_t backend_avx2;
#endif
#ifdef __VAES__
extern soliton_backend_t backend_vaes;
#endif
#ifdef __PCLMUL__
extern soliton_backend_t backend_clmul;
#endif
#endif

#ifdef __aarch64__
#ifdef __ARM_NEON
extern soliton_backend_t backend_chacha_neon;
#endif
#ifdef __ARM_FEATURE_CRYPTO
extern soliton_backend_t backend_neon;
extern soliton_backend_t backend_pmull;
#endif
#endif

/* Select best backend based on CPU features */
const soliton_backend_t* soliton_get_backend(void) {
    static const soliton_backend_t* selected_backend = NULL;
    static int initialized = 0;

    if (!initialized) {
        soliton_caps caps;
        soliton_query_caps(&caps);

#ifdef __x86_64__
#ifdef __VAES__
        /* VAES enabled - key expansion fixed! */
        if (caps.bits & SOLITON_FEAT_VAES) {
            selected_backend = &backend_vaes;
        } else
#endif
#endif
#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO
        /* Use ARM crypto extensions if available */
        if (caps.bits & SOLITON_FEAT_AES) {
            selected_backend = &backend_neon;
        } else
#endif
#endif
        {
            /* Fallback to scalar backend */
            selected_backend = &backend_aes_scalar;
        }

        initialized = 1;

        /* Record selected backend for diagnostics */
        DIAG_SET_BACKEND(selected_backend->name);
    }

    return selected_backend;
}

/* Select best GHASH backend */
const soliton_backend_t* soliton_get_ghash_backend(void) {
    static const soliton_backend_t* ghash_backend = NULL;
    static int initialized = 0;

    if (!initialized) {
        soliton_caps caps;
        soliton_query_caps(&caps);

#ifdef __x86_64__
#ifdef __PCLMUL__
        /* Use CLMUL for GHASH if available */
        if (caps.bits & (SOLITON_FEAT_PCLMUL | SOLITON_FEAT_VPCLMUL)) {
            ghash_backend = &backend_clmul;
        } else
#endif
#endif
#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO
        /* Use PMULL for GHASH if available */
        if (caps.bits & SOLITON_FEAT_PMULL) {
            ghash_backend = &backend_pmull;
        } else
#endif
#endif
        {
            /* Use same backend as AES */
            ghash_backend = soliton_get_backend();
        }

        initialized = 1;
    }

    return ghash_backend;
}

/* Select best ChaCha backend */
const soliton_backend_t* soliton_get_chacha_backend(void) {
    static const soliton_backend_t* chacha_backend = NULL;
    static int initialized = 0;

    if (!initialized) {
        soliton_caps caps;
        soliton_query_caps(&caps);

#ifdef __x86_64__
#ifdef __AVX2__
        /* Use AVX2 for ChaCha if available */
        if (caps.bits & SOLITON_FEAT_AVX2) {
            chacha_backend = &backend_avx2;
        } else
#endif
#endif
#ifdef __aarch64__
#ifdef __ARM_NEON
        /* Use NEON for ChaCha if available */
        if (caps.bits & SOLITON_FEAT_NEON) {
            chacha_backend = &backend_chacha_neon;
        } else
#endif
#endif
        {
            /* Fallback to scalar backend */
            chacha_backend = &backend_chacha_scalar;
        }

        initialized = 1;
    }

    return chacha_backend;
}

/* Version string */
const char* soliton_version_string(void) {
    return "soliton.c v0.1.1";
}

/* Context size definitions */
#define SOLITON_AESGCM_CTX_SIZE 512
#define SOLITON_CHACHA_CTX_SIZE 512
#define SOLITON_BATCH_CTX_SIZE  256

/* AES-GCM API implementation */
soliton_status soliton_aesgcm_init(
    soliton_aesgcm_ctx* ctx,
    const uint8_t key[SOLITON_AESGCM_KEY_BYTES],
    const uint8_t* iv, size_t iv_len) {

    DIAG_INC(gcm_init_calls);

    /* Validate inputs */
    if (!ctx || !key || !iv || iv_len == 0) {
        return SOLITON_INVALID_INPUT;
    }

    /* Get backend (do this first, before any expensive operations) */
    ctx->backend = soliton_get_backend();

    /* Clear only sensitive state fields (not whole context - too slow!) */
    soliton_wipe(ctx->ghash_state, 16);
    soliton_wipe(ctx->buffer, 16);
    ctx->aad_len = 0;
    ctx->ct_len = 0;
    ctx->buffer_len = 0;

    /* Expand key */
    ctx->backend->aes_key_expand(key, ctx->round_keys);

    /* Initialize GHASH key H = AES_K(0) */
    ctx->backend->ghash_init(ctx->h, ctx->round_keys);

    /* Pre-compute H-powers immediately during init (not lazily) to avoid any corruption */
    #ifdef __PCLMUL__
    extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);
    ghash_precompute_h_powers_clmul(ctx->h_powers, ctx->h);
    #else
    extern void ghash_precompute_powers_scalar(uint8_t h_powers[16][16], const uint8_t h[16]);
    ghash_precompute_powers_scalar(ctx->h_powers, ctx->h);
    #endif
    ctx->h_powers_ready = 1;

    /* Setup IV */
    if (iv_len == 12) {
        /* Standard 96-bit IV */
        for (size_t i = 0; i < 12; i++) {
            ctx->j0[i] = iv[i];
        }
        ctx->j0[12] = 0;
        ctx->j0[13] = 0;
        ctx->j0[14] = 0;
        ctx->j0[15] = 1;

        /* Zero GHASH state for fresh start */
        soliton_wipe(ctx->ghash_state, 16);
    } else {
        /* Non-standard IV length - use GHASH per NIST SP 800-38D Section 7.1
         * J₀ = GHASH_H(IV || 0^(s+64) || [len(IV)]₆₄)
         * where s = 128⌈len(IV)/128⌉ – len(IV) */
        soliton_wipe(ctx->ghash_state, 16);

        /* Process complete 16-byte blocks from IV */
        size_t iv_full_blocks = iv_len / 16;
        if (iv_full_blocks > 0) {
            ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], iv, iv_full_blocks * 16);
        }

        /* Remaining bytes and padding calculation */
        size_t iv_remainder = iv_len % 16;
        size_t len_bits = iv_len * 8;

        /* s = 128⌈len(IV)/128⌉ – len(IV) in bits */
        size_t s = (128 * ((len_bits + 127) / 128)) - len_bits;

        /* Total padding needed: s + 64 bits for zeros, plus 64 bits for length */
        /* This equals 128⌈len(IV)/128⌉ + 64 - len(IV) total bits after IV */
        size_t total_padding_bits = s + 64 + 64;  /* s + 64 zeros + 64 for length field */
        size_t total_padding_bytes = total_padding_bits / 8;

        /* Build padding blocks: partial IV remainder + zeros + length */
        uint8_t padding[64] = {0};  /* Max padding needed */

        /* Copy any remaining IV bytes */
        for (size_t i = 0; i < iv_remainder; i++) {
            padding[i] = iv[iv_full_blocks * 16 + i];
        }

        /* Zeros are already there from memset */

        /* Put 64-bit length at the end */
        soliton_put_be64(padding + total_padding_bytes - 8, len_bits);

        /* Process padding blocks */
        ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], padding, total_padding_bytes);

        /* j0 = GHASH result */
        for (int i = 0; i < 16; i++) {
            ctx->j0[i] = ctx->ghash_state[i];
        }
        soliton_wipe(ctx->ghash_state, 16);
    }

    /* Initialize counter and state */
    ctx->counter = 2;  /* Start at 2 (1 is used for tag) */
    ctx->aad_len = 0;
    ctx->ct_len = 0;
    ctx->buffer_len = 0;
    ctx->state = AES_STATE_INIT;

    /* Select and cache execution plan (v1.8.1 optimization) */
    soliton_hw_caps_t hw_caps;
    soliton_workload_t workload;

    soliton_plan_query_hw_caps(&hw_caps);
    /* Default to high-throughput workload (will adapt if needed) */
    soliton_workload_default(&workload, 65536); /* Assume large messages */
    soliton_plan_select(&ctx->plan, &hw_caps, &workload);

    return SOLITON_OK;
}

/* Reset AES-GCM context for new message (v0.4.4+)
 * Reuses key expansion and H-powers, only updates IV and state
 * This amortizes expensive init cost across multiple messages */
soliton_status soliton_aesgcm_reset(
    soliton_aesgcm_ctx* ctx,
    const uint8_t* iv, size_t iv_len) {

    /* Validate inputs */
    if (!ctx || !iv || iv_len == 0) {
        return SOLITON_INVALID_INPUT;
    }

    /* Verify context was previously initialized (backend must be set) */
    if (!ctx->backend) {
        return SOLITON_INVALID_INPUT;
    }

    /* Clear only message-specific state (NOT keys or H-powers!) */
    soliton_wipe(ctx->ghash_state, 16);
    soliton_wipe(ctx->buffer, 16);
    ctx->aad_len = 0;
    ctx->ct_len = 0;
    ctx->buffer_len = 0;

    /* Setup IV (reuse exact logic from init) */
    if (iv_len == 12) {
        /* Standard 96-bit IV */
        for (size_t i = 0; i < 12; i++) {
            ctx->j0[i] = iv[i];
        }
        ctx->j0[12] = 0;
        ctx->j0[13] = 0;
        ctx->j0[14] = 0;
        ctx->j0[15] = 1;

        /* Zero GHASH state for fresh start */
        soliton_wipe(ctx->ghash_state, 16);
    } else {
        /* Non-standard IV length - use GHASH per NIST SP 800-38D Section 7.1 */
        soliton_wipe(ctx->ghash_state, 16);

        /* Process complete 16-byte blocks from IV */
        size_t iv_full_blocks = iv_len / 16;
        if (iv_full_blocks > 0) {
            ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], iv, iv_full_blocks * 16);
        }

        /* Remaining bytes and padding */
        size_t iv_remainder = iv_len % 16;
        size_t len_bits = iv_len * 8;

        /* Final block: remainder + padding + length */
        uint8_t final_block[16] = {0};
        if (iv_remainder > 0) {
            for (size_t i = 0; i < iv_remainder; i++) {
                final_block[i] = iv[iv_full_blocks * 16 + i];
            }
        }

        /* Last 8 bytes: big-endian bit length */
        final_block[8] = (uint8_t)(len_bits >> 56);
        final_block[9] = (uint8_t)(len_bits >> 48);
        final_block[10] = (uint8_t)(len_bits >> 40);
        final_block[11] = (uint8_t)(len_bits >> 32);
        final_block[12] = (uint8_t)(len_bits >> 24);
        final_block[13] = (uint8_t)(len_bits >> 16);
        final_block[14] = (uint8_t)(len_bits >> 8);
        final_block[15] = (uint8_t)(len_bits);

        /* Process final block */
        ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], final_block, 16);

        /* J₀ is the final GHASH output */
        for (size_t i = 0; i < 16; i++) {
            ctx->j0[i] = ctx->ghash_state[i];
        }

        /* Clear GHASH state for actual message processing */
        soliton_wipe(ctx->ghash_state, 16);
    }

    /* Initialize counter (counter 1 reserved for tag, start at 2) */
    ctx->counter = 2;

    /* Reset state machine */
    ctx->state = AES_STATE_INIT;

    /* Note: Execution plan reused from original init */

    return SOLITON_OK;
}

soliton_status soliton_aesgcm_aad_update(
    soliton_aesgcm_ctx* ctx, const uint8_t* aad, size_t aad_len) {

    DIAG_INC(gcm_aad_calls);

    if (!ctx || (!aad && aad_len > 0)) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state != AES_STATE_INIT && ctx->state != AES_STATE_AAD) {
        return SOLITON_INVALID_INPUT;
    }

    ctx->state = AES_STATE_AAD;
    ctx->aad_len += aad_len;

    /* Update GHASH with AAD */
    ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], aad, aad_len);

    return SOLITON_OK;
}

soliton_status soliton_aesgcm_encrypt_update(
    soliton_aesgcm_ctx* ctx, const uint8_t* pt, uint8_t* ct, size_t len) {

    DIAG_INC(gcm_encrypt_calls);

    if (!ctx || (!pt && len > 0) || (!ct && len > 0)) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == AES_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    /* Lazy H-powers precomputation (deferred from init for performance) */
    if (!ctx->h_powers_ready) {
        #ifdef __PCLMUL__
        extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h[16]);
        ghash_precompute_h_powers_clmul(ctx->h_powers, ctx->h);
        #else
        extern void ghash_precompute_powers_scalar(uint8_t h_powers[16][16], const uint8_t h[16]);
        ghash_precompute_powers_scalar(ctx->h_powers, ctx->h);
        #endif
        ctx->h_powers_ready = 1;
    }

    /* AAD padding is handled automatically by ghash_update - no explicit padding needed */

    ctx->state = AES_STATE_UPDATE;
    ctx->ct_len += len;

    /* Generate keystream and encrypt */
    size_t blocks = len / 16;
    size_t remainder = len % 16;

    if (blocks > 0) {
        uint8_t ctr[16];
        for (int i = 0; i < 16; i++) {
            ctr[i] = ctx->j0[i];
        }

        /* Interleave AES and GHASH in batches to overlap execution */
        const size_t INTERLEAVE_DEPTH = 8;
        size_t full_batches = blocks / INTERLEAVE_DEPTH;
        size_t tail_blocks = blocks % INTERLEAVE_DEPTH;

        /* Process full batches with phase-locked pipeline when possible */
        #if 1 && defined(__VAES__) && defined(__PCLMUL__)  /* ENABLED - Session 9 fix applied */
        GHASH_PATH_LOG("[GHASH PATH] VAES fused kernel (8-block or 16-block)\n");
        /* Declare all three VAES+CLMUL kernels */
        extern void gcm_fused_encrypt8_vaes_clmul(
            const uint32_t* restrict, const uint8_t* restrict, uint8_t* restrict,
            const uint8_t[16], uint32_t, uint8_t* restrict, const uint8_t[8][16]);
        extern void gcm_pipelined_encrypt16_vaes_clmul(
            const uint32_t*, const uint8_t*, uint8_t*, const uint8_t[16],
            uint32_t, uint8_t*, const uint8_t (*)[16]);
        extern void gcm_fused_encrypt16_vaes_clmul(
            const uint32_t*, const uint8_t*, uint8_t*, const uint8_t[16],
            uint32_t, uint8_t*, const uint8_t (*)[16]);

        /* Use cached plan from context (selected during init) */
        soliton_plan_t *plan = &ctx->plan;

        /* Select kernel based on cached plan */
        if (plan->lane_depth == 16) {
            /* Depth-16 path */
            size_t batches_16 = full_batches / 2; /* 16 blocks = 2×8 */
            size_t remaining_8 = full_batches % 2;

            if (plan->overlap == 1) {
                /* Use phase-locked pipeline (overlap AES k+1 with GHASH k) */
                for (size_t batch = 0; batch < batches_16; batch++) {
                    size_t offset = batch * 16 * 16;
                    diag_record_batch(16);

                    gcm_pipelined_encrypt16_vaes_clmul(
                        ctx->round_keys, pt + offset, ct + offset,
                        ctx->j0, ctx->counter, ctx->ghash_state,
                        (const uint8_t (*)[16])ctx->h_powers
                    );
                    ctx->counter += 16;
                }
            } else {
                /* Use depth-16 fused kernel (single reduction per 16 blocks) */
                for (size_t batch = 0; batch < batches_16; batch++) {
                    size_t offset = batch * 16 * 16;
                    diag_record_batch(16);

                    gcm_fused_encrypt16_vaes_clmul(
                        ctx->round_keys, pt + offset, ct + offset,
                        ctx->j0, ctx->counter, ctx->ghash_state,
                        (const uint8_t (*)[16])ctx->h_powers
                    );
                    ctx->counter += 16;
                }
            }

            /* Process remaining 8-block batch if any */
            if (remaining_8 > 0) {
                size_t offset = batches_16 * 16 * 16;
                diag_record_batch(INTERLEAVE_DEPTH);

                gcm_fused_encrypt8_vaes_clmul(
                    ctx->round_keys, pt + offset, ct + offset,
                    ctx->j0, ctx->counter, ctx->ghash_state,
                    (const uint8_t (*)[16])ctx->h_powers
                );
                ctx->counter += INTERLEAVE_DEPTH;
            }
        } else {
            /* Depth-8 path (default for small messages) */
            for (size_t batch = 0; batch < full_batches; batch++) {
                size_t offset = batch * INTERLEAVE_DEPTH * 16;
                diag_record_batch(INTERLEAVE_DEPTH);

                gcm_fused_encrypt8_vaes_clmul(
                    ctx->round_keys, pt + offset, ct + offset,
                    ctx->j0, ctx->counter, ctx->ghash_state,
                    (const uint8_t (*)[16])ctx->h_powers
                );
                ctx->counter += INTERLEAVE_DEPTH;
            }
        }
        #elif 1 && defined(__PCLMUL__)  /* ENABLED - Testing after Session 9 ghash_mul_reflected fix */
        GHASH_PATH_LOG("[GHASH PATH] PCLMUL 8-way (separate AES+GHASH)\n");
        /* Fallback: separate AES and GHASH (AES-NI without VAES) */
        extern void ghash_update_clmul8(uint8_t*, const uint8_t[8][16], const uint8_t*, size_t);
        for (size_t batch = 0; batch < full_batches; batch++) {
            size_t offset = batch * INTERLEAVE_DEPTH * 16;

            /* Track batch size */
            diag_record_batch(INTERLEAVE_DEPTH);

            /* AES-CTR: encrypt 8 blocks */
            ctx->backend->aes_ctr_blocks(ctx->round_keys, ctr, ctx->counter,
                                          pt + offset, ct + offset, INTERLEAVE_DEPTH);
            ctx->counter += INTERLEAVE_DEPTH;

            /* GHASH: authenticate those 8 blocks immediately with 8-way CLMUL */
            ghash_update_clmul8(ctx->ghash_state, (const uint8_t (*)[16])ctx->h_powers, ct + offset, INTERLEAVE_DEPTH * 16);
        }
        #else
        GHASH_PATH_LOG("[GHASH PATH] Slow fallback (single-block scalar)\n");
        for (size_t batch = 0; batch < full_batches; batch++) {
            size_t offset = batch * INTERLEAVE_DEPTH * 16;

            /* AES-CTR: encrypt 8 blocks */
            ctx->backend->aes_ctr_blocks(ctx->round_keys, ctr, ctx->counter,
                                          pt + offset, ct + offset, INTERLEAVE_DEPTH);
            ctx->counter += INTERLEAVE_DEPTH;

            /* GHASH: authenticate those 8 blocks immediately */
            ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], ct + offset, INTERLEAVE_DEPTH * 16);
        }
        #endif

        /* Process remaining blocks (< 8) */
        if (tail_blocks > 0) {
            size_t offset = full_batches * INTERLEAVE_DEPTH * 16;

            /* Track tail batch size */
            diag_record_batch(tail_blocks);
            DIAG_INC(tail_partial_blocks);

            ctx->backend->aes_ctr_blocks(ctx->round_keys, ctr, ctx->counter,
                                          pt + offset, ct + offset, tail_blocks);
            ctx->counter += (uint32_t)tail_blocks;
            ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], ct + offset, tail_blocks * 16);
        }
    }

    /* Handle partial block */
    if (remainder > 0) {
        uint8_t keystream[16];
        uint8_t ctr[16];

        /* Track sub-block tail */
        DIAG_ADD(tail_sub_block_bytes, remainder);

        for (int i = 0; i < 12; i++) {
            ctr[i] = ctx->j0[i];
        }
        soliton_put_be32(ctr + 12, ctx->counter);

        ctx->backend->aes_encrypt_block(ctx->round_keys, ctr, keystream);

        for (size_t i = 0; i < remainder; i++) {
            ct[blocks * 16 + i] = pt[blocks * 16 + i] ^ keystream[i];
        }

        /* Update GHASH with partial block */
        ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], ct + blocks * 16, remainder);

        ctx->counter++;
    }

    return SOLITON_OK;
}

soliton_status soliton_aesgcm_encrypt_final(
    soliton_aesgcm_ctx* ctx, uint8_t tag[SOLITON_AESGCM_TAG_BYTES]) {

    DIAG_INC(gcm_final_calls);

    if (!ctx || !tag) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == AES_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    /* Ciphertext padding is handled automatically by ghash_update - no explicit padding needed */

    /* Finalize GHASH (use CLMUL version if available to match ghash_update format) */
    #ifdef __PCLMUL__
    extern void ghash_final_clmul(uint8_t*, const uint8_t*, const uint8_t*, uint64_t, uint64_t);
    ghash_final_clmul(tag, ctx->ghash_state, ctx->h_powers[0], ctx->aad_len, ctx->ct_len);
    #else
    extern void ghash_final_scalar(uint8_t*, const uint8_t*, const uint8_t*, uint64_t, uint64_t);
    ghash_final_scalar(tag, ctx->ghash_state, ctx->h_powers[0], ctx->aad_len, ctx->ct_len);
    #endif

    /* Encrypt GHASH output to get final tag */
    uint8_t ctr[16];
    for (int i = 0; i < 12; i++) {
        ctr[i] = ctx->j0[i];
    }
    soliton_put_be32(ctr + 12, 1);  /* Counter = 1 for tag */

    uint8_t encrypted_j0[16];
    ctx->backend->aes_encrypt_block(ctx->round_keys, ctr, encrypted_j0);

    /* XOR GHASH result with E(J0) - both should be in same byte order */
    for (int i = 0; i < 16; i++) {
        tag[i] ^= encrypted_j0[i];
    }

    ctx->state = AES_STATE_FINAL;
    return SOLITON_OK;
}

soliton_status soliton_aesgcm_decrypt_update(
    soliton_aesgcm_ctx* ctx, const uint8_t* ct, uint8_t* pt, size_t len) {

    DIAG_INC(gcm_decrypt_calls);

    if (!ctx || (!ct && len > 0) || (!pt && len > 0)) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == AES_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    /* AAD padding is handled automatically by ghash_update - no explicit padding needed */

    ctx->state = AES_STATE_UPDATE;
    ctx->ct_len += len;

    /* Update GHASH with ciphertext BEFORE decrypting (GCM requirement) */
    ctx->backend->ghash_update(ctx->ghash_state, ctx->h_powers[0], ct, len);

    /* Decrypt using CTR mode */
    size_t blocks = len / 16;
    size_t remainder = len % 16;

    if (blocks > 0) {
        /* CTR decrypt: Copy j0 to local buffer like encrypt does */
        uint8_t ctr[16];
        for (int i = 0; i < 16; i++) {
            ctr[i] = ctx->j0[i];
        }

        /* Use the copy instead of j0 directly */
        ctx->backend->aes_ctr_blocks(ctx->round_keys, ctr, ctx->counter, ct, pt, blocks);
        ctx->counter += (uint32_t)blocks;
    }

    /* Handle partial block */
    if (remainder > 0) {
        uint8_t keystream[16];
        uint8_t ctr[16];

        for (int i = 0; i < 12; i++) {
            ctr[i] = ctx->j0[i];
        }
        soliton_put_be32(ctr + 12, ctx->counter);

        ctx->backend->aes_encrypt_block(ctx->round_keys, ctr, keystream);

        for (size_t i = 0; i < remainder; i++) {
            pt[blocks * 16 + i] = ct[blocks * 16 + i] ^ keystream[i];
        }

        ctx->counter++;
    }

    return SOLITON_OK;
}

soliton_status soliton_aesgcm_decrypt_final(
    soliton_aesgcm_ctx* ctx, const uint8_t tag[SOLITON_AESGCM_TAG_BYTES]) {

    if (!ctx || !tag) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == AES_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    uint8_t computed_tag[16];

    /* Ciphertext padding is handled automatically by ghash_update - no explicit padding needed */

    /* Finalize GHASH (use CLMUL version if available to match ghash_update format) */
    #ifdef __PCLMUL__
    extern void ghash_final_clmul(uint8_t*, const uint8_t*, const uint8_t*, uint64_t, uint64_t);
    ghash_final_clmul(computed_tag, ctx->ghash_state, ctx->h_powers[0], ctx->aad_len, ctx->ct_len);
    #else
    extern void ghash_final_scalar(uint8_t*, const uint8_t*, const uint8_t*, uint64_t, uint64_t);
    ghash_final_scalar(computed_tag, ctx->ghash_state, ctx->h_powers[0], ctx->aad_len, ctx->ct_len);
    #endif

    /* Encrypt GHASH output to get final tag */
    uint8_t ctr[16];
    for (int i = 0; i < 12; i++) {
        ctr[i] = ctx->j0[i];
    }
    soliton_put_be32(ctr + 12, 1);  /* Counter = 1 for tag */

    uint8_t encrypted_j0[16];
    ctx->backend->aes_encrypt_block(ctx->round_keys, ctr, encrypted_j0);

    /* XOR GHASH result with E(J0) */
    for (int i = 0; i < 16; i++) {
        computed_tag[i] ^= encrypted_j0[i];
    }

    /* Constant-time tag comparison */
    int valid = ct_memcmp(computed_tag, tag, 16);

    ctx->state = AES_STATE_FINAL;

    /* Wipe computed tag */
    soliton_wipe(computed_tag, sizeof(computed_tag));

    return valid == 0 ? SOLITON_OK : SOLITON_AUTH_FAIL;
}

void soliton_aesgcm_context_wipe(soliton_aesgcm_ctx* ctx) {
    if (ctx) {
        soliton_wipe(ctx, sizeof(*ctx));
    }
}

/* ChaCha20-Poly1305 API implementation */
soliton_status soliton_chacha_init(
    soliton_chacha_ctx* ctx,
    const uint8_t key[SOLITON_CHACHA_KEY_BYTES],
    const uint8_t nonce[SOLITON_CHACHA_NONCE_BYTES]) {

    /* Validate inputs */
    if (!ctx || !key || !nonce) {
        return SOLITON_INVALID_INPUT;
    }

    /* Clear context */
    soliton_wipe(ctx, sizeof(*ctx));

    /* Get backend */
    ctx->backend = soliton_get_backend();

    /* Copy key and nonce */
    for (int i = 0; i < 32; i++) {
        ctx->key[i] = key[i];
    }
    for (int i = 0; i < 12; i++) {
        ctx->nonce[i] = nonce[i];
    }

    /* Generate Poly1305 one-time key from ChaCha20(counter=0) */
    uint8_t poly_key[32];
    extern void chacha20_poly1305_key_gen_scalar(uint8_t*, const uint8_t*, const uint8_t*);
    chacha20_poly1305_key_gen_scalar(poly_key, key, nonce);

    /* Initialize Poly1305 */
    extern void poly1305_init_scalar(void*, const uint8_t*);
    poly1305_init_scalar(&ctx->poly, poly_key);

    /* Wipe poly key */
    soliton_wipe(poly_key, sizeof(poly_key));

    /* Initialize state */
    ctx->counter = 1;  /* Start at 1 (0 was used for Poly1305 key) */
    ctx->aad_len = 0;
    ctx->ct_len = 0;
    ctx->buffer_len = 0;
    ctx->state = CHACHA_STATE_INIT;

    return SOLITON_OK;
}

soliton_status soliton_chacha_aad_update(
    soliton_chacha_ctx* ctx, const uint8_t* aad, size_t aad_len) {

    if (!ctx || (!aad && aad_len > 0)) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state != CHACHA_STATE_INIT && ctx->state != CHACHA_STATE_AAD) {
        return SOLITON_INVALID_INPUT;
    }

    ctx->state = CHACHA_STATE_AAD;
    ctx->aad_len += aad_len;

    /* Update Poly1305 with AAD */
    extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
    poly1305_update_scalar(&ctx->poly, aad, aad_len);

    return SOLITON_OK;
}

soliton_status soliton_chacha_encrypt_update(
    soliton_chacha_ctx* ctx, const uint8_t* pt, uint8_t* ct, size_t len) {

    if (!ctx || (!pt && len > 0) || (!ct && len > 0)) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == CHACHA_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    /* Pad AAD to 16-byte boundary if needed */
    if (ctx->state == CHACHA_STATE_AAD && ctx->aad_len % 16 != 0) {
        uint8_t zeros[16] = {0};
        size_t pad = 16 - (ctx->aad_len % 16);
        extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
        poly1305_update_scalar(&ctx->poly, zeros, pad);
    }

    ctx->state = CHACHA_STATE_UPDATE;
    ctx->ct_len += len;

    /* Encrypt with ChaCha20 */
    extern void chacha20_xor_scalar(const uint8_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
    chacha20_xor_scalar(ctx->key, ctx->nonce, ctx->counter, pt, ct, len);

    /* Update counter */
    ctx->counter += (uint32_t)((len + 63) / 64);

    /* Update Poly1305 with ciphertext */
    extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
    poly1305_update_scalar(&ctx->poly, ct, len);

    return SOLITON_OK;
}

soliton_status soliton_chacha_encrypt_final(
    soliton_chacha_ctx* ctx, uint8_t tag[SOLITON_CHACHA_TAG_BYTES]) {

    if (!ctx || !tag) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == CHACHA_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    /* Pad ciphertext to 16-byte boundary if needed */
    if (ctx->ct_len % 16 != 0) {
        uint8_t zeros[16] = {0};
        size_t pad = 16 - (ctx->ct_len % 16);
        extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
        poly1305_update_scalar(&ctx->poly, zeros, pad);
    }

    /* Add lengths */
    uint8_t lengths[16];
    soliton_put_le64(lengths, ctx->aad_len);
    soliton_put_le64(lengths + 8, ctx->ct_len);
    extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
    poly1305_update_scalar(&ctx->poly, lengths, 16);

    /* Finalize Poly1305 */
    extern void poly1305_final_scalar(void*, uint8_t*);
    poly1305_final_scalar(&ctx->poly, tag);

    ctx->state = CHACHA_STATE_FINAL;
    return SOLITON_OK;
}

soliton_status soliton_chacha_decrypt_update(
    soliton_chacha_ctx* ctx, const uint8_t* ct, uint8_t* pt, size_t len) {

    if (!ctx || (!ct && len > 0) || (!pt && len > 0)) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == CHACHA_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    /* Pad AAD to 16-byte boundary if needed */
    if (ctx->state == CHACHA_STATE_AAD && ctx->aad_len % 16 != 0) {
        uint8_t zeros[16] = {0};
        size_t pad = 16 - (ctx->aad_len % 16);
        extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
        poly1305_update_scalar(&ctx->poly, zeros, pad);
    }

    ctx->state = CHACHA_STATE_UPDATE;
    ctx->ct_len += len;

    /* Update Poly1305 with ciphertext BEFORE decrypting */
    extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
    poly1305_update_scalar(&ctx->poly, ct, len);

    /* Decrypt with ChaCha20 */
    extern void chacha20_xor_scalar(const uint8_t*, const uint8_t*, uint32_t, const uint8_t*, uint8_t*, size_t);
    chacha20_xor_scalar(ctx->key, ctx->nonce, ctx->counter, ct, pt, len);

    /* Update counter */
    ctx->counter += (uint32_t)((len + 63) / 64);

    return SOLITON_OK;
}

soliton_status soliton_chacha_decrypt_final(
    soliton_chacha_ctx* ctx, const uint8_t tag[SOLITON_CHACHA_TAG_BYTES]) {

    if (!ctx || !tag) {
        return SOLITON_INVALID_INPUT;
    }

    if (ctx->state == CHACHA_STATE_FINAL) {
        return SOLITON_INVALID_INPUT;
    }

    uint8_t computed_tag[16];

    /* Pad ciphertext to 16-byte boundary if needed */
    if (ctx->ct_len % 16 != 0) {
        uint8_t zeros[16] = {0};
        size_t pad = 16 - (ctx->ct_len % 16);
        extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
        poly1305_update_scalar(&ctx->poly, zeros, pad);
    }

    /* Add lengths */
    uint8_t lengths[16];
    soliton_put_le64(lengths, ctx->aad_len);
    soliton_put_le64(lengths + 8, ctx->ct_len);
    extern void poly1305_update_scalar(void*, const uint8_t*, size_t);
    poly1305_update_scalar(&ctx->poly, lengths, 16);

    /* Finalize Poly1305 */
    extern void poly1305_final_scalar(void*, uint8_t*);
    poly1305_final_scalar(&ctx->poly, computed_tag);

    /* Constant-time tag comparison */
    int valid = ct_memcmp(computed_tag, tag, 16);

    ctx->state = CHACHA_STATE_FINAL;

    /* Wipe computed tag */
    soliton_wipe(computed_tag, sizeof(computed_tag));

    return valid == 0 ? SOLITON_OK : SOLITON_AUTH_FAIL;
}

void soliton_chacha_context_wipe(soliton_chacha_ctx* ctx) {
    if (ctx) {
        soliton_wipe(ctx, sizeof(*ctx));
    }
}

/* Batch API stubs */
soliton_status soliton_batch_init(soliton_batch_ctx* bctx) {
    (void)bctx;
    return SOLITON_UNSUPPORTED;
}

soliton_status soliton_aesgcm_batch_update(
    soliton_batch_ctx* bctx,
    soliton_aesgcm_ctx** ctxs,
    soliton_span* spans,
    size_t N) {
    (void)bctx;
    (void)ctxs;
    (void)spans;
    (void)N;
    return SOLITON_UNSUPPORTED;
}

soliton_status soliton_chacha_batch_update(
    soliton_batch_ctx* bctx,
    soliton_chacha_ctx** ctxs,
    soliton_span* spans,
    size_t N) {
    (void)bctx;
    (void)ctxs;
    (void)spans;
    (void)N;
    return SOLITON_UNSUPPORTED;
}

void soliton_batch_context_wipe(soliton_batch_ctx* bctx) {
    if (bctx) {
        soliton_wipe(bctx, sizeof(*bctx));
    }
}