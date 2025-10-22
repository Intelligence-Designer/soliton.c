/*
 * aes_aesni.c - AES-NI implementation for single-block encryption
 * Uses x86 AES-NI instructions for fast single-block operations
 */

#if defined(__x86_64__) || defined(__i386__)
#ifdef __AES__

#include <stdint.h>
#include <wmmintrin.h>  /* AES-NI */
#include <emmintrin.h>  /* SSE2 */

/*
 * AES-256 single block encryption using AES-NI
 * Much faster than scalar for init (computing GHASH H key)
 *
 * round_keys: 60 uint32_t = 15 rounds × 4 words (240 bytes total)
 * in: 16-byte plaintext block
 * out: 16-byte ciphertext block
 */
void aes256_encrypt_block_aesni(const uint32_t* round_keys,
                                 const uint8_t in[16],
                                 uint8_t out[16]) {
    /* Load plaintext */
    __m128i state = _mm_loadu_si128((const __m128i*)in);

    /* Load round keys (15 rounds for AES-256) */
    const __m128i* rk = (const __m128i*)round_keys;

    /* Initial round: AddRoundKey */
    state = _mm_xor_si128(state, rk[0]);

    /* Rounds 1-13: SubBytes, ShiftRows, MixColumns, AddRoundKey */
    state = _mm_aesenc_si128(state, rk[1]);
    state = _mm_aesenc_si128(state, rk[2]);
    state = _mm_aesenc_si128(state, rk[3]);
    state = _mm_aesenc_si128(state, rk[4]);
    state = _mm_aesenc_si128(state, rk[5]);
    state = _mm_aesenc_si128(state, rk[6]);
    state = _mm_aesenc_si128(state, rk[7]);
    state = _mm_aesenc_si128(state, rk[8]);
    state = _mm_aesenc_si128(state, rk[9]);
    state = _mm_aesenc_si128(state, rk[10]);
    state = _mm_aesenc_si128(state, rk[11]);
    state = _mm_aesenc_si128(state, rk[12]);
    state = _mm_aesenc_si128(state, rk[13]);

    /* Final round: SubBytes, ShiftRows, AddRoundKey (no MixColumns) */
    state = _mm_aesenclast_si128(state, rk[14]);

    /* Store ciphertext */
    _mm_storeu_si128((__m128i*)out, state);
}

#endif /* __AES__ */
#endif /* __x86_64__ || __i386__ */
