/*
 * Oracle differential test for ghash_update_clmul8
 * Validates power-sum formula: Xi₈ = Xi₀·H⁸ ⊕ C₁·H⁷ ⊕ C₂·H⁶ ⊕ ... ⊕ C₈·H¹
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* Standalone test - define only what we need */
static inline uint64_t soliton_be64(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | (uint64_t)p[7];
}

static inline void soliton_put_be64(uint8_t* p, uint64_t v) {
    p[0] = (v >> 56) & 0xFF;
    p[1] = (v >> 48) & 0xFF;
    p[2] = (v >> 40) & 0xFF;
    p[3] = (v >> 32) & 0xFF;
    p[4] = (v >> 24) & 0xFF;
    p[5] = (v >> 16) & 0xFF;
    p[6] = (v >> 8) & 0xFF;
    p[7] = v & 0xFF;
}

/* Domain conversion helpers */
static inline __m128i to_lepoly_128(__m128i x_spec) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_spec, rev);
}

static inline __m128i from_lepoly_128(__m128i x_kernel) {
    const __m128i rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(x_kernel, rev);
}

/* Verified reduction (from ghash_clmul.c) */
extern __m128i ghash_reduce_256_to_128_lepoly(__m128i lo, __m128i hi);

/* Verified 4-partial multiply */
static inline void mul256_lohi(__m128i a, __m128i b, __m128i *lo, __m128i *hi) {
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i mid = _mm_xor_si128(p01, p10);
    *lo = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
    *hi = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));
}

/* Reference 8-block GHASH using power-sum formula */
static __m128i ghash_clmul8_oracle(
    __m128i Xi0_kern,
    __m128i C_kern[8],
    __m128i Hpow_kern[9]  /* Hpow[1..8], Hpow[0] unused */
) {
    __m128i acc_lo = _mm_setzero_si128();
    __m128i acc_hi = _mm_setzero_si128();
    __m128i tlo, thi;

    /* Xi0 * H^8 */
    mul256_lohi(Xi0_kern, Hpow_kern[8], &tlo, &thi);
    acc_lo = _mm_xor_si128(acc_lo, tlo);
    acc_hi = _mm_xor_si128(acc_hi, thi);

    /* C[i] * H^{8-i}, i=0..7 (C indexed from 0, representing C₁..C₈) */
    for (int i = 0; i < 8; i++) {
        mul256_lohi(C_kern[i], Hpow_kern[8 - i], &tlo, &thi);
        acc_lo = _mm_xor_si128(acc_lo, tlo);
        acc_hi = _mm_xor_si128(acc_hi, thi);
    }

    /* Single reduction at end */
    return ghash_reduce_256_to_128_lepoly(acc_lo, acc_hi);
}

/* Print __m128i as hex */
static void print_hex(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
    printf("\n");
}

/* External functions */
extern void ghash_precompute_h_powers_clmul(uint8_t h_powers[16][16], const uint8_t h_spec[16]);
extern void ghash_update_clmul8(uint8_t* state, const uint8_t h_powers[8][16],
                                const uint8_t* data, size_t len);

int main(void) {
    /* Test case: 128 bytes of {0x00, 0x01, 0x02, ...}, all-zero key */
    uint8_t key[32] = {0};
    uint8_t zeros[16] = {0};
    uint8_t data[128];
    for (int i = 0; i < 128; i++) data[i] = i;

    printf("=== GHASH CLMUL8 Oracle Differential Test ===\n\n");

    /* Compute H = AES_K(0) - for zero key, use AES scalar */
    extern void aes256_key_expand_scalar(const uint8_t key[32], uint32_t round_keys[60]);
    extern void aes256_encrypt_block_scalar(const uint32_t* rk, const uint8_t in[16], uint8_t out[16]);

    uint32_t round_keys[60];
    aes256_key_expand_scalar(key, round_keys);

    uint8_t H_spec[16];
    aes256_encrypt_block_scalar(round_keys, zeros, H_spec);

    printf("H_spec: ");
    for (int i = 0; i < 16; i++) printf("%02x", H_spec[i]);
    printf("\n\n");

    /* Precompute H^1..H^16 */
    uint8_t h_powers_storage[16][16];
    ghash_precompute_h_powers_clmul(h_powers_storage, H_spec);

    /* Load H^1..H^8 in kernel domain */
    __m128i Hpow[9];  /* Hpow[1..8] */
    for (int i = 1; i <= 8; i++) {
        Hpow[i] = _mm_loadu_si128((const __m128i*)h_powers_storage[i-1]);
        print_hex((i==1?"H^1":(i==8?"H^8":"H^?")), Hpow[i]);
    }
    printf("\n");

    /* Initial state Xi0 = 0 in kernel domain */
    __m128i Xi0_kern = _mm_setzero_si128();
    print_hex("Xi0_kern", Xi0_kern);

    /* Convert data blocks C₁..C₈ to kernel domain */
    __m128i C_kern[8];
    for (int i = 0; i < 8; i++) {
        __m128i C_spec = _mm_loadu_si128((const __m128i*)(data + i*16));
        C_kern[i] = to_lepoly_128(C_spec);
        if (i < 2) print_hex((i==0?"C[0]_kern":"C[1]_kern"), C_kern[i]);
    }
    printf("...\n\n");

    /* Oracle: Compute using power-sum formula */
    __m128i Xi_oracle = ghash_clmul8_oracle(Xi0_kern, C_kern, Hpow);
    print_hex("Xi_oracle", Xi_oracle);

    /* Compute individual terms for diagnosis */
    printf("\n--- Power-sum term breakdown ---\n");
    __m128i termXi, tlo, thi;
    mul256_lohi(Xi0_kern, Hpow[8], &tlo, &thi);
    termXi = ghash_reduce_256_to_128_lepoly(tlo, thi);
    print_hex("termXi = Xi0*H^8", termXi);

    for (int i = 0; i < 8; i++) {
        mul256_lohi(C_kern[i], Hpow[8 - i], &tlo, &thi);
        __m128i term = ghash_reduce_256_to_128_lepoly(tlo, thi);
        char buf[32];
        snprintf(buf, sizeof(buf), "term[%d] = C[%d]*H^%d", i, i, 8-i);
        print_hex(buf, term);
    }

    /* Shifted variant (suspected off-by-one pattern) */
    printf("\n--- Shifted variant (off-by-one suspect) ---\n");
    for (int i = 0; i < 8; i++) {
        int power = (i == 0) ? 8 : (8 - i + 1);  // C[0] still H^8, others shifted
        if (power > 8) power = 8;
        mul256_lohi(C_kern[i], Hpow[power], &tlo, &thi);
        __m128i term = ghash_reduce_256_to_128_lepoly(tlo, thi);
        char buf[32];
        snprintf(buf, sizeof(buf), "shift[%d] = C[%d]*H^%d", i, i, power);
        print_hex(buf, term);
    }

    /* Current implementation: ghash_update_clmul8 */
    uint8_t state_simd[16] = {0};  /* Xi0 = 0 */
    ghash_update_clmul8(state_simd, (const uint8_t(*)[16])h_powers_storage, data, 128);
    __m128i Xi_simd = _mm_loadu_si128((const __m128i*)state_simd);

    printf("\n");
    print_hex("Xi_simd (current impl)", Xi_simd);

    /* Compare */
    __m128i diff = _mm_xor_si128(Xi_oracle, Xi_simd);
    int mismatch = !_mm_test_all_zeros(diff, diff);

    printf("\n");
    if (mismatch) {
        print_hex("DIFF (oracle XOR simd)", diff);
        printf("\n❌ MISMATCH: ghash_update_clmul8 does not match power-sum oracle\n");
        printf("   Bug likely: off-by-one in H powers, block-order reversal, or hidden swap\n");
        return 1;
    } else {
        printf("✅ MATCH: ghash_update_clmul8 matches power-sum oracle\n");
        return 0;
    }
}
