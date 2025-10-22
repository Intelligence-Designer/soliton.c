#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "soliton.h"

int main() {
    /* Test Case 2 from test_vectors.h: 16-byte zero plaintext */
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16];
    uint8_t tag[16];
    
    /* Expected values */
    uint8_t expected_ct[16] = {
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
    };
    uint8_t expected_tag[16] = {
        0x33, 0x2e, 0xaf, 0x89, 0xfc, 0x63, 0xd3, 0x1c,
        0x9d, 0x4f, 0xa0, 0xd9, 0xbe, 0x39, 0x46, 0xb8
    };
    
    uint8_t ctx_buffer[2048] __attribute__((aligned(64)));
    soliton_aesgcm_ctx *ctx = (soliton_aesgcm_ctx*)ctx_buffer;
    
    /* Initialize */
    soliton_status status = soliton_aesgcm_init(ctx, key, iv, 12);
    if (status != SOLITON_OK) {
        printf("Init failed: %d\n", status);
        return 1;
    }
    
    /* Encrypt (no AAD) */
    status = soliton_aesgcm_encrypt_update(ctx, pt, ct, 16);
    if (status != SOLITON_OK) {
        printf("Encrypt failed: %d\n", status);
        return 1;
    }
    
    /* Finalize */
    status = soliton_aesgcm_encrypt_final(ctx, tag);
    if (status != SOLITON_OK) {
        printf("Final failed: %d\n", status);
        return 1;
    }
    
    /* Check ciphertext */
    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("\n");
    
    printf("Expected CT: ");
    for (int i = 0; i < 16; i++) printf("%02x", expected_ct[i]);
    printf("\n");
    
    printf("CT Match: %s\n", memcmp(ct, expected_ct, 16) == 0 ? "YES" : "NO");
    
    /* Check tag */
    printf("Tag:         ");
    for (int i = 0; i < 16; i++) printf("%02x", tag[i]);
    printf("\n");
    
    printf("Expected Tag: ");
    for (int i = 0; i < 16; i++) printf("%02x", expected_tag[i]);
    printf("\n");
    
    printf("Tag Match: %s\n", memcmp(tag, expected_tag, 16) == 0 ? "YES" : "NO");
    
    return 0;
}
