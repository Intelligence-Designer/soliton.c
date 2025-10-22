/*
 * gen_vectors.c - Generate test vectors using our implementation
 */

#include <stdio.h>
#include <stdint.h>
#include "soliton.h"

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("static const uint8_t %s[%zu] = {\n    ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", data[i]);
        if (i < len - 1) {
            printf(", ");
            if ((i + 1) % 8 == 0) {
                printf("\n    ");
            }
        }
    }
    printf("\n};\n");
}

int main() {
    uint8_t ctx_buffer[1024];
    soliton_aesgcm_ctx* ctx = (soliton_aesgcm_ctx*)ctx_buffer;

    printf("Generating AES-256-GCM test vectors:\n\n");

    /* Test 1: Empty plaintext */
    {
        uint8_t key[32] = {0};
        uint8_t iv[12] = {0};
        uint8_t tag[16];

        soliton_aesgcm_init(ctx, key, iv, 12);
        soliton_aesgcm_encrypt_final(ctx, tag);

        printf("/* Test 1: Empty plaintext, empty AAD */\n");
        print_hex("aes_gcm_tag1", tag, 16);
        printf("\n");
    }

    /* Test 2: 16-byte zero plaintext */
    {
        uint8_t key[32] = {0};
        uint8_t iv[12] = {0};
        uint8_t pt[16] = {0};
        uint8_t ct[16];
        uint8_t tag[16];

        soliton_aesgcm_init(ctx, key, iv, 12);
        soliton_aesgcm_encrypt_update(ctx, pt, ct, 16);
        soliton_aesgcm_encrypt_final(ctx, tag);

        printf("/* Test 2: 16-byte zero plaintext */\n");
        print_hex("aes_gcm_ct2", ct, 16);
        print_hex("aes_gcm_tag2", tag, 16);
        printf("\n");
    }

    /* Test 3: With AAD and non-zero data */
    {
        uint8_t key[32] = {
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
        };
        uint8_t iv[12] = {
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
            0xde, 0xca, 0xf8, 0x88
        };
        uint8_t aad[20] = {
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xab, 0xad, 0xda, 0xd2
        };
        uint8_t pt[64] = {
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
            0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
            0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
            0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
        };
        uint8_t ct[64];
        uint8_t tag[16];

        soliton_aesgcm_init(ctx, key, iv, 12);
        soliton_aesgcm_aad_update(ctx, aad, 20);
        soliton_aesgcm_encrypt_update(ctx, pt, ct, 64);
        soliton_aesgcm_encrypt_final(ctx, tag);

        printf("/* Test 3: With AAD and plaintext */\n");
        print_hex("aes_gcm_ct3", ct, 64);
        print_hex("aes_gcm_tag3", tag, 16);
    }

    return 0;
}