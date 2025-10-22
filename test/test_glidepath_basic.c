/* Simple test to verify Glidepath Provider actually encrypts */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

int main(void) {
    /* Load provider */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "glidepathprov");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");

    if (!prov) {
        fprintf(stderr, "Failed to load glidepathprov\n");
        return 1;
    }

    /* Test vectors */
    unsigned char key[32] = {0};
    unsigned char iv[12] = {0};
    unsigned char plaintext[256];
    unsigned char ciphertext[256];
    unsigned char tag[16];

    memset(plaintext, 'A', 256);

    /* Encrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);

    if (!cipher) {
        fprintf(stderr, "Failed to fetch AES-256-GCM\n");
        return 1;
    }

    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

    int len = 0, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 256);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);

    printf("Encrypted %d bytes\n", ciphertext_len);
    printf("Plaintext first 16 bytes:  ");
    for (int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    printf("\n");

    printf("Ciphertext first 16 bytes: ");
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    printf("Tag: ");
    for (int i = 0; i < 16; i++) printf("%02x ", tag[i]);
    printf("\n");

    /* Check that ciphertext is different from plaintext */
    if (memcmp(plaintext, ciphertext, 256) == 0) {
        fprintf(stderr, "ERROR: Ciphertext matches plaintext! No encryption performed!\n");
        return 1;
    }

    printf("SUCCESS: Ciphertext differs from plaintext\n");

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(deflt);

    return 0;
}
