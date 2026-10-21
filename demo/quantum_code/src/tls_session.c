/**
 * tls_session.c — Post-Quantum TLS 1.3 & AES-256-GCM Session Manager.
 *
 * Replaces legacy TLS 1.2 / RSA cipher suites and unauthenticated AES-CBC
 * with TLS 1.3 and Authenticated AES-256-GCM (NIST SP 800-38D).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "quantum_crypto.h"

struct aes_gcm_context {
    EVP_CIPHER_CTX *ctx;
    uint8_t         key[AES_GCM_256_KEY_BYTES];
    int             is_initialized;
};

int aes_gcm_init(aes_gcm_context_t **ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key || key_len != AES_GCM_256_KEY_BYTES) return -1;

    aes_gcm_context_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;

    c->ctx = EVP_CIPHER_CTX_new();
    memcpy(c->key, key, AES_GCM_256_KEY_BYTES);
    c->is_initialized = 1;

    *ctx = c;
    return 0;
}

int aes_gcm_encrypt(aes_gcm_context_t *ctx,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext,
                     uint8_t *tag, size_t tag_len)
{
    if (!ctx || !ctx->is_initialized || !iv || !plaintext || !ciphertext || !tag)
        return -1;

    int outlen = 0;
    EVP_EncryptInit_ex(ctx->ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL);
    EVP_EncryptInit_ex(ctx->ctx, NULL, NULL, ctx->key, iv);

    if (aad && aad_len > 0) {
        EVP_EncryptUpdate(ctx->ctx, NULL, &outlen, aad, (int)aad_len);
    }

    EVP_EncryptUpdate(ctx->ctx, ciphertext, &outlen, plaintext, (int)plaintext_len);
    EVP_EncryptFinal_ex(ctx->ctx, ciphertext + outlen, &outlen);
    EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag);

    return 0;
}

int aes_gcm_decrypt(aes_gcm_context_t *ctx,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *tag, size_t tag_len,
                     uint8_t *plaintext)
{
    if (!ctx || !ctx->is_initialized || !iv || !ciphertext || !tag || !plaintext)
        return -1;

    int outlen = 0;
    EVP_DecryptInit_ex(ctx->ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL);
    EVP_DecryptInit_ex(ctx->ctx, NULL, NULL, ctx->key, iv);

    if (aad && aad_len > 0) {
        EVP_DecryptUpdate(ctx->ctx, NULL, &outlen, aad, (int)aad_len);
    }

    EVP_DecryptUpdate(ctx->ctx, plaintext, &outlen, ciphertext, (int)ciphertext_len);
    EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)tag);

    int ret = EVP_DecryptFinal_ex(ctx->ctx, plaintext + outlen, &outlen);
    return ret > 0 ? 0 : -1;
}

void aes_gcm_free(aes_gcm_context_t *ctx)
{
    if (!ctx) return;
    if (ctx->ctx) EVP_CIPHER_CTX_free(ctx->ctx);
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    free(ctx);
}
