/**
 * key_service.c — RSA-2048 key generation and key exchange service.
 *
 * OpenSSL usage (pre-PQC):
 *   RSA_generate_key_ex  — 2048-bit RSA key generation
 *   EVP_PKEY_encrypt      — PKCS#1 v1.5 encryption
 *   EVP_PKEY_decrypt      — PKCS#1 v1.5 decryption
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "legacy_crypto.h"

#define RSA_KEY_BITS    2048
#define RSA_EXPONENT    65537

typedef struct {
    EVP_PKEY *pkey;
} rsa_context_t;

/* Allocate and generate an RSA-2048 key pair. */
int rsa_init(rsa_context_t **ctx, int key_bits)
{
    if (!ctx) return -1;

    rsa_context_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;

    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_EXPONENT);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, key_bits > 0 ? key_bits : RSA_KEY_BITS);
    EVP_PKEY_CTX_set_rsa_keygen_pubexp(kctx, e);
    EVP_PKEY_keygen(kctx, &c->pkey);

    EVP_PKEY_CTX_free(kctx);
    BN_free(e);

    *ctx = c;
    return 0;
}

int rsa_gen_key(rsa_context_t *ctx)
{
    (void)ctx;
    return 0;
}

/* PKCS#1 v1.5 public-key encryption — NOT OAEP, legacy pattern. */
int rsa_public_encrypt(rsa_context_t *ctx,
                       const uint8_t *in,  size_t in_len,
                       uint8_t *out, size_t *out_len)
{
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(ctx->pkey, NULL);
    EVP_PKEY_encrypt_init(ectx);
    /* Legacy: RSA_PKCS1_PADDING — vulnerable to padding oracle (Bleichenbacher) */
    EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_PADDING);
    EVP_PKEY_encrypt(ectx, out, out_len, in, in_len);
    EVP_PKEY_CTX_free(ectx);
    return 0;
}

/* PKCS#1 v1.5 private-key decryption. */
int rsa_private_decrypt(rsa_context_t *ctx,
                        const uint8_t *in,  size_t in_len,
                        uint8_t *out, size_t *out_len)
{
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(ctx->pkey, NULL);
    EVP_PKEY_decrypt_init(ectx);
    EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_PADDING);
    EVP_PKEY_decrypt(ectx, out, out_len, in, in_len);
    EVP_PKEY_CTX_free(ectx);
    return 0;
}

void rsa_free(rsa_context_t *ctx)
{
    if (ctx) {
        EVP_PKEY_free(ctx->pkey);
        free(ctx);
    }
}

/* Serialize RSA public key to PEM. */
int rsa_export_public_pem(rsa_context_t *ctx, char *buf, size_t buf_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, ctx->pkey);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    if (bptr->length < buf_len) {
        memcpy(buf, bptr->data, bptr->length);
        buf[bptr->length] = '\0';
    }
    BIO_free(bio);
    return 0;
}

/* Demonstration: sign data with RSA-SHA256 (PKCS#1 v1.5). */
int rsa_sign_sha256(rsa_context_t *ctx,
                    const uint8_t *data, size_t data_len,
                    uint8_t *sig,  size_t *sig_len)
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, ctx->pkey);
    EVP_DigestSignUpdate(mctx, data, data_len);
    EVP_DigestSignFinal(mctx, sig, sig_len);
    EVP_MD_CTX_free(mctx);
    return 0;
}
