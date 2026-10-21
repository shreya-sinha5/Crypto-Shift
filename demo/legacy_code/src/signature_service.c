/**
 * signature_service.c — Digital signature service using ECDSA and RSA.
 *
 * OpenSSL usage (pre-PQC):
 *   ECDSA_do_sign / ECDSA_do_verify — P-256 ECDSA
 *   RSA_sign / RSA_verify           — RSA-SHA256 PKCS#1 v1.5
 *   EVP_DigestSign                  — unified digest+sign API
 *
 * mbedTLS usage (alternate path):
 *   mbedtls_ecdsa_sign              — ECDSA with P-384
 *   mbedtls_rsa_rsassa_pkcs1_v15_sign
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "legacy_crypto.h"

#define ECDSA_CURVE  NID_X9_62_prime256v1   /* P-256 */
#define SHA256_LEN   32

/* ---- ECDSA P-256 ---- */

typedef struct {
    EC_KEY *key;
} ecdsa_context_t;

int ecdsa_init(ecdsa_context_t **ctx)
{
    ecdsa_context_t *c = calloc(1, sizeof(*c));
    c->key = EC_KEY_new_by_curve_name(ECDSA_CURVE);
    *ctx = c;
    return 0;
}

int ecdsa_gen_keypair(ecdsa_context_t *ctx)
{
    return EC_KEY_generate_key(ctx->key) == 1 ? 0 : -1;
}

int ecdsa_sign(ecdsa_context_t *ctx,
               const uint8_t *hash, size_t hash_len,
               uint8_t *sig,  size_t *sig_len)
{
    ECDSA_SIG *esig = ECDSA_do_sign(hash, (int)hash_len, ctx->key);
    if (!esig) return -1;
    int len = i2d_ECDSA_SIG(esig, &sig);
    *sig_len = (size_t)len;
    ECDSA_SIG_free(esig);
    return 0;
}

int ecdsa_verify(ecdsa_context_t *ctx,
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *sig,  size_t sig_len)
{
    ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &sig, (long)sig_len);
    int ret = ECDSA_do_verify(hash, (int)hash_len, esig, ctx->key);
    ECDSA_SIG_free(esig);
    return ret == 1 ? 0 : -1;
}

void ecdsa_free(ecdsa_context_t *ctx)
{
    if (ctx) {
        EC_KEY_free(ctx->key);
        free(ctx);
    }
}

/* ---- RSA-SHA256 PKCS#1 v1.5 signing ---- */

int rsa_sha256_sign(RSA *rsa_priv,
                    const uint8_t *data, size_t data_len,
                    uint8_t *sig, unsigned int *sig_len)
{
    uint8_t digest[SHA256_LEN];
    SHA256(data, data_len, digest);

    /* RSA_sign uses PKCS#1 v1.5 padding — quantum-vulnerable */
    return RSA_sign(NID_sha256, digest, SHA256_LEN,
                    sig, sig_len, rsa_priv) == 1 ? 0 : -1;
}

int rsa_sha256_verify(RSA *rsa_pub,
                      const uint8_t *data,  size_t data_len,
                      const uint8_t *sig,   unsigned int sig_len)
{
    uint8_t digest[SHA256_LEN];
    SHA256(data, data_len, digest);
    return RSA_verify(NID_sha256, digest, SHA256_LEN,
                      sig, sig_len, rsa_pub) == 1 ? 0 : -1;
}

/* ---- Certificate chain validation (legacy) ---- */

int verify_certificate_rsa(const uint8_t *cert_der, size_t cert_len,
                             RSA *ca_pub_key)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, ca_pub_key);

    const uint8_t *p = cert_der;
    X509 *cert = d2i_X509(NULL, &p, (long)cert_len);
    if (!cert) { EVP_PKEY_free(pkey); return -1; }

    int ret = X509_verify(cert, pkey);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return ret == 1 ? 0 : -1;
}
