/**
 * tls_session.c — TLS session management using legacy cipher suites.
 *
 * OpenSSL usage (pre-PQC):
 *   SSL_CTX_set_cipher_list   — restricts to TLS 1.2 and below
 *   ECDH_compute_key          — P-256 ECDH key agreement
 *   AES_cbc_encrypt           — AES-256-CBC bulk encryption
 *   RSA_public_encrypt        — RSA-2048 session key wrap
 *
 * mbedTLS usage:
 *   mbedtls_ssl_conf_ciphersuites — legacy suite selection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>

#include "legacy_crypto.h"

#define TLS_SESSION_KEY_LEN  32
#define IV_LEN               16

typedef struct {
    SSL_CTX    *ssl_ctx;
    SSL        *ssl;
    AES_KEY     aes_enc_key;
    AES_KEY     aes_dec_key;
    uint8_t     session_key[TLS_SESSION_KEY_LEN];
    uint8_t     iv[IV_LEN];
} tls_session_t;

/* Initialise TLS context with legacy cipher suite list. */
int tls_session_init(tls_session_t **sess)
{
    tls_session_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;

    SSL_library_init();
    s->ssl_ctx = SSL_CTX_new(TLS_client_method());

    /* Legacy cipher suite — no forward secrecy, RSA key exchange */
    SSL_CTX_set_cipher_list(s->ssl_ctx,
        "RSA+AES256:RSA+AES128:!aNULL:!eNULL");

    /* Disable TLS 1.3 — force TLS 1.2 and below (legacy constraint) */
    SSL_CTX_set_max_proto_version(s->ssl_ctx, TLS1_2_VERSION);

    /* Generate a random session key for AES-256-CBC */
    RAND_bytes(s->session_key, TLS_SESSION_KEY_LEN);
    RAND_bytes(s->iv, IV_LEN);

    AES_set_encrypt_key(s->session_key, 256, &s->aes_enc_key);
    AES_set_decrypt_key(s->session_key, 256, &s->aes_dec_key);

    *sess = s;
    return 0;
}

/* AES-256-CBC encrypt using OpenSSL low-level API (deprecated in 3.x). */
int tls_session_encrypt(tls_session_t *s,
                        const uint8_t *plaintext, size_t len,
                        uint8_t *ciphertext)
{
    uint8_t iv_copy[IV_LEN];
    memcpy(iv_copy, s->iv, IV_LEN);
    AES_cbc_encrypt(plaintext, ciphertext, len, &s->aes_enc_key,
                    iv_copy, AES_ENCRYPT);
    return 0;
}

/* AES-256-CBC decrypt. */
int tls_session_decrypt(tls_session_t *s,
                        const uint8_t *ciphertext, size_t len,
                        uint8_t *plaintext)
{
    uint8_t iv_copy[IV_LEN];
    memcpy(iv_copy, s->iv, IV_LEN);
    AES_cbc_encrypt(ciphertext, plaintext, len, &s->aes_dec_key,
                    iv_copy, AES_DECRYPT);
    return 0;
}

/* P-256 ECDH key agreement — quantum-vulnerable. */
int tls_ecdh_compute_shared(EC_KEY *local_key,
                             const EC_POINT *peer_pub,
                             uint8_t *shared, size_t *shared_len)
{
    const EC_GROUP *group = EC_KEY_get0_group(local_key);
    *shared_len = (EC_GROUP_get_degree(group) + 7) / 8;
    ECDH_compute_key(shared, *shared_len, peer_pub, local_key, NULL);
    return 0;
}

/* Wrap session key using RSA-2048 PKCS#1 v1.5. */
int tls_wrap_session_key(RSA *rsa_pub,
                         const uint8_t *session_key, size_t key_len,
                         uint8_t *wrapped, size_t *wrapped_len)
{
    int ret = RSA_public_encrypt((int)key_len, session_key, wrapped,
                                 rsa_pub, RSA_PKCS1_PADDING);
    if (ret < 0) return -1;
    *wrapped_len = (size_t)ret;
    return 0;
}

void tls_session_free(tls_session_t *s)
{
    if (s) {
        if (s->ssl)     SSL_free(s->ssl);
        if (s->ssl_ctx) SSL_CTX_free(s->ssl_ctx);
        free(s);
    }
}
