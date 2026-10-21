/**
 * legacy_crypto.h — Legacy cryptographic API usage (RSA, AES, EC).
 * This header represents pre-PQC cryptographic patterns common in
 * embedded/systems C code using OpenSSL and mbedTLS.
 */

#ifndef LEGACY_CRYPTO_H
#define LEGACY_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---- RSA key exchange ---- */
typedef struct rsa_context rsa_context_t;

int  rsa_init(rsa_context_t **ctx, int key_bits);
int  rsa_gen_key(rsa_context_t *ctx);
int  rsa_public_encrypt(rsa_context_t *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len);
int  rsa_private_decrypt(rsa_context_t *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t *out_len);
void rsa_free(rsa_context_t *ctx);

/* ---- AES-256-CBC symmetric ---- */
typedef struct aes_context aes_context_t;

int  aes_init(aes_context_t **ctx, const uint8_t *key, size_t key_len);
int  aes_encrypt_cbc(aes_context_t *ctx,
                     const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out);
int  aes_decrypt_cbc(aes_context_t *ctx,
                     const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out);
void aes_free(aes_context_t *ctx);

/* ---- ECDSA P-256 signing ---- */
typedef struct ecdsa_context ecdsa_context_t;

int  ecdsa_init(ecdsa_context_t **ctx);
int  ecdsa_gen_keypair(ecdsa_context_t *ctx);
int  ecdsa_sign(ecdsa_context_t *ctx,
                const uint8_t *hash, size_t hash_len,
                uint8_t *sig,  size_t *sig_len);
int  ecdsa_verify(ecdsa_context_t *ctx,
                  const uint8_t *hash, size_t hash_len,
                  const uint8_t *sig,  size_t sig_len);
void ecdsa_free(ecdsa_context_t *ctx);

/* ---- SHA-256 hashing ---- */
void sha256(const uint8_t *data, size_t len, uint8_t digest[32]);
void sha512(const uint8_t *data, size_t len, uint8_t digest[64]);

/* ---- DH key agreement ---- */
typedef struct dh_context dh_context_t;

int  dh_init(dh_context_t **ctx, int prime_bits);
int  dh_generate_public(dh_context_t *ctx, uint8_t *pub, size_t *pub_len);
int  dh_compute_shared(dh_context_t *ctx,
                       const uint8_t *peer_pub, size_t peer_pub_len,
                       uint8_t *shared, size_t *shared_len);
void dh_free(dh_context_t *ctx);

#endif /* LEGACY_CRYPTO_H */
