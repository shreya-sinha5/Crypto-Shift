/**
 * quantum_crypto.h — Post-Quantum Cryptographic API definitions.
 *
 * Implements NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA),
 * FIPS 202 (SHA-3 / SHAKE), and authenticated AES-256-GCM.
 * Replaces legacy classical algorithms (RSA, DH, ECDSA, MD5, SHA-1).
 */

#ifndef QUANTUM_CRYPTO_H
#define QUANTUM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---- ML-KEM-768 Key Encapsulation (FIPS 203) ---- */
#define ML_KEM_768_PUBLIC_KEY_BYTES   1184
#define ML_KEM_768_SECRET_KEY_BYTES   2400
#define ML_KEM_768_CIPHERTEXT_BYTES   1088
#define ML_KEM_768_SHARED_SECRET_BYTES  32

typedef struct ml_kem_context ml_kem_context_t;

int  ml_kem_init(ml_kem_context_t **ctx);
int  ml_kem_keypair(ml_kem_context_t *ctx, uint8_t *public_key, uint8_t *secret_key);
int  ml_kem_encapsulate(const uint8_t *public_key,
                        uint8_t *ciphertext,
                        uint8_t *shared_secret);
int  ml_kem_decapsulate(const uint8_t *secret_key,
                        const uint8_t *ciphertext,
                        uint8_t *shared_secret);
void ml_kem_free(ml_kem_context_t *ctx);

/* ---- ML-DSA-65 Digital Signatures (FIPS 204) ---- */
#define ML_DSA_65_PUBLIC_KEY_BYTES  1952
#define ML_DSA_65_SECRET_KEY_BYTES  4032
#define ML_DSA_65_SIGNATURE_BYTES   3309

typedef struct ml_dsa_context ml_dsa_context_t;

int  ml_dsa_init(ml_dsa_context_t **ctx);
int  ml_dsa_keypair(ml_dsa_context_t *ctx, uint8_t *public_key, uint8_t *secret_key);
int  ml_dsa_sign(const uint8_t *secret_key,
                 const uint8_t *message, size_t message_len,
                 uint8_t *signature, size_t *signature_len);
int  ml_dsa_verify(const uint8_t *public_key,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *signature, size_t signature_len);
void ml_dsa_free(ml_dsa_context_t *ctx);

/* ---- Authenticated AES-256-GCM (Quantum-Resistant Bulk Encryption) ---- */
#define AES_GCM_256_KEY_BYTES  32
#define AES_GCM_IV_BYTES       12
#define AES_GCM_TAG_BYTES      16

typedef struct aes_gcm_context aes_gcm_context_t;

int  aes_gcm_init(aes_gcm_context_t **ctx, const uint8_t *key, size_t key_len);
int  aes_gcm_encrypt(aes_gcm_context_t *ctx,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext,
                     uint8_t *tag, size_t tag_len);
int  aes_gcm_decrypt(aes_gcm_context_t *ctx,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *tag, size_t tag_len,
                     uint8_t *plaintext);
void aes_gcm_free(aes_gcm_context_t *ctx);

/* ---- SHA-3 / SHAKE Hashing (FIPS 202) ---- */
void sha3_256(const uint8_t *data, size_t len, uint8_t digest[32]);
void sha3_512(const uint8_t *data, size_t len, uint8_t digest[64]);
void shake256(const uint8_t *data, size_t len, uint8_t *out, size_t out_len);

/* ---- Hybrid Key Agreement (X25519 + ML-KEM-768 via HKDF) ---- */
typedef struct hybrid_kem_context hybrid_kem_context_t;

int  hybrid_kem_init(hybrid_kem_context_t **ctx);
int  hybrid_kem_generate_keys(hybrid_kem_context_t *ctx,
                              uint8_t *public_blob, size_t *public_blob_len,
                              uint8_t *secret_blob, size_t *secret_blob_len);
int  hybrid_kem_derive_shared(hybrid_kem_context_t *ctx,
                              const uint8_t *peer_public, size_t peer_public_len,
                              uint8_t *shared_secret, size_t *shared_secret_len);
void hybrid_kem_free(hybrid_kem_context_t *ctx);

#endif /* QUANTUM_CRYPTO_H */
