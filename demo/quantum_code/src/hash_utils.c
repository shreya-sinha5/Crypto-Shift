/**
 * hash_utils.c — Modern Post-Quantum Hash Utilities (SHA-3 / SHAKE).
 *
 * Replaces broken MD5 and deprecated SHA-1 with NIST FIPS 202 standards:
 *   SHA3-256 / SHA3-512 (sponge construction, quantum collision-resistant)
 *   SHAKE-256 (extensible-output function XOF)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "quantum_crypto.h"

/* NIST FIPS 202 SHA3-256 */
void sha3_256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha3_256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, digest, NULL);

    EVP_MD_CTX_free(mdctx);
}

/* NIST FIPS 202 SHA3-512 */
void sha3_512(const uint8_t *data, size_t len, uint8_t digest[64])
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha3_512();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, digest, NULL);

    EVP_MD_CTX_free(mdctx);
}

/* NIST FIPS 202 SHAKE-256 Extensible Output Function */
void shake256(const uint8_t *data, size_t len, uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_shake256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinalXOF(mdctx, out, out_len);

    EVP_MD_CTX_free(mdctx);
}
