/**
 * hash_utils.c — Hashing utilities (SHA-1, SHA-256, MD5 legacy usage).
 *
 * This file demonstrates weak hash usages:
 *   MD5   — broken (collision attacks), legacy file checksums
 *   SHA-1 — deprecated for signatures, still in HMAC-SHA1 MACs
 *   SHA-256, SHA-512 — still safe but detected for inventory purposes
 *
 * Detected patterns (OpenSSL):
 *   MD5_Init / MD5_Update / MD5_Final
 *   SHA1_Init / SHA1_Update / SHA1_Final
 *   EVP_md5() / EVP_sha1()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "legacy_crypto.h"

/* MD5 — legacy file integrity check (NOT security-grade). */
int md5_hash(const uint8_t *data, size_t len, uint8_t digest[16])
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(digest, &ctx);
    return 0;
}

/* SHA-1 — deprecated for signatures, present in legacy HMAC-SHA1. */
int sha1_hash(const uint8_t *data, size_t len, uint8_t digest[20])
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(digest, &ctx);
    return 0;
}

/* SHA-256. */
void sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(digest, &ctx);
}

/* SHA-512. */
void sha512(const uint8_t *data, size_t len, uint8_t digest[64])
{
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, data, len);
    SHA512_Final(digest, &ctx);
}

/* HMAC-SHA1 — legacy MAC used in older TLS/WPA2. */
int hmac_sha1(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len,
              uint8_t *mac, unsigned int *mac_len)
{
    HMAC(EVP_sha1(), key, (int)key_len, data, data_len, mac, mac_len);
    return 0;
}

/* HMAC-MD5 — even weaker, found in legacy RADIUS/SNMP. */
int hmac_md5(const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len,
             uint8_t *mac, unsigned int *mac_len)
{
    HMAC(EVP_md5(), key, (int)key_len, data, data_len, mac, mac_len);
    return 0;
}

/* EVP-based generic digest (detects EVP_md5, EVP_sha1 by algorithm name). */
int evp_hash(const char *algo_name,
             const uint8_t *data, size_t len,
             uint8_t *out, unsigned int *out_len)
{
    const EVP_MD *md = EVP_get_digestbyname(algo_name);
    if (!md) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, out_len);
    EVP_MD_CTX_free(ctx);
    return 0;
}
