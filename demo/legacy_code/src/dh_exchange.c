/**
 * dh_exchange.c — Diffie-Hellman key exchange (classic and ECDH).
 *
 * OpenSSL usage (pre-PQC):
 *   DH_generate_parameters_ex — 2048-bit MODP group generation
 *   DH_generate_key            — DH keypair
 *   DH_compute_key             — shared secret derivation
 *   ECDH_compute_key           — P-521 ECDH
 *
 * These are quantum-vulnerable: Shor's algorithm breaks both DH and ECDH.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "legacy_crypto.h"

#define DH_PRIME_BITS     2048
#define ECDH_CURVE_P521   NID_secp521r1

typedef struct {
    DH *dh;
} dh_context_t;

/* Classic DH (MODP-2048). */
int dh_init(dh_context_t **ctx, int prime_bits)
{
    dh_context_t *c = calloc(1, sizeof(*c));
    c->dh = DH_new();

    DH_generate_parameters_ex(c->dh,
                              prime_bits > 0 ? prime_bits : DH_PRIME_BITS,
                              DH_GENERATOR_2, NULL);
    DH_generate_key(c->dh);

    *ctx = c;
    return 0;
}

int dh_generate_public(dh_context_t *ctx, uint8_t *pub, size_t *pub_len)
{
    const BIGNUM *pub_key;
    DH_get0_key(ctx->dh, &pub_key, NULL);
    *pub_len = (size_t)BN_bn2bin(pub_key, pub);
    return 0;
}

int dh_compute_shared(dh_context_t *ctx,
                      const uint8_t *peer_pub, size_t peer_pub_len,
                      uint8_t *shared, size_t *shared_len)
{
    BIGNUM *peer = BN_bin2bn(peer_pub, (int)peer_pub_len, NULL);
    *shared_len = (size_t)DH_size(ctx->dh);
    DH_compute_key(shared, peer, ctx->dh);
    BN_free(peer);
    return 0;
}

void dh_free(dh_context_t *ctx)
{
    if (ctx) {
        DH_free(ctx->dh);
        free(ctx);
    }
}

/* ECDH P-521 key agreement. */
int ecdh_p521_compute_shared(const uint8_t *peer_pub_der, size_t peer_pub_len,
                              uint8_t *shared, size_t *shared_len)
{
    EC_KEY *local = EC_KEY_new_by_curve_name(ECDH_CURVE_P521);
    EC_KEY_generate_key(local);

    const EC_GROUP *group = EC_KEY_get0_group(local);
    EC_POINT *peer_pt = EC_POINT_new(group);

    EC_POINT_oct2point(group, peer_pt, peer_pub_der, peer_pub_len, NULL);

    *shared_len = (EC_GROUP_get_degree(group) + 7) / 8;
    ECDH_compute_key(shared, *shared_len, peer_pt, local, NULL);

    EC_POINT_free(peer_pt);
    EC_KEY_free(local);
    return 0;
}

/* HKDF key derivation from DH shared secret (SHA-256 based). */
int hkdf_from_dh_shared(const uint8_t *shared, size_t shared_len,
                          const uint8_t *salt,   size_t salt_len,
                          const uint8_t *info,   size_t info_len,
                          uint8_t *okm, size_t okm_len)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(kctx);
    EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(kctx, salt, (int)salt_len);
    EVP_PKEY_CTX_set1_hkdf_key(kctx, shared, (int)shared_len);
    EVP_PKEY_CTX_add1_hkdf_info(kctx, info, (int)info_len);
    EVP_PKEY_derive(kctx, okm, &okm_len);
    EVP_PKEY_CTX_free(kctx);
    return 0;
}
