// KpCrypto backend for portduino (host builds and native tests): OpenSSL 3 EVP. Kept in its own translation unit because
// <openssl/sha.h> declares a function SHA256 that collides with the rweather class used by KpCrypto.cpp.
#include "KpCryptoBackend.h"

#if (defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)) && defined(KP_CRYPTO_BACKEND_OPENSSL)

#include <limits.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>

namespace kpcrypto
{
namespace backend
{
namespace
{
const char *const CURVE = "prime256v1";

// Public-only (priv == nullptr) or full key; pub must be a 65-byte uncompressed point.
EVP_PKEY *makeKey(const uint8_t *priv, const uint8_t *pub)
{
    EVP_PKEY *pkey = nullptr;
    BIGNUM *d = nullptr;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    bool ok = bld && ctx && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, CURVE, 0) &&
              OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, P256_PUBKEY_LEN);
    if (ok && priv) {
        d = BN_secure_new();
        ok = d && BN_bin2bn(priv, P256_SCALAR_LEN, d) && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d);
    }
    if (ok)
        ok = (params = OSSL_PARAM_BLD_to_param(bld)) != nullptr;
    if (ok)
        ok = EVP_PKEY_fromdata_init(ctx) == 1 &&
             EVP_PKEY_fromdata(ctx, &pkey, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) == 1;
    OSSL_PARAM_free(params); // secure-heap part (the private BN) is cleared by OpenSSL
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(d);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    return pkey;
}

// pub = priv * G (uncompressed).
bool derivePublic(const uint8_t *priv, uint8_t *pub)
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point = group ? EC_POINT_new(group) : nullptr;
    BIGNUM *d = BN_secure_new();
    bool ok = point && d && BN_bin2bn(priv, P256_SCALAR_LEN, d) &&
              EC_POINT_mul(group, point, d, nullptr, nullptr, nullptr) == 1 &&
              EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pub, P256_PUBKEY_LEN, nullptr) == P256_PUBKEY_LEN;
    BN_clear_free(d);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return ok;
}

EVP_PKEY *makePrivateKey(const uint8_t *priv)
{
    uint8_t pub[P256_PUBKEY_LEN];
    if (!derivePublic(priv, pub))
        return nullptr;
    return makeKey(priv, pub);
}
} // namespace

bool publicKeyOnCurve(const uint8_t pub[P256_PUBKEY_LEN])
{
    EVP_PKEY *pkey = makeKey(nullptr, pub); // decoding already rejects points off the curve
    if (!pkey)
        return false;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    bool ok = ctx && EVP_PKEY_public_check(ctx) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

bool generateKeyPair(uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_PUBKEY_LEN])
{
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", CURVE);
    if (!pkey)
        return false;
    BIGNUM *d = nullptr;
    size_t pubLen = 0;
    bool ok = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d) == 1 &&
              BN_bn2binpad(d, priv, P256_SCALAR_LEN) == (int)P256_SCALAR_LEN &&
              EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, P256_PUBKEY_LEN, &pubLen) == 1 &&
              pubLen == P256_PUBKEY_LEN && pub[0] == 0x04;
    BN_clear_free(d);
    EVP_PKEY_free(pkey);
    return ok;
}

bool verifyDigest(const uint8_t pub[P256_PUBKEY_LEN], const uint8_t digest[SHA256_LEN], const uint8_t sig[P256_SIG_LEN])
{
    EVP_PKEY *pkey = makeKey(nullptr, pub);
    if (!pkey)
        return false;
    ECDSA_SIG *es = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, 32, nullptr);
    BIGNUM *s = BN_bin2bn(sig + 32, 32, nullptr);
    unsigned char *der = nullptr;
    int derLen = -1;
    if (es && r && s && ECDSA_SIG_set0(es, r, s) == 1) {
        r = s = nullptr; // owned by es
        derLen = i2d_ECDSA_SIG(es, &der);
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    bool ok = derLen > 0 && ctx && EVP_PKEY_verify_init(ctx) == 1 && EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1 &&
              EVP_PKEY_verify(ctx, der, (size_t)derLen, digest, SHA256_LEN) == 1;
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(der);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(es);
    EVP_PKEY_free(pkey);
    return ok;
}

bool blindingRandom(uint8_t *dest, unsigned size)
{
    return size <= INT_MAX && RAND_bytes(dest, (int)size) == 1;
}

// Same signer as the device (vendored micro-ecc); OpenSSL verifying against the caller's public key is the independent check.
bool signDigest(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_PUBKEY_LEN], const uint8_t digest[SHA256_LEN],
                uecc::RngFn rng, uint8_t sig[P256_SIG_LEN])
{
    return uecc::signDigest(priv, digest, sig, rng) && verifyDigest(pub, digest, sig);
}

bool ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t peerPub[P256_PUBKEY_LEN], uint8_t secret[ECDH_SECRET_LEN])
{
    EVP_PKEY *own = makePrivateKey(priv);
    EVP_PKEY *peer = makeKey(nullptr, peerPub);
    EVP_PKEY_CTX *ctx = own ? EVP_PKEY_CTX_new_from_pkey(nullptr, own, nullptr) : nullptr;
    size_t len = ECDH_SECRET_LEN;
    bool ok = peer && ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
              EVP_PKEY_derive(ctx, secret, &len) == 1 && len == ECDH_SECRET_LEN;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(own);
    return ok;
}

bool ccmEncrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                const uint8_t *pt, size_t ptLen, uint8_t *ct, uint8_t tag[CCM_TAG_LEN], uint8_t *, size_t)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0;
    uint8_t empty = 0;
    if (ptLen == 0)
        ct = &empty; // a null output pointer would make OpenSSL treat the text update as AAD
    // CCM order: IV/tag lengths, key+nonce, total text length, AAD, text in one call.
    bool ok = c && EVP_EncryptInit_ex(c, EVP_aes_128_ccm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, CCM_NONCE_LEN, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, CCM_TAG_LEN, nullptr) == 1 &&
              EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce) == 1 &&
              EVP_EncryptUpdate(c, nullptr, &n, nullptr, (int)ptLen) == 1 &&
              (aadLen == 0 || EVP_EncryptUpdate(c, nullptr, &n, aad, (int)aadLen) == 1) &&
              EVP_EncryptUpdate(c, ct, &n, pt, (int)ptLen) == 1 && (size_t)n == ptLen &&
              EVP_EncryptFinal_ex(c, ct + n, &n) == 1 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, CCM_TAG_LEN, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

bool ccmDecrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                const uint8_t *ct, size_t ctLen, const uint8_t tag[CCM_TAG_LEN], uint8_t *pt, uint8_t *, size_t)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0;
    uint8_t tagCopy[CCM_TAG_LEN];
    for (size_t i = 0; i < CCM_TAG_LEN; ++i)
        tagCopy[i] = tag[i];
    uint8_t empty = 0;
    if (ctLen == 0) {
        ct = &empty; // a null output pointer would make OpenSSL treat the text update as AAD and skip the tag check
        pt = &empty;
    }
    // For CCM the tag is checked by the text update; there is no separate Final step.
    bool ok = c && EVP_DecryptInit_ex(c, EVP_aes_128_ccm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, CCM_NONCE_LEN, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, CCM_TAG_LEN, tagCopy) == 1 &&
              EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) == 1 &&
              EVP_DecryptUpdate(c, nullptr, &n, nullptr, (int)ctLen) == 1 &&
              (aadLen == 0 || EVP_DecryptUpdate(c, nullptr, &n, aad, (int)aadLen) == 1) &&
              EVP_DecryptUpdate(c, pt, &n, ct, (int)ctLen) == 1 && (size_t)n == ctLen;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

} // namespace backend
} // namespace kpcrypto

#endif
