#include "KpCrypto.h"

#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)

#include "KpCryptoBackend.h"
#include "KpUeccConfig.h"
#include "security/SecureZero.h"
#include <SHA256.h>
#include <new>
#include <string.h>

namespace kpcrypto
{
namespace
{
// P-256 field prime p and group order n, big-endian.
const uint8_t P256_P[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t P256_N[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

// a < b for 32-byte big-endian values, without data-dependent branches (scalars are secret).
bool lessThan32(const uint8_t *a, const uint8_t *b)
{
    uint32_t borrow = 0;
    for (int i = 31; i >= 0; --i) {
        uint32_t d = (uint32_t)a[i] - (uint32_t)b[i] - borrow;
        borrow = (d >> 8) & 1;
    }
    return borrow != 0;
}

bool isZero(const uint8_t *a, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i)
        acc |= a[i];
    return acc == 0;
}

// In [1, n-1].
bool inScalarRange(const uint8_t *v)
{
    return !isZero(v, 32) && lessThan32(v, P256_N);
}

SHA256 &sha(uint8_t *state)
{
    return *reinterpret_cast<SHA256 *>(state);
}
} // namespace

void secureWipe(void *p, size_t n)
{
    meshtastic_security::secure_zero(p, n);
}

bool constantTimeEqual(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *x = static_cast<const volatile uint8_t *>(a);
    const volatile uint8_t *y = static_cast<const volatile uint8_t *>(b);
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i)
        d |= x[i] ^ y[i];
    return d == 0;
}

Sha256::Sha256()
{
    static_assert(sizeof(SHA256) <= sizeof(state_), "Sha256 state buffer too small");
    static_assert(alignof(SHA256) <= 8, "Sha256 state buffer misaligned");
    new (state_) SHA256();
}

Sha256::~Sha256()
{
    sha(state_).clear();
    sha(state_).~SHA256();
    secureWipe(state_, sizeof(state_));
}

void Sha256::update(const void *data, size_t len)
{
    sha(state_).update(data, len);
}

void Sha256::finish(uint8_t out[SHA256_LEN])
{
    sha(state_).finalize(out, SHA256_LEN);
    sha(state_).clear();
}

void sha256(const void *data, size_t len, uint8_t out[SHA256_LEN])
{
    Sha256 h;
    h.update(data, len);
    h.finish(out);
}

void hmacSha256(const uint8_t *key, size_t keyLen, const void *data, size_t dataLen, uint8_t out[SHA256_LEN])
{
    SHA256 h;
    h.resetHMAC(key, keyLen);
    h.update(data, dataLen);
    h.finalizeHMAC(key, keyLen, out, SHA256_LEN);
    h.clear();
}

void hkdfExtract(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen, uint8_t prk[SHA256_LEN])
{
    static const uint8_t zeroSalt[SHA256_LEN] = {0};
    if (saltLen == 0) {
        salt = zeroSalt;
        saltLen = sizeof(zeroSalt);
    }
    hmacSha256(salt, saltLen, ikm, ikmLen, prk);
}

bool hkdfExpand(const uint8_t prk[SHA256_LEN], const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen)
{
    if (!prk || !out || outLen == 0 || outLen > HKDF_MAX_OKM || (infoLen && !info))
        return false;
    uint8_t t[SHA256_LEN];
    size_t tLen = 0, done = 0;
    for (uint8_t counter = 1; done < outLen; ++counter) {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        SHA256 h;
        h.resetHMAC(prk, SHA256_LEN);
        h.update(t, tLen);
        h.update(info, infoLen);
        h.update(&counter, 1);
        h.finalizeHMAC(prk, SHA256_LEN, t, SHA256_LEN);
        h.clear();
        tLen = SHA256_LEN;
        size_t n = outLen - done < SHA256_LEN ? outLen - done : SHA256_LEN;
        memcpy(out + done, t, n);
        done += n;
    }
    secureWipe(t, sizeof(t));
    return true;
}

bool p256PointEncodingValid(const uint8_t *pub, size_t pubLen)
{
    if (!pub || pubLen != P256_PUBKEY_LEN || pub[0] != 0x04)
        return false;
    return lessThan32(pub + 1, P256_P) && lessThan32(pub + 33, P256_P);
}

bool p256SignatureScalarsValid(const uint8_t sig[P256_SIG_LEN])
{
    return sig && inScalarRange(sig) && inScalarRange(sig + 32);
}

bool p256PublicKeyValid(const uint8_t *pub, size_t pubLen)
{
    return p256PointEncodingValid(pub, pubLen) && backend::publicKeyOnCurve(pub);
}

bool p256PrivateKeyValid(const uint8_t priv[P256_SCALAR_LEN])
{
    return priv && inScalarRange(priv);
}

bool p256GenerateKeyPair(uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_PUBKEY_LEN])
{
    if (!priv || !pub)
        return false;
    if (backend::generateKeyPair(priv, pub) && p256PrivateKeyValid(priv) && p256PublicKeyValid(pub, P256_PUBKEY_LEN))
        return true;
    secureWipe(priv, P256_SCALAR_LEN);
    secureWipe(pub, P256_PUBKEY_LEN);
    return false;
}

bool ecdsaVerify(const uint8_t pub[P256_PUBKEY_LEN], const void *msg, size_t msgLen, const uint8_t sig[P256_SIG_LEN])
{
    if (!p256SignatureScalarsValid(sig) || (msgLen && !msg))
        return false;
    if (!p256PublicKeyValid(pub, P256_PUBKEY_LEN))
        return false;
    uint8_t digest[SHA256_LEN];
    sha256(msg, msgLen, digest);
    return backend::verifyDigest(pub, digest, sig);
}

bool p256KeyPairMatches(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_PUBKEY_LEN])
{
    if (!p256PrivateKeyValid(priv) || !p256PublicKeyValid(pub, P256_PUBKEY_LEN))
        return false;
    uint8_t derived[P256_PUBKEY_LEN];
    bool ok = uecc::publicKey(priv, derived) && constantTimeEqual(derived, pub, P256_PUBKEY_LEN);
    secureWipe(derived, sizeof(derived));
    return ok;
}

bool ecdsaSign(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_PUBKEY_LEN], const void *msg, size_t msgLen,
               uint8_t sig[P256_SIG_LEN])
{
    if (!sig)
        return false;
    bool ok = false;
    // Encoding check only: pub was fully validated by p256KeyPairMatches() at load, and the backend verify rejects the rest.
    if (p256PrivateKeyValid(priv) && p256PointEncodingValid(pub, P256_PUBKEY_LEN) && (msg || msgLen == 0)) {
        uint8_t digest[SHA256_LEN];
        sha256(msg, msgLen, digest);
        uecc::RngFn rng = &backend::blindingRandom;
#if defined(PIO_UNIT_TESTING)
        if (testing::blindingRngOverride)
            rng = testing::blindingRngOverride;
#endif
        ok = backend::signDigest(priv, pub, digest, rng, sig) && p256SignatureScalarsValid(sig);
    }
    if (!ok)
        secureWipe(sig, P256_SIG_LEN);
    return ok;
}

bool selfTest()
{
    static const uint8_t X[P256_SCALAR_LEN] = {0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
                                               0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
                                               0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};
    static const uint8_t U[P256_PUBKEY_LEN] = {0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74,
                                               0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6,
                                               0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8,
                                               0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2,
                                               0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
    static const uint8_t RS[P256_SIG_LEN] = {0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4,
                                             0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d,
                                             0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c,
                                             0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb,
                                             0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8};
    uint8_t sig[P256_SIG_LEN];
    bool ok = p256KeyPairMatches(X, U) && ecdsaSign(X, U, "sample", 6, sig) && constantTimeEqual(sig, RS, sizeof(RS));
    if (!ok)
        LOG_ERROR("KpCrypto self-test (RFC 6979 A.2.5) failed");
    return ok;
}

bool ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t peerPub[P256_PUBKEY_LEN], uint8_t secret[ECDH_SECRET_LEN])
{
    if (!secret)
        return false;
    bool ok = p256PrivateKeyValid(priv) && p256PublicKeyValid(peerPub, P256_PUBKEY_LEN) && backend::ecdh(priv, peerPub, secret) &&
              !isZero(secret, ECDH_SECRET_LEN);
    if (!ok)
        secureWipe(secret, ECDH_SECRET_LEN);
    return ok;
}

namespace
{
// buf == nullptr: one-shot call. Otherwise a CcmStream buffer of bufLen bytes; oversize requests fail.
bool ccmEncryptWith(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aadLen, const uint8_t *pt, size_t ptLen,
                    uint8_t *out, uint8_t *buf, size_t bufLen)
{
    if (!key || !nonce || !out || (aadLen && !aad) || (ptLen && !pt))
        return false;
    bool fits = !buf || (aadLen <= CCM_STREAM_MAX_AAD && ptLen <= CCM_STREAM_MAX_TEXT && aadLen + ptLen <= bufLen);
    if (fits && backend::ccmEncrypt(key, nonce, aad, aadLen, pt, ptLen, out, out + ptLen, buf, bufLen))
        return true;
    secureWipe(out, ptLen + CCM_TAG_LEN);
    return false;
}

bool ccmDecryptWith(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aadLen, const uint8_t *in, size_t inLen,
                    uint8_t *out, uint8_t *buf, size_t bufLen)
{
    if (!key || !nonce || !in || inLen < CCM_TAG_LEN || (aadLen && !aad))
        return false;
    size_t ctLen = inLen - CCM_TAG_LEN;
    if (ctLen && !out)
        return false;
    bool fits = !buf || (aadLen <= CCM_STREAM_MAX_AAD && ctLen <= CCM_STREAM_MAX_TEXT && aadLen + ctLen <= bufLen);
    bool ok = false;
#if defined(PIO_UNIT_TESTING)
    if (testing::ccmDecryptOverride)
        ok = fits && testing::ccmDecryptOverride(key, nonce, aad, aadLen, in, ctLen, in + ctLen, out);
    else
#endif
        ok = fits && backend::ccmDecrypt(key, nonce, aad, aadLen, in, ctLen, in + ctLen, out, buf, bufLen);
    if (!ok && ctLen)
        secureWipe(out, ctLen);
    return ok;
}
} // namespace

bool aes128CcmEncrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                      const uint8_t *pt, size_t ptLen, uint8_t *out)
{
    return ccmEncryptWith(key, nonce, aad, aadLen, pt, ptLen, out, nullptr, 0);
}

bool aes128CcmDecrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                      const uint8_t *in, size_t inLen, uint8_t *out)
{
    return ccmDecryptWith(key, nonce, aad, aadLen, in, inLen, out, nullptr, 0);
}

CcmStream::CcmStream(const uint8_t key[AES128_KEY_LEN])
{
    memcpy(key_, key, sizeof(key_));
    memset(buf_, 0, sizeof(buf_));
}

CcmStream::~CcmStream()
{
    secureWipe(key_, sizeof(key_));
    secureWipe(buf_, sizeof(buf_));
}

bool CcmStream::encrypt(const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen, const uint8_t *pt, size_t ptLen,
                        uint8_t *out)
{
    return ccmEncryptWith(key_, nonce, aad, aadLen, pt, ptLen, out, buf_, sizeof(buf_));
}

bool CcmStream::decrypt(const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen, const uint8_t *in, size_t inLen,
                        uint8_t *out)
{
    return ccmDecryptWith(key_, nonce, aad, aadLen, in, inLen, out, buf_, sizeof(buf_));
}

#if defined(PIO_UNIT_TESTING)
testing::CcmDecryptFn testing::ccmDecryptOverride = nullptr;
uecc::RngFn testing::blindingRngOverride = nullptr;
unsigned testing::ueccBlindingCalls = 0;
#endif

namespace
{
// uECC_HashContext backed by the rweather SHA-256. Standard layout, so the cast back from &base is valid.
struct UeccSha256 {
    uECC_HashContext base;
    SHA256 *sha;
};

SHA256 &ueccSha(const uECC_HashContext *c)
{
    return *reinterpret_cast<const UeccSha256 *>(c)->sha;
}

void ueccInit(const uECC_HashContext *c)
{
    ueccSha(c).reset();
}

void ueccUpdate(const uECC_HashContext *c, const uint8_t *msg, unsigned len)
{
    ueccSha(c).update(msg, len);
}

// Blinding RNG of the signature in progress (cryptLock serialises signers on nRF52); a failure latches until the next one.
uecc::RngFn ueccRng = nullptr;
bool ueccRngFailed = false;

int ueccLatchedRng(uint8_t *dest, unsigned size)
{
#if defined(PIO_UNIT_TESTING)
    ++testing::ueccBlindingCalls;
#endif
    if (!ueccRngFailed && ueccRng && ueccRng(dest, size))
        return 1;
    ueccRngFailed = true;
    return 0;
}

void ueccFinish(const uECC_HashContext *c, uint8_t *out)
{
    ueccSha(c).finalize(out, SHA256_LEN);
    // After an RNG failure every further RFC 6979 candidate becomes k = 0, which uECC rejects before the scalar mult.
    if (ueccRngFailed)
        secureWipe(out, SHA256_LEN);
}
// Neither inlined nor IPA-cloned, even under LTO: the secret frames must sit below the caller's, where scrubStack() reaches.
#if defined(__has_attribute)
#if __has_attribute(noipa)
#define KP_OWN_FRAME __attribute__((noinline, noipa))
#endif
#endif
#ifndef KP_OWN_FRAME
#define KP_OWN_FRAME __attribute__((noinline))
#endif

// micro-ecc leaves k, the native private key and point coordinates on the stack; scrubStack() from the helper's caller
// overwrites them. X1 LTO -Os deepest chain: ueccSign 600 + EccPoint_mult 232 + XYcZ_addC 136 + modMult 148 = 1116 B.
constexpr size_t UECC_STACK_SCRUB = 1536;

KP_OWN_FRAME void scrubStack()
{
    volatile uint8_t area[UECC_STACK_SCRUB];
    for (size_t i = 0; i < sizeof(area); ++i)
        area[i] = 0;
}

KP_OWN_FRAME bool ueccSign(const uint8_t *priv, const uint8_t *digest, uint8_t *sig)
{
    SHA256 sha;
    uint8_t tmp[2 * SHA256_LEN + SHA256::BLOCK_SIZE]; // HMAC-DRBG K and V plus one block, as uECC requires
    UeccSha256 ctx = {{&ueccInit, &ueccUpdate, &ueccFinish, SHA256::BLOCK_SIZE, SHA256_LEN, tmp}, &sha};
    bool ok = uECC_sign_deterministic(priv, digest, SHA256_LEN, &ctx.base, sig, uECC_secp256r1()) == 1;
    secureWipe(tmp, sizeof(tmp));
    sha.clear();
    return ok;
}

KP_OWN_FRAME bool ueccPublicKey(const uint8_t *priv, uint8_t *pubXY)
{
    return uECC_compute_public_key(priv, pubXY, uECC_secp256r1()) == 1;
}
} // namespace

bool uecc::signDigest(const uint8_t priv[P256_SCALAR_LEN], const uint8_t digest[SHA256_LEN], uint8_t sig[P256_SIG_LEN], RngFn rng)
{
    bool ok = false;
    if (rng) { // probe once: a dead RNG fails before any scalar multiplication
        uint8_t probe[P256_SCALAR_LEN];
        ok = rng(probe, sizeof(probe));
        secureWipe(probe, sizeof(probe));
    }
    if (ok) {
        ueccRng = rng;
        ueccRngFailed = false;
        uECC_set_rng(&ueccLatchedRng);
        // A later candidate after a failed RNG call would be a valid but non-RFC-6979 signature: reject it too.
        ok = ueccSign(priv, digest, sig) && !ueccRngFailed;
        uECC_set_rng(nullptr);
        ueccRng = nullptr;
        scrubStack();
    }
    if (!ok)
        secureWipe(sig, P256_SIG_LEN);
    return ok;
}

bool uecc::publicKey(const uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_PUBKEY_LEN])
{
    pub[0] = 0x04;
    bool ok = ueccPublicKey(priv, pub + 1);
    scrubStack(); // the native copy of priv
    return ok;
}

#if defined(KP_CRYPTO_BACKEND_NONE)
// No backend on this target (only reachable in unit-test builds for other architectures): everything fails closed.
namespace backend
{
bool publicKeyOnCurve(const uint8_t *)
{
    return false;
}
bool generateKeyPair(uint8_t *, uint8_t *)
{
    return false;
}
bool verifyDigest(const uint8_t *, const uint8_t *, const uint8_t *)
{
    return false;
}
bool blindingRandom(uint8_t *, unsigned)
{
    return false;
}
bool signDigest(const uint8_t *, const uint8_t *, const uint8_t *, uecc::RngFn, uint8_t *)
{
    return false;
}
bool ecdh(const uint8_t *, const uint8_t *, uint8_t *)
{
    return false;
}
bool ccmEncrypt(const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, uint8_t *,
                uint8_t *, size_t)
{
    return false;
}
bool ccmDecrypt(const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, uint8_t *,
                uint8_t *, size_t)
{
    return false;
}
} // namespace backend
#endif

} // namespace kpcrypto

#endif
