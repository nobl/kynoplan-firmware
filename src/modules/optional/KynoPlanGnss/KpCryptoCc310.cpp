// KpCrypto backend for the nRF52840: ARM CryptoCell CC310 through the CRYS API shipped with Adafruit nRFCrypto.
// Every operation runs under cryptLock (shared with packet crypto and HardwareRNG users) inside nRFCrypto.begin()/end().
// Inputs are copied to RAM first: the CC310 DMA cannot read flash.
#include "KpCryptoBackend.h"

#if (defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)) && defined(KP_CRYPTO_BACKEND_CC310)

#include "concurrency/Lock.h"
#include <Adafruit_nRFCrypto.h>
#include <stdlib.h>
#include <string.h>

#include "nrf_cc310/include/crys_aesccm.h"
#include "nrf_cc310/include/crys_ecpki_build.h"
#include "nrf_cc310/include/crys_ecpki_dh.h"
#include "nrf_cc310/include/crys_ecpki_domain.h"
#include "nrf_cc310/include/crys_ecpki_ecdsa.h"
#include "nrf_cc310/include/crys_ecpki_kg.h"

extern concurrency::Lock *cryptLock;
extern Adafruit_nRFCrypto nRFCrypto;

namespace kpcrypto
{
namespace backend
{
namespace
{
concurrency::Lock *acquire(concurrency::Lock *l)
{
    if (l)
        l->lock();
    return l;
}

// cryptLock, then nRFCrypto.begin() (the HardwareRNG / EncryptedStorage convention); released in reverse order.
// keepStarted (CcmStream frames): skip end(), so a library whose end() tears down is not restarted every frame.
class Cc310Session
{
  public:
    explicit Cc310Session(bool keepStarted = false)
        : lock_(acquire(cryptLock)), started_(nRFCrypto.begin()), keepStarted_(keepStarted)
    {
    }
    ~Cc310Session()
    {
        if (started_ && !keepStarted_)
            nRFCrypto.end();
        if (lock_)
            lock_->unlock();
    }
    Cc310Session(const Cc310Session &) = delete;
    Cc310Session &operator=(const Cc310Session &) = delete;
    bool ok() const { return started_; }

  private:
    concurrency::Lock *lock_;
    bool started_;
    bool keepStarted_;
};

// Zeroed heap object, wiped before it is freed (CRYS contexts and temp buffers are too large for task stacks).
template <typename T> class Scratch
{
  public:
    Scratch() : p_(static_cast<T *>(calloc(1, sizeof(T)))) {}
    ~Scratch()
    {
        if (p_) {
            secureWipe(p_, sizeof(T));
            free(p_);
        }
    }
    Scratch(const Scratch &) = delete;
    Scratch &operator=(const Scratch &) = delete;
    T *get() { return p_; }
    explicit operator bool() const { return p_ != nullptr; }

  private:
    T *p_;
};

const CRYS_ECPKI_Domain_t *domain()
{
    return CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
}

bool buildPublic(const uint8_t *pub, CRYS_ECPKI_UserPublKey_t *out, bool fullCheck)
{
    Scratch<CRYS_ECPKI_BUILD_TempData_t> temp;
    uint8_t ram[P256_PUBKEY_LEN];
    memcpy(ram, pub, sizeof(ram));
    if (!temp || !domain())
        return false;
    CRYSError_t err = fullCheck ? CRYS_ECPKI_BuildPublKeyFullCheck(domain(), ram, sizeof(ram), out, temp.get())
                                : CRYS_ECPKI_BuildPublKeyPartlyCheck(domain(), ram, sizeof(ram), out, temp.get());
    return err == CRYS_OK;
}

bool buildPrivate(const uint8_t *priv, CRYS_ECPKI_UserPrivKey_t *out)
{
    uint8_t ram[P256_SCALAR_LEN];
    memcpy(ram, priv, sizeof(ram));
    bool ok = domain() && CRYS_ECPKI_BuildPrivKey(domain(), ram, sizeof(ram), out) == CRYS_OK;
    secureWipe(ram, sizeof(ram));
    return ok;
}

// Caller holds a Cc310Session; buf is RAM with room for aadLen + len bytes (AAD then text), wiped afterwards.
bool ccmLocked(SaSiAesEncryptMode_t mode, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
               const uint8_t *in, size_t len, uint8_t *out, uint8_t *mac, uint8_t *buf)
{
    CRYS_AESCCM_Key_t k = {0};
    uint8_t n[CCM_NONCE_LEN];
    memcpy(k, key, AES128_KEY_LEN);
    memcpy(n, nonce, sizeof(n));
    if (aadLen)
        memcpy(buf, aad, aadLen);
    if (len)
        memcpy(buf + aadLen, in, len);
    bool ok = CRYS_AESCCM(mode, k, CRYS_AES_Key128BitSize, n, sizeof(n), buf, (uint32_t)aadLen, buf + aadLen, (uint32_t)len, out,
                          CCM_TAG_LEN, mac) == CRYS_OK;
    secureWipe(buf, aadLen + len);
    secureWipe(k, sizeof(k));
    return ok;
}

// streamBuf: a CcmStream's buffer (no heap, library kept started), or nullptr for a one-shot call.
bool ccm(SaSiAesEncryptMode_t mode, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
         const uint8_t *in, size_t len, uint8_t *out, uint8_t *mac, uint8_t *streamBuf, size_t streamBufLen)
{
    if (aadLen > 0xFFFF || len > 0xFFFF)
        return false;
    if (streamBuf) {
        if (aadLen + len > streamBufLen)
            return false;
        Cc310Session cc(true);
        return cc.ok() && ccmLocked(mode, key, nonce, aad, aadLen, in, len, out, mac, streamBuf);
    }
    Cc310Session cc;
    if (!cc.ok())
        return false;
    // +1 so a zero-length request still has a valid pointer.
    uint8_t *buf = static_cast<uint8_t *>(malloc(aadLen + len + 1));
    if (!buf)
        return false;
    bool ok = ccmLocked(mode, key, nonce, aad, aadLen, in, len, out, mac, buf);
    free(buf);
    return ok;
}
} // namespace

bool publicKeyOnCurve(const uint8_t pub[P256_PUBKEY_LEN])
{
    Cc310Session cc;
    CRYS_ECPKI_UserPublKey_t key;
    return cc.ok() && buildPublic(pub, &key, true);
}

bool generateKeyPair(uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_PUBKEY_LEN])
{
    Cc310Session cc;
    if (!cc.ok() || !domain())
        return false; // RNG not initialised: fail closed (SPEC 6.1)
    Scratch<CRYS_ECPKI_KG_TempData_t> temp;
    Scratch<CRYS_ECPKI_UserPrivKey_t> privKey;
    CRYS_ECPKI_UserPublKey_t pubKey;
    if (!temp || !privKey)
        return false;
    uint32_t privLen = P256_SCALAR_LEN, pubLen = P256_PUBKEY_LEN;
    return CRYS_ECPKI_GenKeyPair(nRFCrypto.Random.getContext(), CRYS_RND_GenerateVector, domain(), privKey.get(), &pubKey,
                                 temp.get(), nullptr) == CRYS_OK &&
           CRYS_ECPKI_ExportPrivKey(privKey.get(), priv, &privLen) == CRYS_OK && privLen == P256_SCALAR_LEN &&
           CRYS_ECPKI_ExportPublKey(&pubKey, CRYS_EC_PointUncompressed, pub, &pubLen) == CRYS_OK && pubLen == P256_PUBKEY_LEN;
}

// Caller holds a Cc310Session.
static bool verifyDigestLocked(const uint8_t *pub, const uint8_t *digest, const uint8_t *sig)
{
    Scratch<CRYS_ECDSA_VerifyUserContext_t> ctx;
    CRYS_ECPKI_UserPublKey_t key;
    uint8_t d[SHA256_LEN], s[P256_SIG_LEN];
    memcpy(d, digest, sizeof(d));
    memcpy(s, sig, sizeof(s));
    return ctx && buildPublic(pub, &key, false) &&
           CRYS_ECDSA_Verify(ctx.get(), &key, CRYS_ECPKI_AFTER_HASH_SHA256_mode, s, sizeof(s), d, sizeof(d)) == CRYS_OK;
}

bool verifyDigest(const uint8_t pub[P256_PUBKEY_LEN], const uint8_t digest[SHA256_LEN], const uint8_t sig[P256_SIG_LEN])
{
    Cc310Session cc;
    return cc.ok() && verifyDigestLocked(pub, digest, sig);
}

// CRYS_ECDSA_Sign draws k from the CC310 DRBG alone, which SPEC 7.5 forbids. Signing therefore uses the vendored
// micro-ecc RFC 6979 signer; the CC310 RNG only feeds micro-ecc's side-channel blinding (signature unchanged).
// Called inside signDigest's Cc310Session.
bool blindingRandom(uint8_t *dest, unsigned size)
{
    return size <= 0xFFFF && nRFCrypto.Random.generate(dest, (uint16_t)size);
}

bool signDigest(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_PUBKEY_LEN], const uint8_t digest[SHA256_LEN],
                uecc::RngFn rng, uint8_t sig[P256_SIG_LEN])
{
    Cc310Session cc; // cryptLock also serialises micro-ecc's global RNG pointer
    if (!cc.ok())
        return false;
    // Fault check: a glitched computation must not release a signature (or a k-revealing one) that does not verify.
    return uecc::signDigest(priv, digest, sig, rng) && verifyDigestLocked(pub, digest, sig);
}

bool ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t peerPub[P256_PUBKEY_LEN], uint8_t secret[ECDH_SECRET_LEN])
{
    Cc310Session cc;
    if (!cc.ok())
        return false;
    Scratch<CRYS_ECDH_TempData_t> temp;
    Scratch<CRYS_ECPKI_UserPrivKey_t> privKey;
    CRYS_ECPKI_UserPublKey_t peer;
    uint32_t len = ECDH_SECRET_LEN;
    return temp && privKey && buildPrivate(priv, privKey.get()) && buildPublic(peerPub, &peer, false) &&
           CRYS_ECDH_SVDP_DH(&peer, privKey.get(), secret, &len, temp.get()) == CRYS_OK && len == ECDH_SECRET_LEN;
}

bool ccmEncrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                const uint8_t *pt, size_t ptLen, uint8_t *ct, uint8_t tag[CCM_TAG_LEN], uint8_t *buf, size_t bufLen)
{
    CRYS_AESCCM_Mac_Res_t mac = {0};
    bool ok = ccm(SASI_AES_ENCRYPT, key, nonce, aad, aadLen, pt, ptLen, ct, mac, buf, bufLen);
    if (ok)
        memcpy(tag, mac, CCM_TAG_LEN);
    return ok;
}

bool ccmDecrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                const uint8_t *ct, size_t ctLen, const uint8_t tag[CCM_TAG_LEN], uint8_t *pt, uint8_t *buf, size_t bufLen)
{
    CRYS_AESCCM_Mac_Res_t mac = {0};
    memcpy(mac, tag, CCM_TAG_LEN); // decrypt compares the computed tag with this one
    return ccm(SASI_AES_DECRYPT, key, nonce, aad, aadLen, ct, ctLen, pt, mac, buf, bufLen);
}

} // namespace backend
} // namespace kpcrypto

#endif
