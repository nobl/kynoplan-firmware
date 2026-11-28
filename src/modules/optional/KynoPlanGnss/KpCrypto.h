#pragma once

#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)

#include <stddef.h>
#include <stdint.h>

// Cryptographic primitives for the KynoPlan GNSS protocol (contract SPEC 2, 6.4, 7.2-7.5, 8).
// SHA-256/HMAC/HKDF and all input validation are portable (rweather Crypto); P-256 and AES-CCM use the nRF52840 CC310
// or, on portduino, OpenSSL. Every function fails closed: false means "do not use the outputs" (they are wiped).
// On nRF52 the P-256 and CCM calls take cryptLock themselves, so callers must NOT already hold it.
namespace kpcrypto
{

constexpr size_t SHA256_LEN = 32;
constexpr size_t P256_SCALAR_LEN = 32;
constexpr size_t P256_PUBKEY_LEN = 65; // 0x04 || X || Y
constexpr size_t P256_SIG_LEN = 64;    // r || s, big-endian
constexpr size_t ECDH_SECRET_LEN = 32; // x-coordinate
constexpr size_t AES128_KEY_LEN = 16;
constexpr size_t CCM_NONCE_LEN = 13;
constexpr size_t CCM_TAG_LEN = 16;
constexpr size_t HKDF_MAX_OKM = 255 * SHA256_LEN;

// Wipe that the compiler cannot elide.
void secureWipe(void *p, size_t n);
// Constant-time equality of two n-byte buffers.
bool constantTimeEqual(const void *a, const void *b, size_t n);

// Incremental SHA-256. finish() may be called once; the state is wiped afterwards and on destruction.
class Sha256
{
  public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256 &) = delete;
    Sha256 &operator=(const Sha256 &) = delete;
    void update(const void *data, size_t len);
    void finish(uint8_t out[SHA256_LEN]);

  private:
    alignas(8) uint8_t state_[192];
};

void sha256(const void *data, size_t len, uint8_t out[SHA256_LEN]);
void hmacSha256(const uint8_t *key, size_t keyLen, const void *data, size_t dataLen, uint8_t out[SHA256_LEN]);

// RFC 5869 with SHA-256. An empty salt means HashLen zero bytes. Expand: outLen in [1, HKDF_MAX_OKM].
void hkdfExtract(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen, uint8_t prk[SHA256_LEN]);
bool hkdfExpand(const uint8_t prk[SHA256_LEN], const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen);

// SPEC 7.5: exactly 65 bytes, prefix 0x04, X and Y < p, on the curve (which also excludes infinity).
bool p256PublicKeyValid(const uint8_t *pub, size_t pubLen);
// The encoding part of p256PublicKeyValid() alone (no curve equation): 65 bytes, prefix 0x04, X < p, Y < p.
bool p256PointEncodingValid(const uint8_t *pub, size_t pubLen);
// SPEC 7.5 signature form: r and s each in [1, n-1] (high S allowed).
bool p256SignatureScalarsValid(const uint8_t sig[P256_SIG_LEN]);
// Private scalar in [1, n-1].
bool p256PrivateKeyValid(const uint8_t priv[P256_SCALAR_LEN]);
// Fresh key pair from the hardware RNG (portduino: OS CSPRNG). False if the RNG cannot be used.
bool p256GenerateKeyPair(uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_PUBKEY_LEN]);

// True if pub is a valid point and equals priv * G. Call once when a key pair is loaded, before using it with ecdsaSign().
bool p256KeyPairMatches(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_PUBKEY_LEN]);

// ECDSA-P256-SHA256 over msg, raw r||s. Verify rejects r or s outside [1, n-1] and invalid keys; high S is accepted.
bool ecdsaVerify(const uint8_t pub[P256_PUBKEY_LEN], const void *msg, size_t msgLen, const uint8_t sig[P256_SIG_LEN]);
// RFC 6979 signing with the vendored micro-ecc on every target. pub is the caller's stored public key (checked once with
// p256KeyPairMatches()); the signature is verified against it with the backend before release, so no per-sign priv * G.
bool ecdsaSign(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_PUBKEY_LEN], const void *msg, size_t msgLen,
               uint8_t sig[P256_SIG_LEN]);

// Known-answer test (RFC 6979 A.2.5 "sample") of key derivation, signing and verify-after-sign on this target. The module
// calls it once at start and keeps the feature unavailable if it returns false (the failure is logged).
bool selfTest();

// ECDH-P256: 32-byte x-coordinate. Validates the peer point and rejects an all-zero result.
bool ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t peerPub[P256_PUBKEY_LEN], uint8_t secret[ECDH_SECRET_LEN]);

// AES-128-CCM, 13-byte nonce, 16-byte tag appended: out holds ptLen + CCM_TAG_LEN bytes (ciphertext || tag).
bool aes128CcmEncrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                      const uint8_t *pt, size_t ptLen, uint8_t *out);
// in = ciphertext || tag (inLen >= CCM_TAG_LEN); out holds inLen - CCM_TAG_LEN bytes and is wiped on failure.
bool aes128CcmDecrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                      const uint8_t *in, size_t inLen, uint8_t *out);

constexpr size_t CCM_STREAM_MAX_AAD = 33;   // SPEC 8.1 AAD
constexpr size_t CCM_STREAM_MAX_TEXT = 160; // SPEC 8.6 padded plaintext

// AES-128-CCM for one session direction across a burst of frames (the 1 Hz stream): the key and a fixed RAM buffer live
// here, so a frame does no heap allocation and never end()s/restarts the CC310 library; cryptLock is taken per frame only.
// nRFCrypto begin() is idempotent and end() not ref-counted; Bluefruit LESC only calls begin(), so a stream cannot stop it.
class CcmStream
{
  public:
    explicit CcmStream(const uint8_t key[AES128_KEY_LEN]);
    ~CcmStream();
    CcmStream(const CcmStream &) = delete;
    CcmStream &operator=(const CcmStream &) = delete;
    // Same contract as aes128CcmEncrypt/Decrypt; false (outputs wiped) if aadLen or the text exceeds the limits above.
    bool encrypt(const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen, const uint8_t *pt, size_t ptLen,
                 uint8_t *out);
    bool decrypt(const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen, const uint8_t *in, size_t inLen,
                 uint8_t *out);

  private:
    uint8_t key_[AES128_KEY_LEN];
    uint8_t buf_[CCM_STREAM_MAX_AAD + CCM_STREAM_MAX_TEXT];
};

} // namespace kpcrypto

#endif
