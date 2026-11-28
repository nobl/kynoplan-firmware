#pragma once

#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)

#include "KpCrypto.h"
#include "configuration.h" // ARCH_NRF52 / ARCH_PORTDUINO come from the platform's architecture.h

// Backend selection for KpCrypto. Exactly one of the KP_CRYPTO_BACKEND_* macros is 1.
// The OpenSSL backend uses the 3.x OSSL_PARAM API, so OpenSSL 1.1 hosts fall back to NONE.
#if defined(ARCH_NRF52) && defined(NRF52840_XXAA)
#define KP_CRYPTO_BACKEND_CC310 1
#elif defined(ARCH_PORTDUINO) && !defined(ARCH_PORTDUINO_WASM) && defined(__has_include)
#if __has_include(<openssl/evp.h>) && __has_include(<openssl/param_build.h>)
#define KP_CRYPTO_BACKEND_OPENSSL 1
#endif
#endif
#if !defined(KP_CRYPTO_BACKEND_CC310) && !defined(KP_CRYPTO_BACKEND_OPENSSL)
#if defined(KYNOPLAN_GNSS_STREAM)
#error "KYNOPLAN_GNSS_STREAM needs a KpCrypto backend (nRF52840 CC310 or portduino OpenSSL 3)"
#endif
#define KP_CRYPTO_BACKEND_NONE 1
#endif

namespace kpcrypto
{
namespace uecc
{
// RNG for micro-ecc's side-channel blinding: fills dest, false on failure.
using RngFn = bool (*)(uint8_t *dest, unsigned size);
} // namespace uecc

// Called by KpCrypto.cpp only, after the portable checks (lengths, prefix, coordinate/scalar/r/s ranges) passed.
// Digests are SHA-256 outputs computed by the portable layer.
namespace backend
{
bool publicKeyOnCurve(const uint8_t pub[P256_PUBKEY_LEN]);
bool generateKeyPair(uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_PUBKEY_LEN]);
bool verifyDigest(const uint8_t pub[P256_PUBKEY_LEN], const uint8_t digest[SHA256_LEN], const uint8_t sig[P256_SIG_LEN]);
// The hardware RNG (portduino: OpenSSL RAND_bytes), used for micro-ecc blinding.
bool blindingRandom(uint8_t *dest, unsigned size);
// uecc::signDigest(priv, digest, rng), then this backend verifies the result against pub before returning it.
bool signDigest(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_PUBKEY_LEN], const uint8_t digest[SHA256_LEN],
                uecc::RngFn rng, uint8_t sig[P256_SIG_LEN]);
bool ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t peerPub[P256_PUBKEY_LEN], uint8_t secret[ECDH_SECRET_LEN]);
// buf: a CcmStream's buffer (>= aadLen + text length; no heap, library left started), or nullptr for a one-shot call.
bool ccmEncrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                const uint8_t *pt, size_t ptLen, uint8_t *ct, uint8_t tag[CCM_TAG_LEN], uint8_t *buf, size_t bufLen);
bool ccmDecrypt(const uint8_t key[AES128_KEY_LEN], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aadLen,
                const uint8_t *ct, size_t ctLen, const uint8_t tag[CCM_TAG_LEN], uint8_t *pt, uint8_t *buf, size_t bufLen);
} // namespace backend

// Vendored micro-ecc P-256 helpers (third_party/micro-ecc via KpUecc.cpp), implemented in KpCrypto.cpp; the HMAC uses the
// rweather SHA-256. The signer is the device-signing path on every target, so the native tests exercise it.
namespace uecc
{
// uECC_sign_deterministic -> raw r||s, RFC 6979 with HMAC-SHA256 (byte-order fix in the vendored copy, see VENDORED.txt).
// rng only blinds (the signature does not depend on it); it is probed first and a failure aborts the whole signature.
bool signDigest(const uint8_t priv[P256_SCALAR_LEN], const uint8_t digest[SHA256_LEN], uint8_t sig[P256_SIG_LEN], RngFn rng);
// 0x04 || X || Y of priv * G.
bool publicKey(const uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_PUBKEY_LEN]);
} // namespace uecc

#if defined(PIO_UNIT_TESTING)
// Test seams.
namespace testing
{
// When set, aes128CcmDecrypt() and CcmStream::decrypt() call this instead of backend::ccmDecrypt(), so the portable
// wipe-on-failure can be checked against a backend that leaves garbage in the output.
using CcmDecryptFn = bool (*)(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aadLen, const uint8_t *ct,
                              size_t ctLen, const uint8_t *tag, uint8_t *pt);
extern CcmDecryptFn ccmDecryptOverride;
// When set, ecdsaSign() blinds with this instead of backend::blindingRandom.
extern uecc::RngFn blindingRngOverride;
// Blinding requests micro-ecc made (one per signing attempt that reached a scalar multiplication), counted from 0.
extern unsigned ueccBlindingCalls;
} // namespace testing
#endif
} // namespace kpcrypto

#endif
