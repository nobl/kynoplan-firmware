// Unit tests for the KynoPlan GNSS cryptographic primitives in src/modules/optional/KynoPlanGnss/KpCrypto.{h,cpp}
// (portable SHA-256/HMAC/HKDF and validation) and its host backend KpCryptoOpenSsl.cpp (P-256, AES-128-CCM).
//
// The vectors in KpCryptoVectors.h are generated from the golden fixtures of the kynoplan-protocol contract repository
// (fixtures/handshake.json, enrollment.json, envelopes.json, negative.json, signatures.json); each constant names its
// source file and JSON key. Android and the Python reference implementation are held to the same bytes, so any drift
// here means the device cannot talk to the app.
//
// Contract pinned here:
//  - SHA-256 incremental == one-shot, HMAC-SHA256 including keys longer than one block, HKDF-Extract/Expand per
//    RFC 5869 including multi-block output (SPEC 7.3 only uses 16 bytes, so a broken T(i-1) chain would otherwise pass);
//  - the handshake key schedule reproduces PRK, k_c2d and k_d2c byte-exactly, ECDH reproduces Z from both sides, and an
//    all-zero Z is rejected (SPEC 7.3) - provoked with the real point (0, sqrt(b)) and scalar 1;
//  - SPEC 7.5 point validation rejects every negative.json point; ECDSA verify accepts every fixture signature
//    (including high S) and rejects every negative.json signature (wrong label, wrong key, bit flip, r = 0, s = n,
//    downgraded C);
//  - the device signer (vendored micro-ecc in third_party/micro-ecc, the same code on host and X1) derives the fixture
//    public keys and reproduces every fixture signature byte-exactly (they were generated with RFC 6979), also through
//    ecdsaSign() with the backend's verify-after-sign; a digest >= n pins the bits2octets(h1) mod n step. Unpatched
//    micro-ecc 1.0.0 reads the RFC 6979 candidate T into k little-endian and fails these assertions. Beyond the
//    contract's own fixtures it reproduces the published RFC 6979 A.2.5 P-256/SHA-256 vectors (U, k, r, s) and, byte
//    for byte, OpenSSL 3's deterministic ECDSA for 256 seeded key/digest pairs and the edge cases (keys 1 and n-1,
//    leading zero bytes, digests 0, 1, n-1, n, n+1 and ff..ff, where bits2octets must reduce mod n). The A.2.5 and
//    OpenSSL checks also run against a second build of the same vendored file with 32-bit words and no asm
//    (uecc_word32.cpp), the word size of the X1, because the host's own build uses 64-bit words;
//  - ecdsaSign() verifies against the caller's stored public key (no per-sign priv * G) and fails closed, sig wiped,
//    when that key does not match; p256KeyPairMatches() is the load-time check that it does;
//  - the blinding RNG is probed before signing and a failure is latched: a dead RNG costs no scalar multiplication, a
//    failure mid-signature costs one (not uECC_RNG_MAX_TRIES = 64 under cryptLock), and a transient failure never
//    releases the next RFC 6979 candidate's valid but non-canonical signature;
//  - selfTest(), the known-answer test the module runs at start on the device, passes on a correct build and fails
//    when signing fails;
//  - CcmStream (the 1 Hz path's fixed-buffer CCM) reproduces the envelopes, rejects oversize input and wipes outputs;
//  - AES-128-CCM (13-byte nonce, 16-byte tag, 33-byte AAD) reproduces every envelope ciphertext||tag, and decryption
//    rejects any changed tag, ciphertext, AAD, nonce or key and wipes the output buffer;
//  - the portable checks (point encoding: length, prefix, X/Y < p; signature r/s in [1, n-1]; wipe after a failed
//    decrypt) hold on their own, without relying on OpenSSL also rejecting - on the X1 they are the only guard where
//    the CC310 is laxer (its partial point check accepts compressed and hybrid encodings).
//
// Regressions guarded: a transcript hash that differs when fed in pieces; HMAC long-key handling; HKDF counter or
// chaining errors; swapped ECDH/HKDF inputs; accepting an all-zero shared secret; accepting compressed, off-curve or
// out-of-range points; accepting r = 0 / s = n; random-nonce signing; CCM AAD truncation (the in-tree aes-ccm.cpp caps
// AAD at 30 bytes); plaintext of a forged envelope left in the caller's buffer; a signature released unverified or after
// an RNG failure; 64 scalar multiplications under cryptLock on a dead RNG; a word-size-dependent RFC 6979 bug that only
// the 32-bit device build would show.
#include "Arduino.h" // declares setup()/loop() with the linkage the framework's main() calls
#include "TestUtil.h"
#include "modules/optional/KynoPlanGnss/KpCrypto.h"
#include "modules/optional/KynoPlanGnss/KpCryptoBackend.h" // test seam, micro-ecc helpers
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
// After <stdint.h>: the generated tables use uint8_t.
#include "KpCryptoVectors.h"
#include <string>
#include <unity.h>
#include <vector>
#if defined(KP_CRYPTO_BACKEND_OPENSSL)
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#endif

using namespace kpcrypto;

// The 32-bit-word micro-ecc build in uecc_word32.cpp.
namespace kpuecc32
{
unsigned wordSize();
bool signDigest(const uint8_t *priv, const uint8_t *digest, uint8_t *sig);
bool publicKey(const uint8_t *priv, uint8_t *pub);
} // namespace kpuecc32

namespace
{
std::vector<uint8_t> hex(const char *s)
{
    std::vector<uint8_t> out;
    size_t n = strlen(s);
    TEST_ASSERT_EQUAL_MESSAGE(0, n % 2, "odd hex length");
    for (size_t i = 0; i < n; i += 2) {
        auto nib = [](char c) { return (uint8_t)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10); };
        out.push_back((uint8_t)(nib(s[i]) << 4 | nib(s[i + 1])));
    }
    return out;
}

std::vector<uint8_t> cat(std::initializer_list<std::vector<uint8_t>> parts)
{
    std::vector<uint8_t> out;
    for (const auto &p : parts)
        out.insert(out.end(), p.begin(), p.end());
    return out;
}

void assertBytes(const std::vector<uint8_t> &expected, const uint8_t *actual, size_t len, const char *what)
{
    TEST_ASSERT_EQUAL_MESSAGE(expected.size(), len, what);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected.data(), actual, len, what);
}

bool allZero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (p[i])
            return false;
    return true;
}

const char *const P256_N_HEX = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
// (0, sqrt(b) mod p) is on P-256; with scalar 1 its ECDH x-coordinate is all zero.
const char *const POINT_X_ZERO =
    "04000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6"
    "541c2af31dae871728bf856a174f93f4";
} // namespace

void setUp(void) {}
void tearDown(void) {}

// --- hashing ---

static void test_sha256_nist_vectors(void)
{
    uint8_t out[SHA256_LEN];
    sha256("abc", 3, out);
    assertBytes(hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), out, sizeof(out), "abc");
    sha256(nullptr, 0, out);
    assertBytes(hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), out, sizeof(out), "empty");
}

// TH (SPEC 7.3) hashed incrementally, field by field, and split at every byte of the joined input.
static void test_sha256_incremental_reproduces_transcript_hash(void)
{
    for (const auto &v : HANDSHAKES) {
        uint8_t hDev[SHA256_LEN], hCli[SHA256_LEN], th[SHA256_LEN];
        auto dev = hex(KEY_DEVICE_IDENTITY_PUB), cli = hex(v.clientPub);
        sha256(dev.data(), dev.size(), hDev);
        sha256(cli.data(), cli.size(), hCli);
        auto parts = {std::vector<uint8_t>(hDev, hDev + 32),
                      std::vector<uint8_t>(hCli, hCli + 32),
                      hex(v.H),
                      hex(v.C),
                      hex(v.deviceSig),
                      hex(v.clientSig)};
        Sha256 inc;
        for (const auto &p : parts)
            inc.update(p.data(), p.size());
        inc.finish(th);
        assertBytes(hex(v.TH), th, sizeof(th), v.name);

        auto all = cat(parts);
        for (size_t split = 0; split <= all.size(); split += 7) {
            Sha256 s;
            s.update(all.data(), split);
            s.update(all.data() + split, all.size() - split);
            s.finish(th);
            assertBytes(hex(v.TH), th, sizeof(th), "split");
        }
    }
}

static void test_hmac_sha256_rfc4231_short_and_long_key(void)
{
    uint8_t out[SHA256_LEN];
    std::vector<uint8_t> k1(20, 0x0b);
    hmacSha256(k1.data(), k1.size(), "Hi There", 8, out);
    assertBytes(hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), out, sizeof(out), "case 1");
    std::vector<uint8_t> k6(131, 0xaa);
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmacSha256(k6.data(), k6.size(), m6, strlen(m6), out);
    assertBytes(hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), out, sizeof(out), "case 6");
}

// --- HKDF ---

static void test_hkdf_rfc5869_multi_block_and_empty_salt(void)
{
    std::vector<uint8_t> ikm(22, 0x0b), salt = hex("000102030405060708090a0b0c"), info = hex("f0f1f2f3f4f5f6f7f8f9");
    uint8_t prk[SHA256_LEN], okm[42];
    hkdfExtract(salt.data(), salt.size(), ikm.data(), ikm.size(), prk);
    assertBytes(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk, sizeof(prk), "case 1 PRK");
    TEST_ASSERT_TRUE(hkdfExpand(prk, info.data(), info.size(), okm, sizeof(okm)));
    assertBytes(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), okm, sizeof(okm),
                "case 1 OKM");

    hkdfExtract(nullptr, 0, ikm.data(), ikm.size(), prk);
    assertBytes(hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), prk, sizeof(prk), "case 3 PRK");
    TEST_ASSERT_TRUE(hkdfExpand(prk, nullptr, 0, okm, sizeof(okm)));
    assertBytes(hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"), okm, sizeof(okm),
                "case 3 OKM");
}

static void test_hkdf_expand_length_limits(void)
{
    uint8_t prk[SHA256_LEN] = {1};
    std::vector<uint8_t> okm(HKDF_MAX_OKM + 1);
    TEST_ASSERT_FALSE(hkdfExpand(prk, nullptr, 0, okm.data(), 0));
    TEST_ASSERT_FALSE(hkdfExpand(prk, nullptr, 0, okm.data(), HKDF_MAX_OKM + 1));
    TEST_ASSERT_TRUE(hkdfExpand(prk, nullptr, 0, okm.data(), HKDF_MAX_OKM));
}

static void test_hkdf_reproduces_handshake_key_schedule(void)
{
    for (const auto &v : HANDSHAKES) {
        auto salt = hex(v.salt), z = hex(v.Z), ic = hex(v.infoC2d), id = hex(v.infoD2c);
        uint8_t prk[SHA256_LEN], k[16];
        hkdfExtract(salt.data(), salt.size(), z.data(), z.size(), prk);
        assertBytes(hex(v.PRK), prk, sizeof(prk), v.name);
        TEST_ASSERT_TRUE(hkdfExpand(prk, ic.data(), ic.size(), k, sizeof(k)));
        assertBytes(hex(v.kC2d), k, sizeof(k), "k_c2d");
        TEST_ASSERT_TRUE(hkdfExpand(prk, id.data(), id.size(), k, sizeof(k)));
        assertBytes(hex(v.kD2c), k, sizeof(k), "k_d2c");
    }
}

// --- P-256 keys and ECDH ---

static void test_fixture_public_keys_are_valid(void)
{
    const char *keys[] = {
        KEY_CLIENT_STATIC_PUB,      KEY_DEVICE_IDENTITY_PUB,    KEY_CLIENT_EPHEMERAL_PUB, KEY_DEVICE_EPHEMERAL_PUB,
        KEY_CLIENT_EPHEMERAL_2_PUB, KEY_DEVICE_EPHEMERAL_2_PUB, KEY_CLIENT_NEW_PUB,       POINT_X_ZERO};
    for (const char *k : keys) {
        auto p = hex(k);
        TEST_ASSERT_TRUE_MESSAGE(p256PublicKeyValid(p.data(), p.size()), k);
    }
}

static void test_point_validation_rejects_negative_vectors(void)
{
    for (const auto &v : NEGATIVE_POINTS) {
        auto p = hex(v.point);
        TEST_ASSERT_FALSE_MESSAGE(p256PublicKeyValid(p.data(), p.size()), v.name);
    }
    auto good = hex(KEY_CLIENT_STATIC_PUB);
    TEST_ASSERT_FALSE(p256PublicKeyValid(good.data(), 64));
    TEST_ASSERT_FALSE(p256PublicKeyValid(nullptr, 65));
}

static void test_private_scalar_range(void)
{
    auto n = hex(P256_N_HEX), nm1 = n;
    nm1[31]--;
    uint8_t zero[32] = {0}, one[32] = {0};
    one[31] = 1;
    TEST_ASSERT_FALSE(p256PrivateKeyValid(zero));
    TEST_ASSERT_TRUE(p256PrivateKeyValid(one));
    TEST_ASSERT_TRUE(p256PrivateKeyValid(nm1.data()));
    TEST_ASSERT_FALSE(p256PrivateKeyValid(n.data()));
}

static void test_ecdh_reproduces_fixture_from_both_sides(void)
{
    for (const auto &v : HANDSHAKES) {
        auto cPriv = hex(v.clientEphPriv), cPub = hex(v.clientEphPub), dPriv = hex(v.deviceEphPriv), dPub = hex(v.deviceEphPub);
        uint8_t z[ECDH_SECRET_LEN];
        TEST_ASSERT_TRUE(ecdh(cPriv.data(), dPub.data(), z));
        assertBytes(hex(v.Z), z, sizeof(z), v.name);
        TEST_ASSERT_TRUE(ecdh(dPriv.data(), cPub.data(), z));
        assertBytes(hex(v.Z), z, sizeof(z), "device side");
    }
}

static void test_ecdh_rejects_all_zero_secret_and_invalid_inputs(void)
{
    uint8_t z[ECDH_SECRET_LEN], one[32] = {0};
    one[31] = 1;
    auto xZero = hex(POINT_X_ZERO);
    memset(z, 0xAA, sizeof(z));
    TEST_ASSERT_FALSE(ecdh(one, xZero.data(), z));
    TEST_ASSERT_TRUE(allZero(z, sizeof(z)));

    auto priv = hex(KEY_CLIENT_EPHEMERAL_PRIV);
    for (const auto &v : NEGATIVE_POINTS) {
        auto p = hex(v.point);
        if (p.size() != P256_PUBKEY_LEN)
            continue; // the API takes exactly 65 bytes; shorter encodings are covered by test_point_validation
        memset(z, 0xAA, sizeof(z));
        TEST_ASSERT_FALSE_MESSAGE(ecdh(priv.data(), p.data(), z), v.name);
        TEST_ASSERT_TRUE(allZero(z, sizeof(z)));
    }
    auto n = hex(P256_N_HEX), dPub = hex(KEY_DEVICE_EPHEMERAL_PUB);
    TEST_ASSERT_FALSE(ecdh(n.data(), dPub.data(), z));
}

static void test_generated_key_pairs_agree_and_sign(void)
{
    uint8_t aPriv[32], aPub[65], bPriv[32], bPub[65], zab[32], zba[32];
    TEST_ASSERT_TRUE(p256GenerateKeyPair(aPriv, aPub));
    TEST_ASSERT_TRUE(p256GenerateKeyPair(bPriv, bPub));
    TEST_ASSERT_TRUE(p256PrivateKeyValid(aPriv));
    TEST_ASSERT_TRUE(p256PublicKeyValid(aPub, sizeof(aPub)));
    TEST_ASSERT_FALSE(constantTimeEqual(aPriv, bPriv, 32));
    TEST_ASSERT_TRUE(ecdh(aPriv, bPub, zab));
    TEST_ASSERT_TRUE(ecdh(bPriv, aPub, zba));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zab, zba, 32);
    TEST_ASSERT_TRUE(p256KeyPairMatches(aPriv, aPub));
    uint8_t sig[64];
    TEST_ASSERT_TRUE(ecdsaSign(aPriv, aPub, "msg", 3, sig));
    TEST_ASSERT_TRUE(ecdsaVerify(aPub, "msg", 3, sig));
    TEST_ASSERT_FALSE(ecdsaVerify(bPub, "msg", 3, sig));
}

// --- ECDSA ---

static void test_ecdsa_verifies_fixture_signatures(void)
{
    auto dev = hex(KEY_DEVICE_IDENTITY_PUB);
    for (const auto &v : HANDSHAKES) {
        auto cli = hex(v.clientPub), dm = hex(v.deviceMsg), ds = hex(v.deviceSig), cm = hex(v.clientMsg), cs = hex(v.clientSig);
        TEST_ASSERT_TRUE_MESSAGE(ecdsaVerify(dev.data(), dm.data(), dm.size(), ds.data()), v.name);
        TEST_ASSERT_TRUE_MESSAGE(ecdsaVerify(cli.data(), cm.data(), cm.size(), cs.data()), v.name);
        // The device signature is not valid for the client's message (labels differ).
        TEST_ASSERT_FALSE(ecdsaVerify(dev.data(), cm.data(), cm.size(), ds.data()));
    }
    for (const auto &v : ENROLLMENTS) {
        auto cli = hex(v.clientPub), cm = hex(v.clientMsg), cs = hex(v.clientSig), dm = hex(v.deviceMsg), ds = hex(v.deviceSig);
        TEST_ASSERT_TRUE_MESSAGE(ecdsaVerify(cli.data(), cm.data(), cm.size(), cs.data()), v.name);
        TEST_ASSERT_TRUE_MESSAGE(ecdsaVerify(dev.data(), dm.data(), dm.size(), ds.data()), v.name);
    }
    auto np = hex(KEY_CLIENT_NEW_PUB), rm = hex(ROT_MSG), rs = hex(ROT_SIG);
    TEST_ASSERT_TRUE_MESSAGE(ecdsaVerify(np.data(), rm.data(), rm.size(), rs.data()), "rotation");
    auto hp = hex(HIGH_S_PUB), hm = hex(HIGH_S_MSG), hs = hex(HIGH_S_SIG);
    TEST_ASSERT_TRUE_MESSAGE(ecdsaVerify(hp.data(), hm.data(), hm.size(), hs.data()), "high S accepted (SPEC 7.5)");
}

static void test_ecdsa_rejects_negative_vectors(void)
{
    for (const auto &v : NEGATIVE_SIGNATURES) {
        auto p = hex(v.pub), m = hex(v.msg), s = hex(v.sig);
        TEST_ASSERT_EQUAL(P256_SIG_LEN, s.size());
        TEST_ASSERT_FALSE_MESSAGE(ecdsaVerify(p.data(), m.data(), m.size(), s.data()), v.name);
    }
    // A valid signature against an off-curve key.
    const auto &h = HANDSHAKES[0];
    auto m = hex(h.deviceMsg), s = hex(h.deviceSig);
    for (const auto &v : NEGATIVE_POINTS) {
        auto p = hex(v.point);
        if (p.size() == P256_PUBKEY_LEN)
            TEST_ASSERT_FALSE_MESSAGE(ecdsaVerify(p.data(), m.data(), m.size(), s.data()), v.name);
    }
}

static void test_ecdsa_sign_rfc6979_reproduces_fixture_signatures(void)
{
    auto devPriv = hex(KEY_DEVICE_IDENTITY_PRIV), devPub = hex(KEY_DEVICE_IDENTITY_PUB);
    uint8_t sig[P256_SIG_LEN];
    for (const auto &v : HANDSHAKES) {
        auto cliPriv = hex(v.clientPriv), cliPub = hex(v.clientPub), dm = hex(v.deviceMsg), cm = hex(v.clientMsg);
        TEST_ASSERT_TRUE(ecdsaSign(devPriv.data(), devPub.data(), dm.data(), dm.size(), sig));
        assertBytes(hex(v.deviceSig), sig, sizeof(sig), v.name);
        TEST_ASSERT_TRUE(ecdsaSign(cliPriv.data(), cliPub.data(), cm.data(), cm.size(), sig));
        assertBytes(hex(v.clientSig), sig, sizeof(sig), v.name);
    }
    for (const auto &v : ENROLLMENTS) {
        auto cliPriv = hex(v.clientPriv), cliPub = hex(v.clientPub), cm = hex(v.clientMsg), dm = hex(v.deviceMsg);
        TEST_ASSERT_TRUE(ecdsaSign(cliPriv.data(), cliPub.data(), cm.data(), cm.size(), sig));
        assertBytes(hex(v.clientSig), sig, sizeof(sig), v.name);
        TEST_ASSERT_TRUE(ecdsaSign(devPriv.data(), devPub.data(), dm.data(), dm.size(), sig));
        assertBytes(hex(v.deviceSig), sig, sizeof(sig), v.name);
    }
    auto newPriv = hex(KEY_CLIENT_NEW_PRIV), newPub = hex(KEY_CLIENT_NEW_PUB), rm = hex(ROT_MSG);
    TEST_ASSERT_TRUE(ecdsaSign(newPriv.data(), newPub.data(), rm.data(), rm.size(), sig));
    assertBytes(hex(ROT_SIG), sig, sizeof(sig), "rotation");
}

static void test_ecdsa_sign_rejects_invalid_scalar(void)
{
    uint8_t zero[32] = {0}, sig[P256_SIG_LEN];
    auto n = hex(P256_N_HEX), devPub = hex(KEY_DEVICE_IDENTITY_PUB);
    memset(sig, 0xAA, sizeof(sig));
    TEST_ASSERT_FALSE(ecdsaSign(zero, devPub.data(), "m", 1, sig));
    TEST_ASSERT_TRUE(allZero(sig, sizeof(sig)));
    TEST_ASSERT_FALSE(ecdsaSign(n.data(), devPub.data(), "m", 1, sig));
}

// The caller's stored public key is what the signature is verified against: a key that does not belong to priv (a
// corrupted record, or a corrupted priv) must yield no signature at all, not an unverified one.
static void test_ecdsa_sign_fails_closed_with_wrong_public_key(void)
{
    auto devPriv = hex(KEY_DEVICE_IDENTITY_PRIV), otherPub = hex(KEY_CLIENT_STATIC_PUB);
    uint8_t sig[P256_SIG_LEN];
    memset(sig, 0xAA, sizeof(sig));
    TEST_ASSERT_FALSE(ecdsaSign(devPriv.data(), otherPub.data(), "m", 1, sig));
    TEST_ASSERT_TRUE(allZero(sig, sizeof(sig)));
    auto badPrefix = hex(KEY_DEVICE_IDENTITY_PUB);
    badPrefix[0] = 0x03;
    TEST_ASSERT_FALSE(ecdsaSign(devPriv.data(), badPrefix.data(), "m", 1, sig));
    TEST_ASSERT_FALSE(ecdsaSign(devPriv.data(), nullptr, "m", 1, sig));
}

static void test_p256_key_pair_matches(void)
{
    auto devPriv = hex(KEY_DEVICE_IDENTITY_PRIV), devPub = hex(KEY_DEVICE_IDENTITY_PUB), otherPub = hex(KEY_CLIENT_STATIC_PUB);
    TEST_ASSERT_TRUE(p256KeyPairMatches(devPriv.data(), devPub.data()));
    TEST_ASSERT_FALSE_MESSAGE(p256KeyPairMatches(devPriv.data(), otherPub.data()), "other key's public half");
    auto flipped = devPub;
    flipped[64] ^= 0x01; // off the curve
    TEST_ASSERT_FALSE_MESSAGE(p256KeyPairMatches(devPriv.data(), flipped.data()), "invalid point");
    std::vector<uint8_t> zero(32, 0);
    TEST_ASSERT_FALSE_MESSAGE(p256KeyPairMatches(zero.data(), devPub.data()), "invalid scalar");
}

// --- blinding RNG failure (fail closed, fast) ---

// Counting RNG: fails on call number rngFailOnly and on every call from rngFailFrom on (1-based; 0 disables either).
static unsigned rngCalls, rngFailOnly, rngFailFrom;
static bool scriptedRng(uint8_t *dest, unsigned size)
{
    ++rngCalls;
    if (rngCalls == rngFailOnly || (rngFailFrom && rngCalls >= rngFailFrom))
        return false;
    memset(dest, 0x3C, size);
    return true;
}
static void scriptRng(unsigned failOnly, unsigned failFrom)
{
    rngCalls = 0;
    rngFailOnly = failOnly;
    rngFailFrom = failFrom;
    testing::ueccBlindingCalls = 0;
}

static void test_uecc_signer_dead_rng_fails_before_any_scalar_mult(void)
{
    auto x = hex(KEY_DEVICE_IDENTITY_PRIV);
    uint8_t digest[SHA256_LEN] = {1}, sig[P256_SIG_LEN];
    memset(sig, 0xAA, sizeof(sig));
    scriptRng(0, 1);
    TEST_ASSERT_FALSE(uecc::signDigest(x.data(), digest, sig, &scriptedRng));
    TEST_ASSERT_TRUE(allZero(sig, sizeof(sig)));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, rngCalls, "probed exactly once");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, testing::ueccBlindingCalls, "micro-ecc never ran");
    TEST_ASSERT_FALSE(uecc::signDigest(x.data(), digest, sig, nullptr));
}

// The probe passes, then the blinding call (after the first scalar multiplication) fails: the signer must give up after
// that one attempt instead of running all 64 RFC 6979 candidates, each with its own scalar multiplication.
static void test_uecc_signer_aborts_after_one_attempt_when_blinding_rng_fails(void)
{
    auto x = hex(KEY_DEVICE_IDENTITY_PRIV);
    uint8_t digest[SHA256_LEN] = {1}, sig[P256_SIG_LEN];
    memset(sig, 0xAA, sizeof(sig));
    scriptRng(0, 2);
    TEST_ASSERT_FALSE(uecc::signDigest(x.data(), digest, sig, &scriptedRng));
    TEST_ASSERT_TRUE(allZero(sig, sizeof(sig)));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, testing::ueccBlindingCalls, "one signing attempt, one scalar multiplication");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(2, rngCalls, "the latched failure is not retried");
}

// One transient failure: uECC would move on to the next RFC 6979 candidate and return a valid signature with a k that
// is not the RFC 6979 one (and differs from what the same inputs give next time). That signature must not be released.
static void test_uecc_signer_transient_rng_failure_releases_no_signature(void)
{
    auto x = hex(KEY_DEVICE_IDENTITY_PRIV);
    uint8_t digest[SHA256_LEN] = {1}, sig[P256_SIG_LEN];
    memset(sig, 0xAA, sizeof(sig));
    scriptRng(2, 0);
    TEST_ASSERT_FALSE(uecc::signDigest(x.data(), digest, sig, &scriptedRng));
    TEST_ASSERT_TRUE(allZero(sig, sizeof(sig)));
    TEST_ASSERT_EQUAL_UINT(2, rngCalls);
    scriptRng(0, 0);
    TEST_ASSERT_TRUE_MESSAGE(uecc::signDigest(x.data(), digest, sig, &scriptedRng), "the latch is per signature");
}

static void test_self_test_passes_and_fails_closed_on_rng_failure(void)
{
    TEST_ASSERT_TRUE(selfTest());
    scriptRng(0, 1);
    testing::blindingRngOverride = &scriptedRng;
    bool ok = selfTest();
    testing::blindingRngOverride = nullptr;
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, rngCalls, "ecdsaSign() blinds with the injected RNG");
    TEST_ASSERT_TRUE(selfTest());
}

// --- AES-128-CCM ---

static std::vector<uint8_t> envelopeKey(const EnvelopeVector &v)
{
    return hex(v.dir == 1 ? ENV_K_C2D : ENV_K_D2C);
}

static void test_ccm_reproduces_envelopes(void)
{
    for (const auto &v : ENVELOPES) {
        auto key = envelopeKey(v), nonce = hex(v.nonce), aad = hex(v.aad), pt = hex(v.paddedPlaintext), ct = hex(v.ciphertext);
        TEST_ASSERT_EQUAL(CCM_NONCE_LEN, nonce.size());
        TEST_ASSERT_EQUAL(33, aad.size());
        std::vector<uint8_t> out(pt.size() + CCM_TAG_LEN), back(pt.size());
        TEST_ASSERT_TRUE(aes128CcmEncrypt(key.data(), nonce.data(), aad.data(), aad.size(), pt.data(), pt.size(), out.data()));
        assertBytes(ct, out.data(), out.size(), v.name);
        TEST_ASSERT_TRUE(aes128CcmDecrypt(key.data(), nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), back.data()));
        assertBytes(pt, back.data(), back.size(), v.name);
    }
}

// Every rejected decryption must leave the caller's buffer zeroed, not holding unauthenticated plaintext.
static void expectRejected(const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce, const std::vector<uint8_t> &aad,
                           const std::vector<uint8_t> &ct, size_t aadLen, const char *what)
{
    std::vector<uint8_t> out(ct.size() - CCM_TAG_LEN, 0xAA);
    TEST_ASSERT_FALSE_MESSAGE(aes128CcmDecrypt(key.data(), nonce.data(), aad.data(), aadLen, ct.data(), ct.size(), out.data()),
                              what);
    TEST_ASSERT_TRUE_MESSAGE(allZero(out.data(), out.size()), what);
}

static void test_ccm_rejects_tampering_and_wipes_output(void)
{
    const auto &v = ENVELOPES[0];
    auto key = envelopeKey(v), nonce = hex(v.nonce), aad = hex(v.aad), ct = hex(v.ciphertext);
    for (size_t i : {(size_t)0, ct.size() - CCM_TAG_LEN - 1, ct.size() - CCM_TAG_LEN, ct.size() - 1}) {
        auto bad = ct;
        bad[i] ^= 0x01;
        expectRejected(key, nonce, aad, bad, aad.size(), i >= ct.size() - CCM_TAG_LEN ? "tag bit" : "ciphertext bit");
    }
    for (size_t i : {(size_t)0, aad.size() - 1}) {
        auto bad = aad;
        bad[i] ^= 0x80;
        expectRejected(key, nonce, bad, ct, bad.size(), "AAD bit");
    }
    expectRejected(key, nonce, aad, ct, aad.size() - 1, "AAD truncated");
    auto badNonce = nonce;
    badNonce[0] ^= 0x03; // the other direction
    expectRejected(key, badNonce, aad, ct, aad.size(), "nonce");
    expectRejected(hex(ENV_K_C2D), nonce, aad, ct, aad.size(), "other direction key");

    std::vector<uint8_t> out(16);
    TEST_ASSERT_FALSE(aes128CcmDecrypt(key.data(), nonce.data(), aad.data(), aad.size(), ct.data(), CCM_TAG_LEN - 1, out.data()));
}

// Backend that fails after writing plaintext-like garbage, as a CC310 might; the portable layer must still wipe.
static bool garbageThenFail(const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t ctLen,
                            const uint8_t *, uint8_t *pt)
{
    memset(pt, 0x5C, ctLen);
    return false;
}

static void test_ccm_decrypt_failure_wipes_output_whatever_the_backend(void)
{
    const auto &v = ENVELOPES[1];
    auto key = envelopeKey(v), nonce = hex(v.nonce), aad = hex(v.aad), ct = hex(v.ciphertext);
    std::vector<uint8_t> out(ct.size() - CCM_TAG_LEN, 0xAA);
    testing::ccmDecryptOverride = &garbageThenFail;
    bool ok = aes128CcmDecrypt(key.data(), nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), out.data());
    testing::ccmDecryptOverride = nullptr;
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_TRUE(allZero(out.data(), out.size()));
}

// --- CcmStream (fixed buffer, no per-frame heap) ---

static void test_ccm_stream_reproduces_envelopes_across_a_burst(void)
{
    CcmStream c2d(hex(ENV_K_C2D).data()), d2c(hex(ENV_K_D2C).data());
    for (int round = 0; round < 2; ++round) { // the same session object, frame after frame
        for (const auto &v : ENVELOPES) {
            CcmStream &s = v.dir == 1 ? c2d : d2c;
            auto nonce = hex(v.nonce), aad = hex(v.aad), pt = hex(v.paddedPlaintext), ct = hex(v.ciphertext);
            TEST_ASSERT_EQUAL(CCM_STREAM_MAX_TEXT, pt.size());
            std::vector<uint8_t> out(pt.size() + CCM_TAG_LEN), back(pt.size());
            TEST_ASSERT_TRUE(s.encrypt(nonce.data(), aad.data(), aad.size(), pt.data(), pt.size(), out.data()));
            assertBytes(ct, out.data(), out.size(), v.name);
            TEST_ASSERT_TRUE(s.decrypt(nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), back.data()));
            assertBytes(pt, back.data(), back.size(), v.name);
        }
    }
}

static void test_ccm_stream_rejects_tampering_and_oversize_and_wipes(void)
{
    const auto &v = ENVELOPES[0];
    CcmStream s(envelopeKey(v).data());
    auto nonce = hex(v.nonce), aad = hex(v.aad), ct = hex(v.ciphertext);
    std::vector<uint8_t> out(ct.size() - CCM_TAG_LEN, 0xAA);
    auto bad = ct;
    bad[3] ^= 0x01;
    TEST_ASSERT_FALSE(s.decrypt(nonce.data(), aad.data(), aad.size(), bad.data(), bad.size(), out.data()));
    TEST_ASSERT_TRUE(allZero(out.data(), out.size()));

    // One byte over each limit: the fixed buffer must never be overrun, and nothing is left in the outputs.
    std::vector<uint8_t> bigAad(CCM_STREAM_MAX_AAD + 1, 0x11), pt(CCM_STREAM_MAX_TEXT + 1, 0x22);
    std::vector<uint8_t> enc(pt.size() + CCM_TAG_LEN, 0xAA);
    TEST_ASSERT_FALSE(s.encrypt(nonce.data(), bigAad.data(), bigAad.size(), pt.data(), CCM_STREAM_MAX_TEXT, enc.data()));
    TEST_ASSERT_TRUE(allZero(enc.data(), CCM_STREAM_MAX_TEXT + CCM_TAG_LEN));
    memset(enc.data(), 0xAA, enc.size());
    TEST_ASSERT_FALSE(s.encrypt(nonce.data(), aad.data(), aad.size(), pt.data(), pt.size(), enc.data()));
    TEST_ASSERT_TRUE(allZero(enc.data(), enc.size()));
    std::vector<uint8_t> bigCt(CCM_STREAM_MAX_TEXT + 1 + CCM_TAG_LEN, 0x33), dec(CCM_STREAM_MAX_TEXT + 1, 0xAA);
    TEST_ASSERT_FALSE(s.decrypt(nonce.data(), aad.data(), aad.size(), bigCt.data(), bigCt.size(), dec.data()));
    TEST_ASSERT_TRUE(allZero(dec.data(), dec.size()));

    // Wipe-on-failure holds for the stream path too, whatever the backend left behind.
    memset(out.data(), 0xAA, out.size());
    testing::ccmDecryptOverride = &garbageThenFail;
    bool ok = s.decrypt(nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), out.data());
    testing::ccmDecryptOverride = nullptr;
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_TRUE(allZero(out.data(), out.size()));

    // Exactly at the limits still works (SPEC 8.1 AAD, 8.6 plaintext).
    auto pt160 = hex(v.paddedPlaintext);
    std::vector<uint8_t> enc160(pt160.size() + CCM_TAG_LEN);
    TEST_ASSERT_TRUE(s.encrypt(nonce.data(), aad.data(), CCM_STREAM_MAX_AAD, pt160.data(), pt160.size(), enc160.data()));
    assertBytes(ct, enc160.data(), enc160.size(), "at the limits");
}

// --- backend-independent validators (the only guard where a backend is laxer, e.g. CC310 partial point checks) ---

static void test_point_encoding_validator(void)
{
    auto good = hex(KEY_CLIENT_STATIC_PUB);
    TEST_ASSERT_TRUE(p256PointEncodingValid(good.data(), good.size()));
    TEST_ASSERT_FALSE(p256PointEncodingValid(good.data(), 64));
    for (uint8_t prefix : {0x00, 0x02, 0x03, 0x05, 0x06}) {
        auto p = good;
        p[0] = prefix;
        TEST_ASSERT_FALSE_MESSAGE(p256PointEncodingValid(p.data(), p.size()), "prefix");
    }
    const auto pHex = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    for (size_t off : {(size_t)1, (size_t)33}) {
        auto p = good;
        memcpy(p.data() + off, pHex.data(), 32);
        TEST_ASSERT_FALSE_MESSAGE(p256PointEncodingValid(p.data(), p.size()), off == 1 ? "x = p" : "y = p");
        p[off + 31] = 0xfe; // p - 1: a valid field element (encoding only, not on the curve)
        TEST_ASSERT_TRUE_MESSAGE(p256PointEncodingValid(p.data(), p.size()), off == 1 ? "x = p - 1" : "y = p - 1");
    }
}

static void test_signature_scalar_validator(void)
{
    auto n = hex(P256_N_HEX), nm1 = n;
    nm1[31]--;
    std::vector<uint8_t> zero(32, 0), one(32, 0);
    one[31] = 1;
    TEST_ASSERT_TRUE(p256SignatureScalarsValid(cat({one, nm1}).data()));
    TEST_ASSERT_TRUE(p256SignatureScalarsValid(cat({nm1, one}).data()));
    TEST_ASSERT_FALSE(p256SignatureScalarsValid(cat({zero, one}).data()));
    TEST_ASSERT_FALSE(p256SignatureScalarsValid(cat({one, zero}).data()));
    TEST_ASSERT_FALSE(p256SignatureScalarsValid(cat({n, one}).data()));
    TEST_ASSERT_FALSE(p256SignatureScalarsValid(cat({one, n}).data()));
}

// --- micro-ecc signer (the X1's signing path) ---

// RFC 6979 signature by the device_identity key over the digest ff..ff (>= n, so bits2octets(h1) must reduce it mod n).
// Computed independently with Python cryptography (OpenSSL, deterministic_signing=True, Prehashed SHA-256).
static const char *const RFC6979_DIGEST_FF_DEVICE_SIG = "d7f5f5b4877ad7175dd10e20f2054416d3cf359e55a789b39323947126b74298"
                                                        "897a2bcafe61c909df583b915a3753cd41e2eda76d9faef9c551c7d34eefd15f";

static void test_uecc_signer_reproduces_fixture_signatures(void)
{
    struct Case {
        const char *priv, *pub, *msg, *sig;
    };
    std::vector<Case> cases;
    for (const auto &v : HANDSHAKES) {
        cases.push_back({KEY_DEVICE_IDENTITY_PRIV, KEY_DEVICE_IDENTITY_PUB, v.deviceMsg, v.deviceSig});
        cases.push_back({v.clientPriv, v.clientPub, v.clientMsg, v.clientSig});
    }
    for (const auto &v : ENROLLMENTS) {
        cases.push_back({v.clientPriv, v.clientPub, v.clientMsg, v.clientSig});
        cases.push_back({KEY_DEVICE_IDENTITY_PRIV, KEY_DEVICE_IDENTITY_PUB, v.deviceMsg, v.deviceSig});
    }
    cases.push_back({KEY_CLIENT_NEW_PRIV, KEY_CLIENT_NEW_PUB, ROT_MSG, ROT_SIG});
    for (const auto &c : cases) {
        auto priv = hex(c.priv), msg = hex(c.msg);
        uint8_t pub[P256_PUBKEY_LEN], digest[SHA256_LEN], sig[P256_SIG_LEN];
        TEST_ASSERT_TRUE(uecc::publicKey(priv.data(), pub));
        assertBytes(hex(c.pub), pub, sizeof(pub), "uECC public key");
        sha256(msg.data(), msg.size(), digest);
        uint8_t again[P256_SIG_LEN];
        TEST_ASSERT_TRUE(uecc::signDigest(priv.data(), digest, sig, &backend::blindingRandom));
        TEST_ASSERT_TRUE(uecc::signDigest(priv.data(), digest, again, &backend::blindingRandom));
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(sig, again, sizeof(sig), "uECC signing is deterministic");
        TEST_ASSERT_TRUE_MESSAGE(ecdsaVerify(pub, msg.data(), msg.size(), sig), "uECC signature verifies (OpenSSL)");
        assertBytes(hex(c.sig), sig, sizeof(sig), "uECC RFC 6979 signature byte-exact");
    }
    auto devPriv = hex(KEY_DEVICE_IDENTITY_PRIV);
    uint8_t digest[SHA256_LEN], sig[P256_SIG_LEN];
    memset(digest, 0xff, sizeof(digest));
    TEST_ASSERT_TRUE(uecc::signDigest(devPriv.data(), digest, sig, &backend::blindingRandom));
    assertBytes(hex(RFC6979_DIGEST_FF_DEVICE_SIG), sig, sizeof(sig), "RFC 6979 with digest >= n");
}

// RFC 6979 Appendix A.2.5 (ECDSA, 256 bits (prime field)), SHA-256 cases: private key x, public key U = xG, and for
// the messages "sample" and "test" the nonce k and the signature (r, s). https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
static const char *const RFC6979_A25_X = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char *const RFC6979_A25_U = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
                                         "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
static const struct {
    const char *msg, *k, *rs;
} RFC6979_A25_SHA256[] = {
    {"sample", "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
     "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
     "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"},
    {"test", "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
     "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
     "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"},
};

using SignFn = bool (*)(const uint8_t *priv, const uint8_t *digest, uint8_t *sig);
using PublicKeyFn = bool (*)(const uint8_t *priv, uint8_t *pub);

static bool signNative(const uint8_t *priv, const uint8_t *digest, uint8_t *sig)
{
    return uecc::signDigest(priv, digest, sig, &backend::blindingRandom);
}

static void expectRfc6979A25(SignFn sign, PublicKeyFn publicKey)
{
    auto x = hex(RFC6979_A25_X);
    uint8_t pub[P256_PUBKEY_LEN], digest[SHA256_LEN], sig[P256_SIG_LEN], kG[P256_PUBKEY_LEN];
    TEST_ASSERT_TRUE(publicKey(x.data(), pub));
    assertBytes(hex(RFC6979_A25_U), pub, sizeof(pub), "A.2.5 U");
    for (const auto &v : RFC6979_A25_SHA256) {
        sha256(v.msg, strlen(v.msg), digest);
        TEST_ASSERT_TRUE(sign(x.data(), digest, sig));
        assertBytes(hex(v.rs), sig, sizeof(sig), v.msg);
        // The published k is the nonce behind that r: r = x(kG) mod n (here x(kG) < n).
        auto k = hex(v.k);
        TEST_ASSERT_TRUE(publicKey(k.data(), kG));
        assertBytes(std::vector<uint8_t>(sig, sig + 32), kG + 1, 32, "r = x(kG)");
    }
}

static void test_uecc_signer_rfc6979_appendix_a25_vectors(void)
{
    expectRfc6979A25(&signNative, &uecc::publicKey);
}

static void test_uecc_word32_signer_rfc6979_appendix_a25_vectors(void)
{
    TEST_ASSERT_EQUAL_UINT_MESSAGE(4, kpuecc32::wordSize(), "second build uses 32-bit words");
    expectRfc6979A25(&kpuecc32::signDigest, &kpuecc32::publicKey);
}

#if defined(KP_CRYPTO_BACKEND_OPENSSL)
// Independent RFC 6979 signer for the cross-check: OpenSSL 3 deterministic ECDSA (OSSL_SIGNATURE_PARAM_NONCE_TYPE = 1).
static bool opensslSignRfc6979(const uint8_t *priv, const uint8_t *digest, uint8_t *sig)
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point = EC_POINT_new(group);
    BIGNUM *d = BN_bin2bn(priv, 32, nullptr);
    uint8_t pub[P256_PUBKEY_LEN];
    bool ok = EC_POINT_mul(group, point, d, nullptr, nullptr, nullptr) == 1 &&
              EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), nullptr) == sizeof(pub);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    ok = ok && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) &&
         OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub)) &&
         OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d) && (params = OSSL_PARAM_BLD_to_param(bld)) &&
         EVP_PKEY_fromdata_init(kctx) == 1 && EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params) == 1;
    unsigned int nonceType = 1;
    OSSL_PARAM sp[] = {OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonceType), OSSL_PARAM_construct_end()};
    uint8_t der[80];
    size_t derLen = sizeof(der);
    EVP_PKEY_CTX *sctx = ok ? EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr) : nullptr;
    ok = ok && sctx && EVP_PKEY_sign_init(sctx) == 1 && EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha256()) == 1 &&
         EVP_PKEY_CTX_set_params(sctx, sp) == 1 && EVP_PKEY_sign(sctx, der, &derLen, digest, SHA256_LEN) == 1;
    ECDSA_SIG *es = nullptr;
    if (ok) {
        const unsigned char *p = der;
        es = d2i_ECDSA_SIG(nullptr, &p, (long)derLen);
        ok = es && BN_bn2binpad(ECDSA_SIG_get0_r(es), sig, 32) == 32 && BN_bn2binpad(ECDSA_SIG_get0_s(es), sig + 32, 32) == 32;
    }
    ECDSA_SIG_free(es);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(d);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return ok;
}

static void expectSameAsOpenssl(SignFn sign, const std::vector<uint8_t> &priv, const std::vector<uint8_t> &digest,
                                const char *what)
{
    uint8_t ours[P256_SIG_LEN], ref[P256_SIG_LEN];
    TEST_ASSERT_TRUE_MESSAGE(opensslSignRfc6979(priv.data(), digest.data(), ref), what);
    TEST_ASSERT_TRUE_MESSAGE(sign(priv.data(), digest.data(), ours), what);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(ref, ours, P256_SIG_LEN, what);
}
#endif

// The vendored signer (KpUecc.cpp, the same source the X1 compiles) against OpenSSL for 256 seeded pseudo-random
// key/digest pairs plus the edge cases RFC 6979 is sensitive to.
static void expectMatchesOpensslRfc6979(SignFn sign)
{
#if defined(KP_CRYPTO_BACKEND_OPENSSL)
    auto n = hex(P256_N_HEX), nm1 = n, np1 = n;
    nm1[31]--;
    np1[31]++;
    std::vector<uint8_t> one(32, 0), zeros(32, 0x00), ffs(32, 0xff);
    one[31] = 1;
    char label[32];
    int compared = 0;
    for (int i = 0; i < 256; ++i) {
        uint8_t key[32], dig[32];
        snprintf(label, sizeof(label), "kp-key-%d", i);
        sha256(label, strlen(label), key);
        snprintf(label, sizeof(label), "kp-digest-%d", i);
        sha256(label, strlen(label), dig);
        if (i % 16 == 1)
            memset(key, 0, 2); // leading zero bytes in the private key
        if (i % 16 == 2)
            memset(dig, 0, 3); // leading zero bytes in the digest
        std::vector<uint8_t> k(key, key + 32), d(dig, dig + 32);
        if (!p256PrivateKeyValid(k.data()))
            continue;
        snprintf(label, sizeof(label), "seeded pair %d", i);
        expectSameAsOpenssl(sign, k, d, label);
        ++compared;
    }
    TEST_ASSERT_GREATER_OR_EQUAL(200, compared);
    auto fixtureKey = hex(KEY_DEVICE_IDENTITY_PRIV);
    for (const auto &key : {one, nm1, fixtureKey}) {
        for (const auto &d : {zeros, ffs, n, np1, nm1, one})
            expectSameAsOpenssl(sign, key, d, "edge case (key 1 / n-1 / fixture; digest 0, ff.., n, n+1, n-1, 1)");
    }
#else
    (void)sign;
    TEST_IGNORE_MESSAGE("needs the OpenSSL host backend");
#endif
}

static void test_uecc_signer_matches_openssl_rfc6979(void)
{
    expectMatchesOpensslRfc6979(&signNative);
}

static void test_uecc_word32_signer_matches_openssl_rfc6979(void)
{
    expectMatchesOpensslRfc6979(&kpuecc32::signDigest);
}

// --- helpers ---

static void test_constant_time_equal_and_wipe(void)
{
    uint8_t a[32], b[32];
    memset(a, 0x5A, sizeof(a));
    memcpy(b, a, sizeof(b));
    TEST_ASSERT_TRUE(constantTimeEqual(a, b, sizeof(a)));
    b[31] ^= 1;
    TEST_ASSERT_FALSE(constantTimeEqual(a, b, sizeof(a)));
    secureWipe(a, sizeof(a));
    TEST_ASSERT_TRUE(allZero(a, sizeof(a)));
}

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_sha256_nist_vectors);
    RUN_TEST(test_sha256_incremental_reproduces_transcript_hash);
    RUN_TEST(test_hmac_sha256_rfc4231_short_and_long_key);
    RUN_TEST(test_hkdf_rfc5869_multi_block_and_empty_salt);
    RUN_TEST(test_hkdf_expand_length_limits);
    RUN_TEST(test_hkdf_reproduces_handshake_key_schedule);
    RUN_TEST(test_fixture_public_keys_are_valid);
    RUN_TEST(test_point_validation_rejects_negative_vectors);
    RUN_TEST(test_private_scalar_range);
    RUN_TEST(test_ecdh_reproduces_fixture_from_both_sides);
    RUN_TEST(test_ecdh_rejects_all_zero_secret_and_invalid_inputs);
    RUN_TEST(test_generated_key_pairs_agree_and_sign);
    RUN_TEST(test_ecdsa_verifies_fixture_signatures);
    RUN_TEST(test_ecdsa_rejects_negative_vectors);
    RUN_TEST(test_ecdsa_sign_rfc6979_reproduces_fixture_signatures);
    RUN_TEST(test_ecdsa_sign_rejects_invalid_scalar);
    RUN_TEST(test_ecdsa_sign_fails_closed_with_wrong_public_key);
    RUN_TEST(test_p256_key_pair_matches);
    RUN_TEST(test_uecc_signer_dead_rng_fails_before_any_scalar_mult);
    RUN_TEST(test_uecc_signer_aborts_after_one_attempt_when_blinding_rng_fails);
    RUN_TEST(test_uecc_signer_transient_rng_failure_releases_no_signature);
    RUN_TEST(test_self_test_passes_and_fails_closed_on_rng_failure);
    RUN_TEST(test_ccm_reproduces_envelopes);
    RUN_TEST(test_ccm_rejects_tampering_and_wipes_output);
    RUN_TEST(test_ccm_decrypt_failure_wipes_output_whatever_the_backend);
    RUN_TEST(test_ccm_stream_reproduces_envelopes_across_a_burst);
    RUN_TEST(test_ccm_stream_rejects_tampering_and_oversize_and_wipes);
    RUN_TEST(test_point_encoding_validator);
    RUN_TEST(test_signature_scalar_validator);
    RUN_TEST(test_uecc_signer_reproduces_fixture_signatures);
    RUN_TEST(test_uecc_signer_rfc6979_appendix_a25_vectors);
    RUN_TEST(test_uecc_signer_matches_openssl_rfc6979);
    RUN_TEST(test_uecc_word32_signer_rfc6979_appendix_a25_vectors);
    RUN_TEST(test_uecc_word32_signer_matches_openssl_rfc6979);
    RUN_TEST(test_constant_time_equal_and_wipe);
    exit(UNITY_END());
}

void loop() {}
