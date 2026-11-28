// Second build of the vendored micro-ecc (src/modules/optional/KynoPlanGnss/third_party/micro-ecc/uECC.c.inc, the
// patched RFC 6979 signer) with 32-bit words and no assembly, the word size the X1's Cortex-M4 uses. The host's own
// KpUecc.cpp build uses 64-bit words, so without this copy the uECC_WORD_SIZE == 4 paths of the patch (bits2int,
// int2octets, the T_octets conversion) would only ever run on the device.
//
// The copy lives in namespace kpuecc32 (its curve and word types differ from the 64-bit build) and every external
// function is renamed: uECC.h declares them extern "C", so a namespace alone would not keep the link names apart.
// Blinding uses micro-ecc's default /dev/urandom RNG; the signature does not depend on it.
#include <SHA256.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define uECC_compress kp32_uECC_compress
#define uECC_compute_public_key kp32_uECC_compute_public_key
#define uECC_curve_private_key_size kp32_uECC_curve_private_key_size
#define uECC_curve_public_key_size kp32_uECC_curve_public_key_size
#define uECC_decompress kp32_uECC_decompress
#define uECC_get_rng kp32_uECC_get_rng
#define uECC_make_key kp32_uECC_make_key
#define uECC_secp160r1 kp32_uECC_secp160r1
#define uECC_secp192r1 kp32_uECC_secp192r1
#define uECC_secp224r1 kp32_uECC_secp224r1
#define uECC_secp256k1 kp32_uECC_secp256k1
#define uECC_secp256r1 kp32_uECC_secp256r1
#define uECC_set_rng kp32_uECC_set_rng
#define uECC_shared_secret kp32_uECC_shared_secret
#define uECC_sign kp32_uECC_sign
#define uECC_sign_deterministic kp32_uECC_sign_deterministic
#define uECC_valid_point kp32_uECC_valid_point
#define uECC_valid_public_key kp32_uECC_valid_public_key
#define uECC_verify kp32_uECC_verify

#define uECC_PLATFORM uECC_arch_other // portable C only: no asm_*.inc
#define uECC_WORD_SIZE 4

namespace kpuecc32
{
#include "modules/optional/KynoPlanGnss/KpUeccConfig.h" // same curve and optimisation settings as the device build
#include "modules/optional/KynoPlanGnss/third_party/micro-ecc/uECC.c.inc"

static_assert(sizeof(uECC_word_t) == 4, "the second micro-ecc build must use 32-bit words");

namespace
{
struct Ctx {
    uECC_HashContext base;
    SHA256 *sha;
};
SHA256 &sha(const uECC_HashContext *c)
{
    return *reinterpret_cast<const Ctx *>(c)->sha;
}
void init(const uECC_HashContext *c)
{
    sha(c).reset();
}
void update(const uECC_HashContext *c, const uint8_t *m, unsigned n)
{
    sha(c).update(m, n);
}
void finish(const uECC_HashContext *c, uint8_t *out)
{
    sha(c).finalize(out, 32);
}
} // namespace

unsigned wordSize()
{
    return (unsigned)sizeof(uECC_word_t);
}

bool signDigest(const uint8_t *priv, const uint8_t *digest, uint8_t *sig)
{
    SHA256 h;
    uint8_t tmp[2 * 32 + SHA256::BLOCK_SIZE];
    Ctx ctx = {{&init, &update, &finish, SHA256::BLOCK_SIZE, 32, tmp}, &h};
    return uECC_sign_deterministic(priv, digest, 32, &ctx.base, sig, uECC_secp256r1()) == 1;
}

bool publicKey(const uint8_t *priv, uint8_t *pub)
{
    pub[0] = 0x04;
    return uECC_compute_public_key(priv, pub + 1, uECC_secp256r1()) == 1;
}
} // namespace kpuecc32
