#pragma once

// Configuration of the vendored micro-ecc (third_party/micro-ecc, BSD-2-Clause, Kenneth MacKay; see VENDORED.txt): P-256
// only. Every user includes this instead of uECC.h, so the library (KpUecc.cpp) and its callers see the same settings
// without env build flags.
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 0
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 1
#define uECC_SUPPORTS_secp256k1 0
#define uECC_SUPPORT_COMPRESSED_POINT 0
// Level 2 needs only asm_arm.inc; the level-3 mult/square tables are not vendored.
#define uECC_OPTIMIZATION_LEVEL 2

#include "third_party/micro-ecc/uECC.h"
