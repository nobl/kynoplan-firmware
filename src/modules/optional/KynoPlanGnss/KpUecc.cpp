// Build unit for the vendored micro-ecc (third_party/micro-ecc: kmackay/micro-ecc tag v1.0, BSD-2-Clause, Copyright 2014
// Kenneth MacKay; see VENDORED.txt there). Compiled as C++ inside extern "C" so the symbols match uECC.h, with the
// configuration pinned by KpUeccConfig.h. Compiled only where KpCrypto is.
#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)
#include "KpUeccConfig.h"

extern "C" {
#include "third_party/micro-ecc/uECC.c.inc"
}
#endif
