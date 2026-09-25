#include "rill_crypto.h"

/* The explicit Emscripten export list links the versioned C ABI. */
_Static_assert(RILL_CRYPTO_ABI_VERSION == 1u, "unexpected Rill crypto ABI");
