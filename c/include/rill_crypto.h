#ifndef RILL_CRYPTO_H
#define RILL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(RILL_CRYPTO_SHARED)
#  if defined(RILL_CRYPTO_BUILD)
#    define RILL_API __declspec(dllexport)
#  else
#    define RILL_API __declspec(dllimport)
#  endif
#else
#  define RILL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define RILL_CRYPTO_ABI_VERSION 1u
#define RILL_SECRET_KEY_SIZE 32u
#define RILL_XONLY_PUBLIC_KEY_SIZE 32u
#define RILL_COMPRESSED_PUBLIC_KEY_SIZE 33u
#define RILL_MESSAGE_SIZE 32u
#define RILL_SCHNORR_SIGNATURE_SIZE 64u
#define RILL_MUSIG_PUBLIC_NONCE_SIZE 66u
#define RILL_MUSIG_PARTIAL_SIGNATURE_SIZE 32u

typedef enum rill_crypto_status {
    RILL_CRYPTO_OK = 0,
    RILL_CRYPTO_INVALID_ARGUMENT = 1,
    RILL_CRYPTO_INVALID_SECRET_KEY = 2,
    RILL_CRYPTO_INVALID_PUBLIC_KEY = 3,
    RILL_CRYPTO_DUPLICATE_PUBLIC_KEY = 4,
    RILL_CRYPTO_INVALID_SIGNATURE = 5,
    RILL_CRYPTO_INVALID_NONCE = 6,
    RILL_CRYPTO_ATTEMPT_CONSUMED = 7,
    RILL_CRYPTO_ALLOCATION_FAILURE = 8,
    RILL_CRYPTO_INTERNAL_ERROR = 9
} rill_crypto_status;

typedef struct rill_crypto_context rill_crypto_context;
typedef struct rill_musig_attempt rill_musig_attempt;

/*
 * A context must outlive every attempt created from it. Context and attempt
 * destruction must not race any operation using the same object.
 */

RILL_API uint32_t rill_crypto_abi_version(void);

/* random32 must contain fresh process-local randomness. */
RILL_API rill_crypto_context *rill_crypto_context_create(
    const unsigned char random32[32]
);
RILL_API void rill_crypto_context_destroy(rill_crypto_context *context);

RILL_API rill_crypto_status rill_public_key_create(
    const rill_crypto_context *context,
    const unsigned char secret_key32[32],
    unsigned char compressed_public_key33[33]
);

RILL_API rill_crypto_status rill_schnorr_sign(
    const rill_crypto_context *context,
    const unsigned char secret_key32[32],
    const unsigned char message32[32],
    const unsigned char auxiliary_random32[32],
    unsigned char signature64[64]
);

RILL_API rill_crypto_status rill_schnorr_verify(
    const rill_crypto_context *context,
    const unsigned char xonly_public_key32[32],
    const unsigned char message32[32],
    const unsigned char signature64[64]
);

/* Public keys are aggregated in the exact user, provider order. */
RILL_API rill_crypto_status rill_musig_output_key(
    const rill_crypto_context *context,
    const unsigned char user_public_key33[33],
    const unsigned char provider_public_key33[33],
    const unsigned char tap_tweak32[32],
    unsigned char output_xonly_public_key32[32],
    int *output_parity
);

/*
 * Creates a one-shot attempt for one exact key order, tweak, and message.
 * session_random32 must be fresh uniform secret randomness. cooperation_id32
 * is public unique context. The returned handle cannot be serialized or copied.
 */
RILL_API rill_crypto_status rill_musig_begin(
    const rill_crypto_context *context,
    const unsigned char secret_key32[32],
    const unsigned char user_public_key33[33],
    const unsigned char provider_public_key33[33],
    const unsigned char tap_tweak32[32],
    const unsigned char message32[32],
    const unsigned char cooperation_id32[32],
    const unsigned char session_random32[32],
    rill_musig_attempt **attempt,
    unsigned char public_nonce66[66]
);

RILL_API rill_crypto_status rill_musig_public_nonce_validate(
    const rill_crypto_context *context,
    const unsigned char public_nonce66[66]
);

/*
 * Every invocation atomically consumes the attempt, including an invocation
 * that fails. Concurrent callers cannot both sign; one receives CONSUMED.
 */
RILL_API rill_crypto_status rill_musig_partial_sign_once(
    const rill_crypto_context *context,
    rill_musig_attempt *attempt,
    const unsigned char other_public_nonce66[66],
    unsigned char partial_signature32[32]
);

RILL_API rill_crypto_status rill_musig_partial_verify(
    const rill_crypto_context *context,
    const unsigned char user_public_key33[33],
    const unsigned char provider_public_key33[33],
    const unsigned char tap_tweak32[32],
    const unsigned char message32[32],
    const unsigned char user_public_nonce66[66],
    const unsigned char provider_public_nonce66[66],
    size_t signer_index,
    const unsigned char partial_signature32[32]
);

/* Verifies both partials and the final BIP340 signature before returning it. */
RILL_API rill_crypto_status rill_musig_aggregate(
    const rill_crypto_context *context,
    const unsigned char user_public_key33[33],
    const unsigned char provider_public_key33[33],
    const unsigned char tap_tweak32[32],
    const unsigned char message32[32],
    const unsigned char user_public_nonce66[66],
    const unsigned char provider_public_nonce66[66],
    const unsigned char user_partial_signature32[32],
    const unsigned char provider_partial_signature32[32],
    unsigned char signature64[64]
);

/*
 * Destruction wipes keypair and secret nonce storage. NULL is accepted.
 * Destruction must not race partial signing or another destruction.
 */
RILL_API void rill_musig_attempt_destroy(rill_musig_attempt *attempt);

#ifdef __cplusplus
}
#endif

#endif
