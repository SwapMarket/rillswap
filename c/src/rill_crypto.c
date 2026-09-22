#include "rill_crypto.h"

#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_musig.h"
#include "secp256k1_schnorrsig.h"

struct rill_crypto_context {
    secp256k1_context *secp;
};

struct rill_musig_attempt {
    secp256k1_musig_secnonce secret_nonce;
    secp256k1_musig_pubnonce public_nonce;
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_keypair keypair;
    secp256k1_pubkey public_key;
    unsigned char message[32];
    atomic_int consumed;
};

typedef struct rill_musig_public_session {
    secp256k1_pubkey keys[2];
    secp256k1_musig_pubnonce nonces[2];
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_session session;
    secp256k1_xonly_pubkey output_key;
} rill_musig_public_session;

static void rill_wipe(void *pointer, size_t length) {
    volatile unsigned char *bytes = (volatile unsigned char *)pointer;
    while (length > 0u) {
        *bytes = 0u;
        ++bytes;
        --length;
    }
}

static int rill_context_valid(const rill_crypto_context *context) {
    return context != NULL && context->secp != NULL;
}

static rill_crypto_status rill_parse_keys(
    const rill_crypto_context *context,
    const unsigned char user_key33[33],
    const unsigned char provider_key33[33],
    secp256k1_pubkey keys[2]
) {
    if (!rill_context_valid(context) || user_key33 == NULL ||
        provider_key33 == NULL || keys == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    if (memcmp(user_key33, provider_key33, 33u) == 0) {
        return RILL_CRYPTO_DUPLICATE_PUBLIC_KEY;
    }
    if (secp256k1_ec_pubkey_parse(context->secp, &keys[0], user_key33, 33u) != 1 ||
        secp256k1_ec_pubkey_parse(context->secp, &keys[1], provider_key33, 33u) != 1) {
        return RILL_CRYPTO_INVALID_PUBLIC_KEY;
    }
    return RILL_CRYPTO_OK;
}

static rill_crypto_status rill_keyagg_tweaked(
    const rill_crypto_context *context,
    secp256k1_pubkey keys[2],
    const unsigned char tweak32[32],
    secp256k1_musig_keyagg_cache *cache,
    secp256k1_pubkey *output
) {
    const secp256k1_pubkey *key_pointers[2] = {&keys[0], &keys[1]};
    if (secp256k1_musig_pubkey_agg(
            context->secp, NULL, cache, key_pointers, 2u) != 1) {
        return RILL_CRYPTO_INTERNAL_ERROR;
    }
    if (secp256k1_musig_pubkey_xonly_tweak_add(
            context->secp, output, cache, tweak32) != 1) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    return RILL_CRYPTO_OK;
}

static rill_crypto_status rill_keyagg_internal(
    const rill_crypto_context *context,
    secp256k1_pubkey keys[2],
    secp256k1_musig_keyagg_cache *cache,
    secp256k1_pubkey *output
) {
    const secp256k1_pubkey *key_pointers[2] = {&keys[0], &keys[1]};
    if (secp256k1_musig_pubkey_agg(
            context->secp, NULL, cache, key_pointers, 2u) != 1 ||
        secp256k1_musig_pubkey_get(context->secp, output, cache) != 1) {
        return RILL_CRYPTO_INTERNAL_ERROR;
    }
    return RILL_CRYPTO_OK;
}

static rill_crypto_status rill_public_session_create(
    const rill_crypto_context *context,
    const unsigned char user_key33[33],
    const unsigned char provider_key33[33],
    const unsigned char tweak32[32],
    const unsigned char message32[32],
    const unsigned char user_nonce66[66],
    const unsigned char provider_nonce66[66],
    rill_musig_public_session *result
) {
    secp256k1_pubkey output;
    secp256k1_musig_aggnonce aggregate_nonce;
    const secp256k1_musig_pubnonce *nonce_pointers[2];
    rill_crypto_status status;

    if (!rill_context_valid(context) || tweak32 == NULL || message32 == NULL ||
        user_nonce66 == NULL || provider_nonce66 == NULL || result == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    status = rill_parse_keys(context, user_key33, provider_key33, result->keys);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    status = rill_keyagg_tweaked(
        context, result->keys, tweak32, &result->keyagg_cache, &output);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    if (secp256k1_xonly_pubkey_from_pubkey(
            context->secp, &result->output_key, NULL, &output) != 1) {
        return RILL_CRYPTO_INTERNAL_ERROR;
    }
    if (secp256k1_musig_pubnonce_parse(
            context->secp, &result->nonces[0], user_nonce66) != 1 ||
        secp256k1_musig_pubnonce_parse(
            context->secp, &result->nonces[1], provider_nonce66) != 1) {
        return RILL_CRYPTO_INVALID_NONCE;
    }
    nonce_pointers[0] = &result->nonces[0];
    nonce_pointers[1] = &result->nonces[1];
    if (secp256k1_musig_nonce_agg(
            context->secp, &aggregate_nonce, nonce_pointers, 2u) != 1 ||
        secp256k1_musig_nonce_process(
            context->secp,
            &result->session,
            &aggregate_nonce,
            message32,
            &result->keyagg_cache) != 1) {
        return RILL_CRYPTO_INVALID_NONCE;
    }
    return RILL_CRYPTO_OK;
}

uint32_t rill_crypto_abi_version(void) {
    return RILL_CRYPTO_ABI_VERSION;
}

rill_crypto_context *rill_crypto_context_create(const unsigned char random32[32]) {
    rill_crypto_context *context;
    if (random32 == NULL) {
        return NULL;
    }
    context = (rill_crypto_context *)calloc(1u, sizeof(*context));
    if (context == NULL) {
        return NULL;
    }
    context->secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (context->secp == NULL ||
        secp256k1_context_randomize(context->secp, random32) != 1) {
        rill_crypto_context_destroy(context);
        return NULL;
    }
    return context;
}

void rill_crypto_context_destroy(rill_crypto_context *context) {
    if (context == NULL) {
        return;
    }
    if (context->secp != NULL) {
        secp256k1_context_destroy(context->secp);
    }
    rill_wipe(context, sizeof(*context));
    free(context);
}

rill_crypto_status rill_public_key_create(
    const rill_crypto_context *context,
    const unsigned char secret_key32[32],
    unsigned char output33[33]
) {
    secp256k1_pubkey pubkey;
    size_t output_length = 33u;
    if (!rill_context_valid(context) || secret_key32 == NULL || output33 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    if (secp256k1_ec_pubkey_create(context->secp, &pubkey, secret_key32) != 1) {
        return RILL_CRYPTO_INVALID_SECRET_KEY;
    }
    if (secp256k1_ec_pubkey_serialize(
            context->secp,
            output33,
            &output_length,
            &pubkey,
            SECP256K1_EC_COMPRESSED) != 1 || output_length != 33u) {
        return RILL_CRYPTO_INTERNAL_ERROR;
    }
    return RILL_CRYPTO_OK;
}

rill_crypto_status rill_schnorr_sign(
    const rill_crypto_context *context,
    const unsigned char secret_key32[32],
    const unsigned char message32[32],
    const unsigned char auxiliary_random32[32],
    unsigned char signature64[64]
) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey public_key;
    rill_crypto_status result = RILL_CRYPTO_INTERNAL_ERROR;
    if (!rill_context_valid(context) || secret_key32 == NULL || message32 == NULL ||
        auxiliary_random32 == NULL || signature64 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    if (secp256k1_keypair_create(context->secp, &keypair, secret_key32) != 1) {
        return RILL_CRYPTO_INVALID_SECRET_KEY;
    }
    if (secp256k1_keypair_xonly_pub(context->secp, &public_key, NULL, &keypair) == 1 &&
        secp256k1_schnorrsig_sign32(
            context->secp,
            signature64,
            message32,
            &keypair,
            auxiliary_random32) == 1 &&
        secp256k1_schnorrsig_verify(
            context->secp, signature64, message32, 32u, &public_key) == 1) {
        result = RILL_CRYPTO_OK;
    }
    rill_wipe(&keypair, sizeof(keypair));
    return result;
}

rill_crypto_status rill_schnorr_verify(
    const rill_crypto_context *context,
    const unsigned char public_key32[32],
    const unsigned char message32[32],
    const unsigned char signature64[64]
) {
    secp256k1_xonly_pubkey public_key;
    if (!rill_context_valid(context) || public_key32 == NULL || message32 == NULL ||
        signature64 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    if (secp256k1_xonly_pubkey_parse(context->secp, &public_key, public_key32) != 1) {
        return RILL_CRYPTO_INVALID_PUBLIC_KEY;
    }
    if (secp256k1_schnorrsig_verify(
            context->secp, signature64, message32, 32u, &public_key) != 1) {
        return RILL_CRYPTO_INVALID_SIGNATURE;
    }
    return RILL_CRYPTO_OK;
}

rill_crypto_status rill_musig_internal_key(
    const rill_crypto_context *context,
    const unsigned char user_key33[33],
    const unsigned char provider_key33[33],
    unsigned char internal32[32],
    int *internal_parity
) {
    secp256k1_pubkey keys[2];
    secp256k1_pubkey internal;
    secp256k1_xonly_pubkey xonly_internal;
    secp256k1_musig_keyagg_cache cache;
    rill_crypto_status status;
    if (internal32 == NULL || internal_parity == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    status = rill_parse_keys(context, user_key33, provider_key33, keys);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    status = rill_keyagg_internal(context, keys, &cache, &internal);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    if (secp256k1_xonly_pubkey_from_pubkey(
            context->secp, &xonly_internal, internal_parity, &internal) != 1 ||
        secp256k1_xonly_pubkey_serialize(
            context->secp, internal32, &xonly_internal) != 1) {
        return RILL_CRYPTO_INTERNAL_ERROR;
    }
    return RILL_CRYPTO_OK;
}

rill_crypto_status rill_musig_output_key(
    const rill_crypto_context *context,
    const unsigned char user_key33[33],
    const unsigned char provider_key33[33],
    const unsigned char tweak32[32],
    unsigned char output32[32],
    int *output_parity
) {
    secp256k1_pubkey keys[2];
    secp256k1_pubkey output;
    secp256k1_xonly_pubkey xonly_output;
    secp256k1_musig_keyagg_cache cache;
    rill_crypto_status status;
    if (tweak32 == NULL || output32 == NULL || output_parity == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    status = rill_parse_keys(context, user_key33, provider_key33, keys);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    status = rill_keyagg_tweaked(context, keys, tweak32, &cache, &output);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    if (secp256k1_xonly_pubkey_from_pubkey(
            context->secp, &xonly_output, output_parity, &output) != 1 ||
        secp256k1_xonly_pubkey_serialize(
            context->secp, output32, &xonly_output) != 1) {
        return RILL_CRYPTO_INTERNAL_ERROR;
    }
    return RILL_CRYPTO_OK;
}

rill_crypto_status rill_musig_begin(
    const rill_crypto_context *context,
    const unsigned char secret_key32[32],
    const unsigned char user_key33[33],
    const unsigned char provider_key33[33],
    const unsigned char tweak32[32],
    const unsigned char message32[32],
    const unsigned char cooperation_id32[32],
    const unsigned char session_random32[32],
    rill_musig_attempt **attempt_output,
    unsigned char public_nonce66[66]
) {
    secp256k1_pubkey keys[2];
    secp256k1_pubkey tweaked_output;
    unsigned char own_serialized[33];
    unsigned char random_copy[32];
    size_t own_length = 33u;
    rill_musig_attempt *attempt;
    rill_crypto_status status;

    if (!rill_context_valid(context) || secret_key32 == NULL || tweak32 == NULL ||
        message32 == NULL || cooperation_id32 == NULL || session_random32 == NULL ||
        attempt_output == NULL || public_nonce66 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    *attempt_output = NULL;
    status = rill_parse_keys(context, user_key33, provider_key33, keys);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    attempt = (rill_musig_attempt *)calloc(1u, sizeof(*attempt));
    if (attempt == NULL) {
        return RILL_CRYPTO_ALLOCATION_FAILURE;
    }
    atomic_init(&attempt->consumed, 0);
    status = rill_keyagg_tweaked(
        context, keys, tweak32, &attempt->keyagg_cache, &tweaked_output);
    if (status != RILL_CRYPTO_OK ||
        secp256k1_keypair_create(context->secp, &attempt->keypair, secret_key32) != 1 ||
        secp256k1_keypair_pub(context->secp, &attempt->public_key, &attempt->keypair) != 1 ||
        secp256k1_ec_pubkey_serialize(
            context->secp,
            own_serialized,
            &own_length,
            &attempt->public_key,
            SECP256K1_EC_COMPRESSED) != 1) {
        rill_musig_attempt_destroy(attempt);
        return status == RILL_CRYPTO_OK ? RILL_CRYPTO_INVALID_SECRET_KEY : status;
    }
    if (memcmp(own_serialized, user_key33, 33u) != 0 &&
        memcmp(own_serialized, provider_key33, 33u) != 0) {
        rill_musig_attempt_destroy(attempt);
        return RILL_CRYPTO_INVALID_SECRET_KEY;
    }
    memcpy(attempt->message, message32, 32u);
    memcpy(random_copy, session_random32, 32u);
    if (secp256k1_musig_nonce_gen(
            context->secp,
            &attempt->secret_nonce,
            &attempt->public_nonce,
            random_copy,
            secret_key32,
            &attempt->public_key,
            message32,
            &attempt->keyagg_cache,
            cooperation_id32) != 1 ||
        secp256k1_musig_pubnonce_serialize(
            context->secp, public_nonce66, &attempt->public_nonce) != 1) {
        rill_wipe(random_copy, sizeof(random_copy));
        rill_musig_attempt_destroy(attempt);
        return RILL_CRYPTO_INTERNAL_ERROR;
    }
    rill_wipe(random_copy, sizeof(random_copy));
    *attempt_output = attempt;
    return RILL_CRYPTO_OK;
}

rill_crypto_status rill_musig_public_nonce_validate(
    const rill_crypto_context *context,
    const unsigned char public_nonce66[66]
) {
    secp256k1_musig_pubnonce nonce;
    if (!rill_context_valid(context) || public_nonce66 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    return secp256k1_musig_pubnonce_parse(context->secp, &nonce, public_nonce66) == 1
        ? RILL_CRYPTO_OK
        : RILL_CRYPTO_INVALID_NONCE;
}

rill_crypto_status rill_musig_partial_sign_once(
    const rill_crypto_context *context,
    rill_musig_attempt *attempt,
    const unsigned char other_nonce66[66],
    unsigned char partial32[32]
) {
    secp256k1_musig_pubnonce other_nonce;
    secp256k1_musig_aggnonce aggregate_nonce;
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig partial;
    const secp256k1_musig_pubnonce *nonce_pointers[2];
    int success;

    if (!rill_context_valid(context) || attempt == NULL || other_nonce66 == NULL ||
        partial32 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    if (atomic_exchange_explicit(
            &attempt->consumed, 1, memory_order_acq_rel) != 0) {
        return RILL_CRYPTO_ATTEMPT_CONSUMED;
    }
    success = secp256k1_musig_pubnonce_parse(
        context->secp, &other_nonce, other_nonce66);
    nonce_pointers[0] = &attempt->public_nonce;
    nonce_pointers[1] = &other_nonce;
    if (success == 1) {
        success = secp256k1_musig_nonce_agg(
            context->secp, &aggregate_nonce, nonce_pointers, 2u);
    }
    if (success == 1) {
        success = secp256k1_musig_nonce_process(
            context->secp,
            &session,
            &aggregate_nonce,
            attempt->message,
            &attempt->keyagg_cache);
    }
    if (success == 1) {
        success = secp256k1_musig_partial_sign(
            context->secp,
            &partial,
            &attempt->secret_nonce,
            &attempt->keypair,
            &attempt->keyagg_cache,
            &session);
    } else {
        rill_wipe(&attempt->secret_nonce, sizeof(attempt->secret_nonce));
    }
    if (success == 1) {
        success = secp256k1_musig_partial_sig_verify(
            context->secp,
            &partial,
            &attempt->public_nonce,
            &attempt->public_key,
            &attempt->keyagg_cache,
            &session);
    }
    if (success == 1) {
        success = secp256k1_musig_partial_sig_serialize(
            context->secp, partial32, &partial);
    }
    rill_wipe(&attempt->keypair, sizeof(attempt->keypair));
    return success == 1 ? RILL_CRYPTO_OK : RILL_CRYPTO_INVALID_NONCE;
}

rill_crypto_status rill_musig_partial_verify(
    const rill_crypto_context *context,
    const unsigned char user_key33[33],
    const unsigned char provider_key33[33],
    const unsigned char tweak32[32],
    const unsigned char message32[32],
    const unsigned char user_nonce66[66],
    const unsigned char provider_nonce66[66],
    size_t signer_index,
    const unsigned char partial32[32]
) {
    rill_musig_public_session public_session;
    secp256k1_musig_partial_sig partial;
    rill_crypto_status status;
    if (signer_index > 1u || partial32 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    status = rill_public_session_create(
        context,
        user_key33,
        provider_key33,
        tweak32,
        message32,
        user_nonce66,
        provider_nonce66,
        &public_session);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    if (secp256k1_musig_partial_sig_parse(
            context->secp, &partial, partial32) != 1 ||
        secp256k1_musig_partial_sig_verify(
            context->secp,
            &partial,
            &public_session.nonces[signer_index],
            &public_session.keys[signer_index],
            &public_session.keyagg_cache,
            &public_session.session) != 1) {
        return RILL_CRYPTO_INVALID_SIGNATURE;
    }
    return RILL_CRYPTO_OK;
}

rill_crypto_status rill_musig_aggregate(
    const rill_crypto_context *context,
    const unsigned char user_key33[33],
    const unsigned char provider_key33[33],
    const unsigned char tweak32[32],
    const unsigned char message32[32],
    const unsigned char user_nonce66[66],
    const unsigned char provider_nonce66[66],
    const unsigned char user_partial32[32],
    const unsigned char provider_partial32[32],
    unsigned char signature64[64]
) {
    rill_musig_public_session public_session;
    secp256k1_musig_partial_sig partials[2];
    const secp256k1_musig_partial_sig *partial_pointers[2];
    rill_crypto_status status;
    size_t index;
    if (user_partial32 == NULL || provider_partial32 == NULL || signature64 == NULL) {
        return RILL_CRYPTO_INVALID_ARGUMENT;
    }
    status = rill_public_session_create(
        context,
        user_key33,
        provider_key33,
        tweak32,
        message32,
        user_nonce66,
        provider_nonce66,
        &public_session);
    if (status != RILL_CRYPTO_OK) {
        return status;
    }
    if (secp256k1_musig_partial_sig_parse(
            context->secp, &partials[0], user_partial32) != 1 ||
        secp256k1_musig_partial_sig_parse(
            context->secp, &partials[1], provider_partial32) != 1) {
        return RILL_CRYPTO_INVALID_SIGNATURE;
    }
    for (index = 0u; index < 2u; ++index) {
        if (secp256k1_musig_partial_sig_verify(
                context->secp,
                &partials[index],
                &public_session.nonces[index],
                &public_session.keys[index],
                &public_session.keyagg_cache,
                &public_session.session) != 1) {
            return RILL_CRYPTO_INVALID_SIGNATURE;
        }
        partial_pointers[index] = &partials[index];
    }
    if (secp256k1_musig_partial_sig_agg(
            context->secp,
            signature64,
            &public_session.session,
            partial_pointers,
            2u) != 1 ||
        secp256k1_schnorrsig_verify(
            context->secp,
            signature64,
            message32,
            32u,
            &public_session.output_key) != 1) {
        return RILL_CRYPTO_INVALID_SIGNATURE;
    }
    return RILL_CRYPTO_OK;
}

void rill_musig_attempt_destroy(rill_musig_attempt *attempt) {
    if (attempt == NULL) {
        return;
    }
    rill_wipe(attempt, sizeof(*attempt));
    free(attempt);
}
