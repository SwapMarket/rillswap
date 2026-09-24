#include "rill_crypto.h"

#include <assert.h>
#include <string.h>
#include <threads.h>

typedef struct sign_job {
    const rill_crypto_context *context;
    rill_musig_attempt *attempt;
    const unsigned char *other_nonce;
    unsigned char partial[32];
    rill_crypto_status status;
} sign_job;

static int sign_in_thread(void *opaque_job) {
    sign_job *job = (sign_job *)opaque_job;
    job->status = rill_musig_partial_sign_once(
        job->context, job->attempt, job->other_nonce, job->partial);
    return 0;
}

static void fill(unsigned char *buffer, size_t length, unsigned char value) {
    size_t index;
    for (index = 0u; index < length; ++index) {
        buffer[index] = value;
    }
}

int main(void) {
    unsigned char context_random[32];
    unsigned char user_secret[32] = {0};
    unsigned char provider_secret[32] = {0};
    unsigned char odd_provider_secret[32] = {0};
    unsigned char user_key[33];
    unsigned char provider_key[33];
    unsigned char odd_provider_key[33];
    unsigned char tweak[32] = {0};
    unsigned char message[32];
    unsigned char cooperation_id[32];
    unsigned char user_random[32];
    unsigned char provider_random[32];
    unsigned char user_nonce[66];
    unsigned char provider_nonce[66];
    unsigned char user_partial[32];
    unsigned char provider_partial[32];
    unsigned char final_signature[64];
    unsigned char internal_key[32];
    unsigned char output_key[32];
    unsigned char shared_x[32];
    unsigned char invalid_scalar[32] = {0};
    unsigned char invalid_peer[32];
    unsigned char overlapping_secret[32];
    const unsigned char expected_internal_key[32] = {
        /* BIP327 reference.py at acdce4d50c61f81d9ec6534a804b1fb14e84e565, [1G, 2G]. */
        0x3b, 0x46, 0xd2, 0x62, 0xd2, 0xf6, 0x10, 0xe9,
        0x03, 0x8b, 0x44, 0xbe, 0xab, 0xdf, 0xe9, 0x7a,
        0xb5, 0xa0, 0xfe, 0xb8, 0x98, 0x70, 0xac, 0xc2,
        0x26, 0x4e, 0xdf, 0xb7, 0xf6, 0x3e, 0xc2, 0xec
    };
    const unsigned char expected_odd_internal_key[32] = {
        /* Same independent reference, ordered keys [1G, 3G]. */
        0x6e, 0x68, 0xb8, 0x37, 0xde, 0x28, 0x10, 0x10,
        0x18, 0x37, 0x1e, 0x7b, 0xf6, 0xe5, 0x9b, 0x58,
        0x52, 0xc9, 0xe3, 0x94, 0x72, 0x79, 0x4c, 0x28,
        0xfd, 0x95, 0x5c, 0x71, 0x4b, 0x81, 0x74, 0xba
    };
    int internal_parity = -1;
    int output_parity = -1;
    rill_crypto_context *context;
    rill_musig_attempt *user_attempt = NULL;
    rill_musig_attempt *provider_attempt = NULL;
    sign_job user_jobs[2];
    thrd_t user_threads[2];
    int thread_result;

    fill(context_random, sizeof(context_random), 0xa1u);
    fill(message, sizeof(message), 0xb2u);
    fill(cooperation_id, sizeof(cooperation_id), 0xc3u);
    fill(user_random, sizeof(user_random), 0xd4u);
    fill(provider_random, sizeof(provider_random), 0xe5u);
    user_secret[31] = 1u;
    provider_secret[31] = 2u;
    odd_provider_secret[31] = 3u;
    tweak[31] = 3u;

    assert(rill_crypto_abi_version() == 1u);
    context = rill_crypto_context_create(context_random);
    assert(context != NULL);
    assert(rill_public_key_create(context, user_secret, user_key) == RILL_CRYPTO_OK);
    assert(rill_public_key_create(context, provider_secret, provider_key) == RILL_CRYPTO_OK);
    assert(rill_nip44_shared_x(
        context, user_secret, &provider_key[1], shared_x) == RILL_CRYPTO_OK);
    assert(memcmp(shared_x, &provider_key[1], 32u) == 0);
    assert(rill_nip44_shared_x(
        context, provider_secret, &user_key[1], shared_x) == RILL_CRYPTO_OK);
    assert(memcmp(shared_x, &provider_key[1], 32u) == 0);
    fill(shared_x, 32u, 0xaau);
    assert(rill_nip44_shared_x(
        context, invalid_scalar, &provider_key[1], shared_x) ==
        RILL_CRYPTO_INVALID_SECRET_KEY);
    assert(memcmp(shared_x, invalid_scalar, 32u) == 0);
    fill(invalid_scalar, 32u, 0xffu);
    fill(shared_x, 32u, 0xaau);
    assert(rill_nip44_shared_x(
        context, invalid_scalar, &provider_key[1], shared_x) ==
        RILL_CRYPTO_INVALID_SECRET_KEY);
    assert(memcmp(shared_x, (unsigned char[32]){0}, 32u) == 0);
    fill(invalid_peer, 32u, 0xffu);
    fill(shared_x, 32u, 0xaau);
    assert(rill_nip44_shared_x(context, user_secret, invalid_peer, shared_x) ==
           RILL_CRYPTO_INVALID_PUBLIC_KEY);
    assert(memcmp(shared_x, (unsigned char[32]){0}, 32u) == 0);
    fill(shared_x, 32u, 0xaau);
    assert(rill_nip44_shared_x(NULL, user_secret, &provider_key[1], shared_x) ==
           RILL_CRYPTO_INVALID_ARGUMENT);
    assert(memcmp(shared_x, (unsigned char[32]){0}, 32u) == 0);
    fill(shared_x, 32u, 0xaau);
    assert(rill_nip44_shared_x(context, NULL, &provider_key[1], shared_x) ==
           RILL_CRYPTO_INVALID_ARGUMENT);
    assert(memcmp(shared_x, (unsigned char[32]){0}, 32u) == 0);
    fill(shared_x, 32u, 0xaau);
    assert(rill_nip44_shared_x(context, user_secret, NULL, shared_x) ==
           RILL_CRYPTO_INVALID_ARGUMENT);
    assert(memcmp(shared_x, (unsigned char[32]){0}, 32u) == 0);
    assert(rill_nip44_shared_x(context, user_secret, &provider_key[1], NULL) ==
           RILL_CRYPTO_INVALID_ARGUMENT);
    fill(shared_x, 32u, 0xaau);
    assert(rill_nip44_shared_x(context, user_secret, shared_x, shared_x) ==
           RILL_CRYPTO_INVALID_ARGUMENT);
    assert(memcmp(shared_x, (unsigned char[32]){0}, 32u) == 0);
    memcpy(overlapping_secret, user_secret, 32u);
    assert(rill_nip44_shared_x(
        context, overlapping_secret, &provider_key[1], overlapping_secret) ==
        RILL_CRYPTO_INVALID_ARGUMENT);
    assert(memcmp(overlapping_secret, (unsigned char[32]){0}, 32u) == 0);
    assert(rill_public_key_create(
        context, odd_provider_secret, odd_provider_key) == RILL_CRYPTO_OK);
    assert(rill_musig_internal_key(
        context, user_key, provider_key, internal_key, &internal_parity) ==
        RILL_CRYPTO_OK);
    assert(memcmp(internal_key, expected_internal_key, sizeof(internal_key)) == 0);
    assert(internal_parity == 0);
    assert(rill_musig_internal_key(
        context, user_key, odd_provider_key, internal_key, &internal_parity) ==
        RILL_CRYPTO_OK);
    assert(memcmp(
        internal_key, expected_odd_internal_key, sizeof(internal_key)) == 0);
    assert(internal_parity == 1);
    assert(rill_musig_internal_key(
        context, provider_key, user_key, output_key, &output_parity) ==
        RILL_CRYPTO_OK);
    assert(memcmp(
        expected_internal_key, output_key, sizeof(expected_internal_key)) != 0);
    assert(rill_musig_internal_key(
        context, user_key, user_key, internal_key, &internal_parity) ==
        RILL_CRYPTO_DUPLICATE_PUBLIC_KEY);
    assert(rill_musig_internal_key(
        context, user_key, provider_key, NULL, &internal_parity) ==
        RILL_CRYPTO_INVALID_ARGUMENT);
    assert(rill_musig_output_key(
        context, user_key, provider_key, tweak, output_key, &output_parity) ==
        RILL_CRYPTO_OK);
    assert(output_parity == 0 || output_parity == 1);
    assert(rill_musig_output_key(
        context, user_key, user_key, tweak, output_key, &output_parity) ==
        RILL_CRYPTO_DUPLICATE_PUBLIC_KEY);

    assert(rill_musig_begin(
        context,
        user_secret,
        user_key,
        provider_key,
        tweak,
        message,
        cooperation_id,
        user_random,
        &user_attempt,
        user_nonce) == RILL_CRYPTO_OK);
    assert(rill_musig_begin(
        context,
        provider_secret,
        user_key,
        provider_key,
        tweak,
        message,
        cooperation_id,
        provider_random,
        &provider_attempt,
        provider_nonce) == RILL_CRYPTO_OK);
    assert(rill_musig_public_nonce_validate(context, user_nonce) == RILL_CRYPTO_OK);
    memset(user_jobs, 0, sizeof(user_jobs));
    user_jobs[0].context = context;
    user_jobs[0].attempt = user_attempt;
    user_jobs[0].other_nonce = provider_nonce;
    user_jobs[1].context = context;
    user_jobs[1].attempt = user_attempt;
    user_jobs[1].other_nonce = provider_nonce;
    assert(thrd_create(&user_threads[0], sign_in_thread, &user_jobs[0]) == thrd_success);
    assert(thrd_create(&user_threads[1], sign_in_thread, &user_jobs[1]) == thrd_success);
    assert(thrd_join(user_threads[0], &thread_result) == thrd_success);
    assert(thrd_join(user_threads[1], &thread_result) == thrd_success);
    assert(
        (user_jobs[0].status == RILL_CRYPTO_OK &&
         user_jobs[1].status == RILL_CRYPTO_ATTEMPT_CONSUMED) ||
        (user_jobs[1].status == RILL_CRYPTO_OK &&
         user_jobs[0].status == RILL_CRYPTO_ATTEMPT_CONSUMED));
    if (user_jobs[0].status == RILL_CRYPTO_OK) {
        memcpy(user_partial, user_jobs[0].partial, sizeof(user_partial));
    } else {
        memcpy(user_partial, user_jobs[1].partial, sizeof(user_partial));
    }
    assert(rill_musig_partial_sign_once(
        context, user_attempt, provider_nonce, user_partial) ==
        RILL_CRYPTO_ATTEMPT_CONSUMED);
    assert(rill_musig_partial_sign_once(
        context, provider_attempt, user_nonce, provider_partial) == RILL_CRYPTO_OK);
    assert(rill_musig_partial_verify(
        context,
        user_key,
        provider_key,
        tweak,
        message,
        user_nonce,
        provider_nonce,
        0u,
        user_partial) == RILL_CRYPTO_OK);
    assert(rill_musig_partial_verify(
        context,
        user_key,
        provider_key,
        tweak,
        message,
        user_nonce,
        provider_nonce,
        1u,
        provider_partial) == RILL_CRYPTO_OK);
    assert(rill_musig_aggregate(
        context,
        user_key,
        provider_key,
        tweak,
        message,
        user_nonce,
        provider_nonce,
        user_partial,
        provider_partial,
        final_signature) == RILL_CRYPTO_OK);
    assert(rill_schnorr_verify(
        context, output_key, message, final_signature) == RILL_CRYPTO_OK);

    final_signature[0] ^= 1u;
    assert(rill_schnorr_verify(
        context, output_key, message, final_signature) ==
        RILL_CRYPTO_INVALID_SIGNATURE);

    rill_musig_attempt_destroy(user_attempt);
    rill_musig_attempt_destroy(provider_attempt);
    rill_crypto_context_destroy(context);
    return 0;
}
