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
    unsigned char user_key[33];
    unsigned char provider_key[33];
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
    unsigned char output_key[32];
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
    tweak[31] = 3u;

    assert(rill_crypto_abi_version() == 1u);
    context = rill_crypto_context_create(context_random);
    assert(context != NULL);
    assert(rill_public_key_create(context, user_secret, user_key) == RILL_CRYPTO_OK);
    assert(rill_public_key_create(context, provider_secret, provider_key) == RILL_CRYPTO_OK);
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
