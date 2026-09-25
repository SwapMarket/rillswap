# RS-003: BTC to Lightning profile

Status: pre-release draft

Version: `btc-to-ln/v1`

The state sequence is `NEGOTIATING`, `TERMS_ACCEPTED`, `RECOVERY_DURABLE`,
`FUNDING_OBSERVED`, `FUNDING_CONFIRMED`, `LN_PAYMENT_PENDING`,
`PREIMAGE_KNOWN`, `CLAIM_PENDING`, `COMPLETED`. Before funding a failed swap is
`ABORTED`. A funded unpaid swap proceeds through `REFUND_WAIT`,
`REFUND_PENDING`, `REFUNDED`. Ambiguous effects enter
`RECONCILIATION_REQUIRED` without erasing prior knowledge.

The user supplies a fixed-amount BOLT11 invoice from a receiver whose secret
handling the user trusts. Terms bind the decoded amount, payment hash, network,
both contract keys, fees, exact contract, confirmation count, destinations,
and deadlines. The contract value is Lightning sats plus success fee.

The user MUST durably export recovery material before funding. The provider
MUST independently validate the exact funding transaction and required best
chain confirmations before initiating payment.

For current validated height `h`, first refundable block `R`, and latest
outgoing HTLC exposure `E_out`, provider policy MUST establish
`E_out + delta_learn_and_claim < R`. It MUST persist payment intent, hash,
route, absolute exposure, attempt identity, and fee cap before submission.
An unknown RPC result is reconciled by payment hash and attempt, never retried
as a new payment merely because the call failed.

Once the provider knows a valid preimage it has unilateral claim authority.
A cooperative claim is optional. The client MUST validate the exact
transaction and valid preimage before issuing its partial signature. The UI
MUST distinguish seeing provider claim authority from independently observing
receipt by the invoice destination.

If the provider does not obtain claim authority, the user monitors through
refund eligibility, constructs or fee-bumps the unilateral refund, broadcasts,
and continues until the configured confirmation depth. The claim branch
remains valid after the refund height, so eligibility alone is not completion.

## Quotes and firm requests

No economic message is valid before `handshake_confirm`. Every message below
is an ordinary application envelope signed by the sender session key
(RS-001 section 8). Requests have null `in_reply_to` and null `contract_hash`.
Each request has exactly one terminal response. The response replies to the
request and uses the next provider sequence number. An exact replay of a
request returns the recorded response, even after the offer has expired.

`quote_request` carries `QuoteRequestV1`. It has exactly `kind`
(`"btc-to-ln"`), `mode`, `lightning_principal_sat` (a positive decimal sat
string), and `extensions`. When `mode` is `"firm"`, it additionally has
exactly `invoice`, `client_contract_compressed_key`,
`recovery_authorization_xonly_key`, `client_destination_script`, and
`limits`.

- **Indicative request** (`mode` is `"indicative"`). It carries no invoice,
  payment hash, destination, or contract key, so a client can shop without
  exposing a swap. The provider answers with `quote_offer` or `error`. A
  session MAY carry at most 8 indicative requests. An indicative quote grants
  no authority and commits nobody.
- **Firm request** (`mode` is `"firm"`). It is the first and only
  `quote_request` of a fresh session with the selected provider. A provider
  MUST answer `unsupported_request` to a firm request that follows any other
  request in its session, and to any request after a firm one.
  - `invoice` is a lowercase BOLT11 string of at most 2048 characters. Its
    whole-satoshi amount MUST equal `lightning_principal_sat`.
  - `client_destination_script` is a version-1 destination script (P2WPKH
    or P2TR).
  - `limits` has exactly `max_success_fee_sat`, `max_funding_fee_sat`,
    `max_claim_fee_sat`, `max_refund_fee_sat` (decimal sat strings), and
    `max_refund_lock_height` (a block height).
  - The provider answers with `terms_offer` or `error`.

`quote_offer` carries `QuoteOfferV1`. It has exactly the following members:
- `kind`;
- `indicative` (the JSON value `true`);
- `economics`, a `BtcToLnEconomics` object that echoes `L`;
- `funding_confirmations`, `settlement_confirmations`, and
  `refund_resolution_confirmations`;
- `reference_height` and `max_refund_delay_blocks`;
- `max_funding_fee_sat`, `max_claim_fee_sat`, and `max_refund_fee_sat`;
- `minimum_invoice_remaining_seconds`;
- `expires_at`;
- `extensions`.

The refund delay is `(refund_lock_height + 1) - reference_height`, measured to
the first refund-eligible block, not to a completed refund. The fee members
are caps, not estimates. A later firm offer from the same provider is not
bound by an indicative quote, but the client checks it against its own
`limits`.

`terms_offer` carries exactly `terms`, a `ProviderTermsV1` object, and
`provider_terms_signature`, a signature by the provider identity key using
`RillSwap/provider-terms/v1` (RS-001 section 6). Its envelope `contract_hash`
equals `terms.contract_hash`. The terms MUST be `btc-to-ln/v1`, with the
provider as claimant and the client as refund party. They MUST satisfy all of
the following:
- they bind the decoded invoice and the session `handshake_hash`;
- they echo the request's client contract key, recovery key, and destination
  script exactly;
- they set `lightning_principal_sat` to `L`;
- every fee is within `limits`;
- `refund_lock_height <= max_refund_lock_height`.

The client MUST verify every term independently before `terms_accept`.

`error` carries `ErrorV1`, which has exactly `code` and `message`. `code` is
one of the following:
- `amount_out_of_range`;
- `capacity_unavailable`;
- `invoice_unacceptable`;
- `limits_unsatisfiable`;
- `request_unacceptable`;
- `unsupported_request`.

`message` is at most 256 printable ASCII characters and never reveals a
parsing, decryption, payment-status, or hash-ownership oracle. Errors are sent
only for authenticated, admitted requests. Undecodable input gets no reply.

Before exposing a `terms_offer`, the provider MUST durably reserve its payment
hash in the same transaction that records the offer. A firm request whose hash
is already reserved by another session gets `request_unacceptable`, while a
replay of the original request still returns its recorded offer.
Reservations are never released because an offer expired: an old signed
contract may still be funded. A provider store that cannot prove a complete
hash-reservation history MUST NOT issue firm offers. Fresh sessions keep the
invoice private to the selected provider. They cannot stop a client from
racing the same invoice at several providers, and possessing an invoice does
not authenticate its owner.

## Acceptance, funding, and settlement messages

Payload structure is defined by `schemas/wire/settlement-v1.schema.json`.
Every message below is a session-key-signed envelope in the post-confirm
sender streams (RS-001 section 8) with `contract_hash` set to the accepted
contract hash.

- `terms_accept` (client): replies (`in_reply_to`) to the provider's
  `terms_offer`. The payload is `{acceptance, client_acceptance_signature}`.
  `acceptance` is `ClientAcceptanceV1` for this session, transcript, and
  contract. The provider admits it only when all of these hold:
  - the offer is the one it recorded;
  - `terms_expiry` has not passed;
  - the invoice still has `minimum_invoice_remaining_seconds` left.

  Admission atomically moves the session to an accepted state that idle
  expiry never deletes. The provider answers with `ack`
  `{acknowledged_message_id}`. The client MUST export recovery material before
  sending `terms_accept`.
- `funding_binding` (client, unsolicited, `in_reply_to` null): the payload is
  `{binding, funding_binding_signature, funding_transaction}`. `binding` is the
  RS-001 `FundingBindingV1` signed by the client session key.
  `funding_transaction` is the exact serialized transaction. The provider
  checks it statically against the binding and terms. It records the binding
  and answers `ack`. It then independently retrieves the transaction from its
  own node and waits for `funding_confirmations` of the exact unspent contract
  output before any payment.
- `observation` (provider, unsolicited): `payment_settled` carries the
  preimage the client can check against the payment hash. `payment_failed`
  says the provider will not pay, so the client waits for refund eligibility.
  `claim_broadcast` names the provider's claim transaction. Observations
  inform only. The client still verifies the preimage and the chain itself.

Version one uses the unilateral claim leaf. Cooperative MuSig2 claims are
optional and not yet negotiated. A provider using LND `SendPaymentV2` bounds
the absolute HTLC expiry with `cltv_limit` so that it never exceeds
`timing_policy.max_outgoing_htlc_expiry_height`.
