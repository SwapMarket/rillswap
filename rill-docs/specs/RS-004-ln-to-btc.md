# RS-004: Lightning to BTC profile

Status: pre-release draft

Version: `ln-to-btc/v1`

The state sequence is `NEGOTIATING`, `TERMS_ACCEPTED`, `RECOVERY_DURABLE`,
`HOLD_INVOICE_OPEN`, `LN_HELD`, `FUNDING_PENDING`, `FUNDING_CONFIRMED`,
`CLAIM_READY`, `PREIMAGE_RELEASED`, followed by `LN_SETTLEMENT_PENDING` and/or
`CLAIM_PENDING`, then `COMPLETED`. An unfunded swap cancels the hold and is
`ABORTED`. A funded unclaimed swap proceeds through provider refund evidence,
then hold cancellation, then `REFUNDED`.

The user creates a random 32-byte preimage and durably saves it and the swap
key before payment. The provider creates a hold invoice for its SHA256 hash.
The provider MUST observe invoice state `ACCEPTED`, exact amount, and every
accepted HTLC part. It MUST use the earliest relevant part expiry and account
for MPP totals.

For first refundable block `R` and earliest accepted incoming expiry `E_in`,
provider policy MUST establish
`R + delta_refund_and_ln_resolution < E_in`, including backend automatic
cancellation and force-close resolution assumptions, before funding.

Before revealing the preimage, the user independently validates the funding
outpoint, value, complete P2TR commitment, required confirmations, current
height, remaining budget, destination, and fee viability. It MUST construct
and sign a valid unilateral claim and durably record that plan. For current
height `h`, policy MUST establish `h + delta_claim_confirmation < R`.

Only then may the user reveal the preimage. The provider verifies it and may
settle the hold. The provider MUST NOT issue a usable cooperative partial
signature before it possesses the valid preimage and has a safely settleable
accepted payment. If cooperation fails, the user broadcasts and fee-bumps the
unilateral claim.

If no claim occurs, the provider MUST obtain and independently verify required
refund confirmation evidence before canceling the held invoice. Refund height
arrival or an unconfirmed refund is insufficient because the claim remains
valid.

## Quotes and firm requests

The session, envelope, replay, and error rules of RS-003 "Quotes and firm
requests" apply unchanged; only the payloads differ. A provider that does not
serve this profile answers `unsupported_request`.

`quote_request` carries `QuoteRequestV1` with `kind` `"ln-to-btc"`. It has
exactly `kind`, `mode`, `nominal_payout_sat` (`D`, a positive decimal sat
string), and `extensions`. When `mode` is `"firm"`, it additionally has exactly
`payment_hash`, `client_contract_compressed_key`,
`recovery_authorization_xonly_key`, `client_destination_script`, and `limits`.

- `payment_hash` is the SHA256 of a 32-byte preimage the client generated and
  durably saved before sending the request. The client never reveals the
  preimage before `CLAIM_READY`. A hash already reserved by another session
  gets `request_unacceptable`.
- `client_destination_script` is the version-1 script the claim pays.
- `limits` has exactly `max_success_fee_sat`, `min_claim_fee_reserve_sat`,
  `max_claim_fee_sat` (decimal sat strings), `min_refund_lock_height`, and
  `max_incoming_htlc_expiry_height` (block heights). The client is the
  claimant: it needs enough reserve `C` and enough blocks before the provider
  may refund, and it bounds how long its Lightning funds may stay held.

`quote_offer` carries `QuoteOfferV1` with `kind` `"ln-to-btc"` and exactly:
`kind`; `indicative` (`true`); `economics`, an `LnToBtcEconomics` object that
echoes `D`; `funding_confirmations`, `settlement_confirmations`, and
`refund_resolution_confirmations`; `reference_height`; `refund_delay_blocks`
(`(refund_lock_height + 1) - reference_height`); 
`incoming_htlc_expiry_delta_blocks`
(`min_incoming_htlc_expiry_height - reference_height`, strictly greater than
the refund delay); `max_funding_fee_sat`, `max_claim_fee_sat`, and
`max_refund_fee_sat`; `expires_at`; `extensions`.

`terms_offer` carries exactly `terms` (`ProviderTermsV1`),
`provider_terms_signature`, and `hold_invoice`, a lowercase BOLT11 hold
invoice of at most 2048 characters for `H` sat whose payment hash is the
request's `payment_hash` and whose payee is the provider's Lightning node.
The terms MUST be `ln-to-btc/v1`, with the client as claimant and the provider
as refund party. They MUST satisfy all of the following:
- they bind the decoded hold invoice (`invoice_binding`) and the session
  `handshake_hash`;
- they echo the request's client contract key, recovery key, and destination
  script exactly;
- they set `nominal_payout_sat` to `D` and `mining_prepayment_sat` to `"0"`
  unless the `org.rillswap/mining-prepayment/v1` extension was negotiated;
- `success_fee_sat <= max_success_fee_sat`,
  `claim_fee_reserve_sat >= min_claim_fee_reserve_sat`,
  `max_claim_fee_sat <= limits.max_claim_fee_sat`;
- `refund_lock_height >= min_refund_lock_height`;
- `timing_policy.min_incoming_htlc_expiry_height <=
  max_incoming_htlc_expiry_height`.

The client MUST verify every term independently before `terms_accept`, and
paying the hold invoice is what commits it: the client MUST pay with a final
CLTV expiry no lower than `min_incoming_htlc_expiry_height`, MUST NOT pay
before its recovery record is durable, and MUST NOT pay after `terms_expiry`.
The provider MUST reserve `payment_hash` durably in the same transaction that
records the offer, exactly as RS-003 reserves the invoice hash.

## Funding and settlement

After `terms_accept`, the provider watches the hold invoice. It funds the
contract only once the invoice is `ACCEPTED` with total held amount exactly
`H` and every accepted HTLC's expiry `E_in` satisfies
`refund_lock_height + 1 + refund_and_ln_resolution_blocks < E_in`, and only
while `tip + funding_confirmations + client_response_blocks +
claim_confirmation_blocks < refund_lock_height`. Otherwise it cancels the hold
invoice and the swap is `ABORTED`. The provider sends `funding_binding` with
`funder_role` `"provider"` (RS-003 shape).

The client learns the preimage-revealing claim is safe as in the previous
section, then broadcasts its unilateral claim. The provider learns the
preimage from the claim witness on chain (or from an optional
`preimage_reveal` observation, which it verifies against `payment_hash`) and
settles the hold invoice; it MUST settle before the earliest accepted HTLC
expiry or its Lightning backend will fail the HTLC and the provider loses `V`.
The claim's `settlement_confirmations` are the client's concern.

If no claim reaches the provider before `refund_lock_height`, the provider
refunds to `provider_destination_script` and cancels the hold invoice only
once the refund has `refund_resolution_confirmations`, per the rule above.
