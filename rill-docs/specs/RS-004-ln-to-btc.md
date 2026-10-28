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

Only then may the user reveal the preimage. A client MAY explicitly select
direct unilateral settlement by omitting `cooperative-claim/v1` in both
authenticated handshake halves and requiring its absence in the signed terms.
It then reveals the preimage only in the validated claim witness. The provider
observes that outpoint spend and validates the witness preimage before settling
the hold. No cooperative proposal, nonce or partial signature is needed, and
missing local metadata MUST NOT select this mode or renew payment authority.

If cooperation is negotiated, the user reveals the preimage through the
bounded cooperative flow. The provider verifies it and settles the hold.
The provider MUST NOT issue a usable cooperative partial signature until it
possesses the valid preimage and positively reconciles settlement of the exact
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

The user asks for an exact amount at its destination, so the claim pays `C`
as its fee and `C` SHOULD be priced for the cooperative path to confirm in the
next block or so without overpaying. Both sides use the economical two-block
estimate of their own Bitcoin Core (`estimatesmartfee 2 ECONOMICAL`) or a
mempool API's `fastestFee`, never below their node's relay and mempool minimum,
and do not quote or request without one (regtest may use the node minimum):
- the client SHOULD request `min_claim_fee_reserve_sat` of at least the
  cooperative (key-path) claim at that estimate and the script-path claim at
  that minimum, and MUST NOT send the firm request when this exceeds its own
  `max_claim_fee_sat`;
- unless its operator fixes `C`, the provider SHOULD quote the larger of the
  same two amounts at its own estimate and the client's minimum. It answers
  `limits_unsatisfiable` when the client's minimum exceeds the provider's
  `max_claim_fee_sat`, since no claim could spend it, and
  `capacity_unavailable` when it has no estimate or its own reserve exceeds
  `max_claim_fee_sat`.

The claim vsizes are 99 vB (key path) and 143 vB (script path) to a P2WPKH
destination, and 111 vB and 155 vB to a P2TR destination.

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
`funder_role` `"provider"` (RS-003 shape), unsolicited and bound to the
contract hash, signed with its session key over `funding_binding_hash`, and
carrying the exact funding transaction. Version 1 has one attempt with
`binding_revision` 0 and no replacement. It records the signed funding bytes
and marks the swap's economic reservation dispatched before it broadcasts.
The client MUST verify the signature, that the binding names this contract,
the Taproot script, and `V`, and that the transaction bytes pay exactly that
output; it then appends the binding to its recovery record's
`funding_history` before waiting for `funding_confirmations`.

Other provider notices are `observation` payloads and carry no authority:
`hold_accepted`, `hold_settled`, `swap_aborted` (with a short `reason`, sent
only when nothing was funded), `refund_broadcast`, and `refund_confirmed`
(each with `refund_txid`).

A provider's hold invoice MUST outlive the offer: its expiry is at least
`terms_expiry + minimum_invoice_remaining_seconds`, so a client accepting just
before `terms_expiry` still has that long to pay.

The client learns the preimage-revealing claim is safe as in the previous
section, then broadcasts its unilateral claim. The provider learns the
preimage from the claim witness on chain (or from an optional
`preimage_reveal` observation, which it verifies against `payment_hash`) and
settles the hold invoice; it MUST settle before the earliest accepted HTLC
expiry or its Lightning backend will fail the HTLC and the provider loses `V`.
The claim's `settlement_confirmations` are the client's concern.

The client's first claim, cooperative or unilateral, SHOULD pay exactly `C`
(at most the signed `max_claim_fee_sat`), so the destination receives exactly
`D`. A provider SHOULD admit a cooperative claim paying exactly `C` once it
meets its node's relay and mempool minimum, without repricing the signed
reserve against a later estimate. If the claim stays unconfirmed, the client
keeps that fee for the first three quarters of the window ending at
`refund_lock_height - claim_confirmation_blocks`, then raises it linearly to
`max_claim_fee_sat` by that height. A smaller payout is the price of a claim
that is still unconfirmed late; losing the race to the refund would cost both
the Lightning payment and the coins.

If no claim reaches the provider before `refund_lock_height`, the provider
refunds to `provider_destination_script` and cancels the hold invoice only
once the refund has `refund_resolution_confirmations`, per the rule above.
