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
