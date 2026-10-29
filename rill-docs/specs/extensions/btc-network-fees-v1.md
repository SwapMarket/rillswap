# Offer-bound Bitcoin network fees

Status: draft, implemented extension

Required feature: `btc-network-fees/v1`

Extension key: `org.rillswap/fee-policy-v1`

This extension applies only to `btc-to-ln/v1` and `ln-to-btc/v1`. It adds an
upfront estimated provider mining cost to the existing fixed and proportional
service fee. It does not reimburse actual costs or change the base profiles'
amount equations, mining prepayment, independent recovery, or client claim
reserve. Lightning routing costs remain inside the service fee.

## Signed announcement policy

The announcement extension contains exactly:

```json
{
  "model": "p2tr-cooperative-1in-2out/v1",
  "base_sat": "50",
  "proportional_millionths": 1000,
  "max_network_feerate_sat_kvb": "10000",
  "max_routing_fee_ppm": 1000
}
```

Amounts and feerates are canonical nonnegative decimal strings, with a positive
feerate ceiling. Both ppm fields are integers in `[0, 1000000]`. The service
coefficients MUST equal the announcement's existing `indicative_fee_policy`.
The model has no provider-controlled size, multiplier, or hidden margin.

The chargeable transaction is a cooperative Taproot key-path spend with one
input, two P2TR outputs and one 64-byte default-sighash Schnorr signature:
137 stripped bytes plus 68 witness/marker bytes, 616 weight units, **154 vbytes**.
Both Bitcoin directions use this estimate. Actual transaction sizes and fees
can differ; the provider bears that difference. Any desired margin belongs in
the advertised service coefficients, not an unadvertised network factor.

The policy commitment is the version-one tagged hash
`RillSwap/fee-policy/v1` over the canonical JSON policy, using the tagged-hash
construction in RS-001.

## Request binding and independent ceiling

The client MUST retain and authenticate the exact signed announcement it
selected, including its provider, network, profile and validity period. The
quote request extension contains exactly:

```json
{
  "offer_event_id": "1111111111111111111111111111111111111111111111111111111111111111",
  "policy_hash": "<64 lowercase hexadecimal characters>",
  "max_network_feerate_sat_kvb": "3000"
}
```

The ceiling MUST be chosen independently of the provider's claimed estimate,
using the client's trusted node/API and explicit local policy. Existing total
success-fee and spend-authorization limits remain mandatory. A client MUST NOT
silently replace the selected offer or raise these limits after requesting a
quote. Missing independent evidence MUST NOT be treated as an unlimited ceiling.

The reference clients permit at most twice their own trusted estimator's rate,
also bounded by the advertised ceiling. Different estimators can disagree;
an honest provider may be refused rather than silently widening the ceiling.

## Signed quote breakdown

Both indicative quote extensions and signed `ContractTerms.extensions` carry
the breakdown with exactly `offer_event_id`, `policy`, `feerate_sat_kvb`,
`estimated_at`, `issued_at`, `service_fee_sat`, and `network_fee_sat`.

For the base profile's principal `A` (Lightning principal for BTC to LN,
nominal Bitcoin payout for LN to BTC):

```text
service_fee_sat <= base_sat + ceil(A * proportional_millionths / 1000000)
network_fee_sat  = ceil(154 * feerate_sat_kvb / 1000)
success_fee_sat  = service_fee_sat + network_fee_sat
```

The advertised service formula is a ceiling, not an exact price: a provider
MAY discount the service fee, even below zero (a signed rebate), for example to
attract swaps that rebalance its liquidity. It MUST NOT charge more. The
network fee is never discounted or surcharged.

Clients MUST recompute these integers, verify the original announcement ID and
policy commitment, and enforce BOTH the advertised and requested feerate
ceilings. The fee sample MUST be at most 10 seconds old when the quote is
issued. Timestamps are assertions, not evidence that a provider's estimator is
honest. Independent limits provide the protection against inflated estimates.

The same frozen sample and economics MUST determine any reverse hold invoice
and its firm terms. Backend preparation MUST NOT renew an existing deadline.

## Negotiation, expiry, and routing

The feature MUST be required in both handshake halves and in the signed
contract. A missing breakdown, unilateral negotiation, or downgrade from an
offer advertising this policy MUST be rejected before acceptance or payment.

The quote's acceptance expiry MUST be after `issued_at` and no more than **60
seconds** later. A quote is expired at equality. Clients reject issuance more
than five seconds ahead of their clock. Clients recheck expiry immediately
before acceptance, including after recovery export. Acceptance expiry is NOT
a settlement or funding deadline. Once accepted, the signed economics stay
fixed across fee changes, delays and restarts; normal funding, invoice and
settlement deadlines continue to apply.

For provider-originated Lightning payments, the actual routing budget MUST be
bounded by the provider's absolute operator limit and the advertised
principal-based `max_routing_fee_ppm`. It MUST NOT be derived from the signed
service or success fee, which may be a discount or a rebate; a provider that
discounts bears its routing cost. The network component is not available for
routing. The implementation enforces the resulting absolute
limit through LND. No additional routing allowance is charged. The client's
own wallet routing fees for paying a reverse hold invoice are separate.

## Compatibility and upgrades

Only offers carrying this extension have a verified service/network formula.
Legacy announcement prices remain indicative: the existing absolute client
fee cap applies, and the browser requires review when the signed price is
worse than its displayed estimate. Legacy pricing is not presented as a
verified dynamic-fee policy. Historical accepted contracts are never repriced.

Absent configuration does not enable this extension. Historical sessions and
recovery documents keep their original negotiated features and economics.
There is no automatic store migration, repricing, reset or re-estimation of
accepted terms. Enabling or disabling this feature changes a provider's
immutable store policy: drain the previous store and explicitly provision a
new store at a different path. Keep the old store and recovery material.
Changing pricing coefficients alone does not change the store policy.

Old clients fail closed on the required feature. Update recovery tools before
enabling it: an older recovery implementation cannot validate a new featured
swap. New tools MUST continue to validate legacy records, and MUST validate
featured historical terms without requiring an unexpired quote or current
fee estimate.
