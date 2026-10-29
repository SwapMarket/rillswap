# Balance-aware provider fees

Status: draft, provider-local policy (no additional negotiated feature)

Providers MAY discount their normal service fee to incentivize swaps that
repair liquidity shortages. A negative service fee is a rebate. Native
Bitcoin and ERC20 profiles already carry signed success fees (RS-001,
RS-003, RS-004, RS-010); lock amounts and hold invoices remain positive.
External venues, automatic treasury transfers and shared signing keys are
outside this policy.

## Service pricing and costs

For principal `P`, normal service fee `N`, curve adjustment `D`, negative
operator floor in millionths `F`, and remaining rebate allowance `B`:

```
service = max(N + min(quantize(D), 0), -floor(-F * P / 1e6), -B)
```

The normal fee is the advertised base plus the proportional ceiling.
Positive adjustments MUST NOT increase it. The operator's negative floor
MUST be no deeper than the smallest normal proportional fee across every
route sharing liquidity, bounding a rebate against the opposite normal fee.
The reference implementation can validate only its own process's fee; the
operator must coordinate this rule and reserve targets across processes.
Stale snapshots or inconsistent targets can still subsidize cycles when
another leg is discounted too. The budget bounds negative service fees, not
operating losses from routing or gas drift. It does not guarantee that every
round trip loses money. Its default floor is -1000 ppm
(-0.1 %), and it refuses floors below -10000 ppm.

Network costs are added after the service discount. Bitcoin quotes using
`btc-network-fees/v1` commit the signed service fee and unsigned network
charge separately, with the advertised service formula as a ceiling. EVM
success fees include the service fee and expected gas budget as an aggregate
(RS-010); no EVM network-cost breakdown is client-verified yet. Lightning
routing budgets use the normal service fee and operator caps, never a
discounted fee or rebate. Mining prepayment remains bounded by
`0 <= M <= max(success_fee, 0)`.

## Liquidity curve

The reference policy uses one shared Lightning position and the reserve
involved in the trade. Lightning is healthy when outbound liquidity is
45 to 55 % of channel capacity; inbound is the complement. Each BTC or token
reserve has a private soft minimum, not a target portfolio allocation.

Let `r = 0.006`, `T` be the reserve target, `C` channel capacity and `x`
outbound liquidity. The scarcity potentials, expressed in satoshis, are:

```
reserve_potential(b) = r * max(0, T - b)^2 / (2 * T)
channel_potential(x) = r * max(0, 0.45*C - x, x - 0.55*C)^2 / (2 * 0.45*C)
D = ceil(potential(after) - potential(before))
```

A trade paying Lightning moves outbound by `-P` and its reserve by `+P`;
a trade receiving Lightning makes the opposite moves. Pricing integrates
the whole trade rather than using an endpoint marginal price. Improving one
component while harming another earns only the net improvement.

Balances are intervals. The reference policy uses the worse potential change
at either endpoint of each component. In-flight HTLCs widen the Lightning
interval, unconfirmed wallet inputs widen the BTC reserve interval, and this
store's open firm offers widen both toward their pending effect. Missing or
partial balance evidence grants no discount. This is indicative liquidity
evidence, never authorization to spend or proof of available funding.

The BTC reserve is the configured Core wallet. A forward token reserve is
its committed claim recipient's balance; the reverse reserve is its funding
signer's balance. Setting the forward claim recipient to the reverse funding
address shares tokens without sharing keys or making treasury transfers.
Changing configuration affects only future quotes, never retained terms.

## Stablecoin prices and gas

Opt-in live pricing assumes each configured token is worth exactly 1 USD.
Depeg detection is outside the policy. BTC/USD comes from the operator's
HTTPS mempool instance, cross-checked with Kraken within 2 %; the reference
implementation accepts mempool observations up to one hour old and Kraken
trades up to two minutes old. The worse BTC bound for the trader sets the
integer rate. Live ETH/USD values an explicit gas-price-denominated operator
budget for chains whose native gas currency is ETH. Rollup data fees and gas
drift require operator budgeting; the quote-time ceiling never caps execution
of already funded claims. Missing or stale price evidence refuses quotes,
not merely discounts. Fixed operator rates remain an explicit legacy mode;
live and fixed modes cannot be combined or used as fallbacks.

The same rate, gas charge and service fee MUST be frozen before opening a
reverse hold and reused in its signed terms. Accepted terms never reprice.

## Rebate budget and abuse

The reference process counts rebates committed by open offers plus rebates
of swaps completed in the last 24 hours. It reserves the full negative
service component even when network costs make the aggregate success fee
positive. The budget is process-local, not a shared-node global budget.

Inside the offer transaction, the process recomputes commitments and refuses
any rebate that no longer fits. Unknown commitments MUST grant no rebate.
The store records a granted rebate atomically with the firm offer, before
publication. Open reservations remain committed until durably released;
unfunded idle sessions retire under the normal handshake timeout. Admission
limits bound concurrent exposure, but an unfunded quote can temporarily
consume capacity and rebate budget. A refused reverse offer cleans up its
unused hold through the existing durable hold lifecycle.

## Privacy

The targets, observations and budget MUST NOT be announced. The reference
implementation quantizes discounts toward zero in steps of
`max(1, floor(P * 250 / 1e6))` sat, caches balance reads for 15 seconds and
uses ordinary capacity errors for rebate refusals. Prices still reveal
rebalancing incentives, and adaptive probes can infer more. These measures
reduce disclosure; they do not guarantee balance secrecy.
