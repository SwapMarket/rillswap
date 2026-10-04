# Checkout toolkit

Experimental checkout contracts, shared pure policy and merchant ledger for the payment processor
blueprint. This does not enable funded production use or mainnet routes.

`parseTerms` validates terms, not a BOLT11 signature or payment receipt.
`evaluateNative` explains eligibility and never establishes payment acceptance.
Amounts are canonical decimal-string millisatoshis; the initial invoice profile
requires whole satoshis. Time inputs are explicit Unix seconds. Merchant origins
must be exact HTTPS origins, pinned independently by the caller.

Run with Bun 1.3.11:

```sh
bun install --frozen-lockfile
bun run check:schemas
bun run typecheck
bun test
```

Canonical schemas and public fixtures live in `rill-docs/`. Generated validators
are checked in and use no runtime schema compilation in browser consumers.

## Merchant ledger

Import `MerchantLedger` from `@rillswap/payments/merchant` in Bun. Provision
explicitly into a private directory (mode 0700). The database is mode 0600;
ordinary opening never creates, resets, scans or migrates a missing/older store.
Mainnet is refused. Existing provider installations and their stores are unchanged.

The issuer must recover the same invoice after an ambiguous create using the
persisted operation identity. A request timeout never permits replacement.
One attempt per order is currently supported. Receipt observation must come from
the pinned receiver, not a browser or LP. Acceptance and the stable outbox event
are atomic; downstream consumers deduplicate event IDs. Late, excess or
insufficient settled amounts stay in reconciliation without automatic delivery or
refund. Observe expired invoices too. Payment and merchant conversion are distinct.

`issue` and `observe` require a trusted clock function so awaited backend calls
cannot bypass expiry or chronology. Injected test adapters prove ledger behavior,
not operational settlement or provider availability. Real backend adapters require
separate conformance evidence before enabling funds.
