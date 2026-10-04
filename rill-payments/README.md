# Checkout toolkit

Experimental checkout contracts and shared pure policy for the payment processor
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
