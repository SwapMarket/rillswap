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

## Regtest merchant API and SDK

`bun run merchant provision /absolute/private/config.json` is an explicit
one-time operation. `bun run merchant serve /absolute/private/config.json` opens
only that existing store and serves on `127.0.0.1:8787`. Put an HTTPS reverse
proxy at the configured merchant origin; checkout and API must share that origin.
LND REST is numeric-loopback HTTPS and regtest only, with a trusted TLS certificate
and a macaroon granting `info:read`, `invoices:read`, and `invoices:write`, not
outgoing-payment permissions. LND invoice-read credentials can reveal preimages:
restrict the backend and never proxy raw LND responses to customers.

Configuration contains exactly these string fields:

```json
{
  "origin": "https://merchant.example",
  "receiver": "<actual LND compressed node public key>",
  "endpoint": "https://127.0.0.1:8080",
  "ledgerPath": "/absolute/private/merchant/ledger.sqlite",
  "certificatePath": "/absolute/path/to/lnd/tls.cert",
  "macaroonPath": "/absolute/private/merchant/invoice.macaroon",
  "issuanceKeyPath": "/absolute/private/merchant/issuance.key",
  "statusKeyPath": "/absolute/private/merchant/status.key",
  "eventKeyPath": "/absolute/private/merchant/events.key",
  "adminTokenPath": "/absolute/private/merchant/admin.token"
}
```

Use a mode-0700 ledger directory and mode-0600 config, macaroon and secret files.
Explicitly create three independent random 32-byte binary keys and a separate
32-to-128-character base64url or hex admin token. Back them up securely with the
database and LND state. Startup never generates replacements. Changing the
issuance key changes issuer identity and refuses the existing ledger; changing
status/event keys breaks previously issued capabilities/key pins. Key rotation
is not currently supported.

An authenticated ecommerce backend creates an order using `POST /v1/intents`
with `{orderRef, amountMsat, expiresAt}` and a stable `Idempotency-Key`. The price
must come from trusted commerce logic, not a browser. Then it calls
`POST /v1/intents/{id}/attempts` with `{}` and another idempotency key. Responses
include frozen invoice terms; intent creation also returns an opaque read token.
The browser uses that token only in `Authorization: Bearer ...`, never a query
string. `GET /v1/intents/{id}` reports authoritative status; `GET .../events`
returns signed acceptance events. Evidence submission cannot accept payment.
Failed issuance returns an action-required view while the worker reconciles the
same operation. Expired issued invoices continue to be observed.

```typescript
import { createCheckout, indexedDbCheckoutStore } from "@rillswap/payments/sdk";
import { mountTracking } from "@rillswap/payments/tracking";

const checkout = createCheckout({
  intentUrl, statusToken, policy: independentlyPinnedMerchantPolicy,
  wallet: feeBoundedLightningWallet,
  recoveryStore: indexedDbCheckoutStore("merchant-checkout")
});
mountTracking(document.querySelector("#tracking")!, checkout);
// Only an explicit customer action should call checkout.pay().
```

`bun run build:sdk` builds the browser entry without merchant/node dependencies.
`bun run test:browser` checks actual IndexedDB contention and reopen behavior.
Wallet success is progress only; an ambiguous result permanently prevents
automatic redispatch for this attempt. Resume by loading the same intent and
keeping the store. Erased browser storage cannot guarantee duplicate prevention
or reconstruct signing authority; retain the wallet's own payment history.

Acceptance events use Ed25519 over a domain-prefixed JSON array of all declared
event fields. `verifyAcceptance` takes an independently pinned public key, not
the key attached to an untrusted event. Consumers must also match merchant,
intent, amount and their order, then atomically deduplicate both event ID and
order fulfillment. Signature verification alone does not prevent replay.
`createMerchantService().deliverEvents` retries unchanged event IDs until the
consumer acknowledges. `GET .../events` retains history after acknowledgment.

## External provider readiness

`bun run probe:providers` performs bounded read-only GET requests to the official
Atomiq and Boltz token/limit/pair/contract endpoints. It follows no redirects,
queries no customer URLs, creates no swaps or invoices, and uses no wallet or
recovery storage. HTTP/DNS failures and non-JSON responses are explicit. Even a
valid catalog response is unverified and cannot enable execution.

Atomiq SDK 8.9.6 documents third-party fixed BOLT11 invoice support, but reachable
LPs, exact connector deployments, current executable quotes and durable refunds
remain admission gates. SDK initialization can succeed without LPs, and missing
limits can default to 1, so neither proves support. Boltz's source and API
contract describe external invoices and USDT0/tBTC composition; operational
pairs/deployments and refund asset remain unverified. Stablecoin and LayerZero
checkout execution is not yet implemented or advertised by this service.
