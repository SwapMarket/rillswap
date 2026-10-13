# rill-payments

Merchant checkout tools for developers integrating RillSwap payments. The
browser SDK provides `mountRillPay`, a reusable checkout dialog. The Bun
merchant server manages a durable ledger, Lightning invoices and signed
payment acceptance. The dialog alone never pays, creates orders or
establishes payment acceptance.

**Status:** experimental and unaudited. Mainnet funding is disabled. The
[demo shop](examples/demo-shop) uses disposable development payment rails,
not production integrations.

## Install

Use Bun 1.3.11, matching CI. From the repository checkout:

```sh
cd rill-payments
bun install --frozen-lockfile
```

The package is not published to npm; use the checked-out source.

## Quick start

Run the complete Docker development stack from the repository root:

```sh
dev/devctl up
```

Open the shop at http://127.0.0.1:8090/ or the swap page at
http://127.0.0.1:5273/swap.html. See [DEVELOPMENT.md](../DEVELOPMENT.md) for
the payment walkthrough. The stack uses disposable test funds and public
development credentials.

For a browser integration, run `bun run build:rillpay` and serve
`dist/rillpay.js` with your checkout page. This presentation-only example
shows an unavailable method until your merchant backend is connected:

```js
import { mountRillPay } from "./dist/rillpay.js";

const checkout = mountRillPay(document.body, {
  merchant: "Example shop",
  item: "Demo item",
  total: "Quote required",
  methods: [{
    id: "lightning",
    label: "Lightning",
    network: "Bitcoin regtest",
    available: false,
    unavailableReason: "Connect your merchant backend",
    price: null,
    merchantFee: null,
    providerFee: null,
    walletFee: null,
    confirmationTime: null,
    usdCents: null,
    minutesToConfirmation: null,
  }],
  onPay: async () => {}, // Replace with order creation and instructions.
  onCancel: () => checkout.destroy(),
});
```

Your backend owns pricing and method eligibility; enforce both again when
creating an order. Use `null` for unknown prices, fees and timing estimates.
The dialog's built-in stylesheet needs a CSP that allows its inline styles.

For the standalone merchant server, prepare the private configuration and
regtest LND credentials described under [Merchant server](#merchant-server):

```sh
bun src/cli.ts provision /absolute/private/config.json
bun src/cli.ts serve /absolute/private/config.json
```

Provision only a new ledger. `serve` opens the existing ledger on
`127.0.0.1:8787`; put an HTTPS reverse proxy at the merchant origin in front
of it.

## Architecture

- **Checkout UI:** `mountRillPay` renders methods and delegates payment
  preparation to your callback.
- **Browser SDK:** coordinates explicit wallet actions, merchant status reads
  and durable checkout checkpoints.
- **Merchant service:** exposes intents and invoice attempts, observes
  settlement and produces signed acceptance events.
- **Ledger:** persists issuance identities, payment state and acceptance
  events.
- **Demo shop:** connects these pieces to local Lightning, swap, token and
  Monero integrations.

### Package exports

Entry points use the `@rillswap/payments` prefix. Merchant services and
SQLite ledgers run in Bun.

| Entry point | Purpose |
| --- | --- |
| `@rillswap/payments` | Parse Lightning terms and evaluate eligibility |
| `/bolt11` | Decode and bind invoices, including optional metadata hash binding |
| `/rillpay` | Render the checkout dialog and compare known method costs |
| `/sdk` | Lightning checkout coordination and IndexedDB checkpoints |
| `/tracking` | Render Lightning checkout progress |
| `/merchant` | Durable Lightning merchant ledger |
| `/lnd` | Regtest LND invoice issuance and receipt observation |
| `/server` | Merchant HTTP service and acceptance signing and verification |
| `/acceptance-consumer` | Persist order bindings and verified Lightning acceptance |
| `/woocommerce` | Read authoritative order prices and opt-in test-store fulfillment |
| `/discovery` | Read-only external provider probes |
| `/manifest` | Parse and create advisory Lightning merchant manifests |
| `/lnurl-pay` | Explicit Lightning Address discovery and invoice acquisition |
| `/evm-receipt` | Verify prebound direct ERC20 transfer receipts |
| `/native-ledger` | Separate token receipt and inventory ledger |
| `/native-contract` | Sandbox terms and signed receipt contracts |
| `/native-server` | Manually mounted native sandbox HTTP service |
| `/native-sdk` | Explicit native sandbox funding and recovery coordination |
| `/monero-rpc` | Minimal daemon and wallet RPC client |
| `/monero-contract` | Regtest terms and signed Monero receipts |
| `/monero-ledger` | Separate Monero receipt ledger and payment classification |
| `/monero-server` | Local Monero regtest HTTP service |
| `/treasury` | Constrained Sepolia transfer journal |
| `/layerzero` | Inactive OFT quote, observation and unsigned retry artifacts |
| `/routing` | Pure sequential route admission and resume controls |

`bun run build:sdk` builds the Lightning browser module and
`bun run build:native-sdk` the separate native sandbox module.

## Merchant server

The CLI supports only `provision` and `serve`, with a regtest LND backend.
Checkout and API must share the configured HTTPS merchant origin. The
configuration contains exactly these string fields:

```json
{
  "origin": "https://merchant.example",
  "receiver": "<LND compressed node public key>",
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

Use a mode 0700 ledger directory and mode 0600 config, macaroon and secret
files. Create three independent random 32-byte binary keys and a separate
32 to 128 character base64url or hex admin token, and back them up with the
database and LND state. Startup never generates replacements.

LND REST must be on numeric loopback HTTPS with a trusted TLS certificate.
The macaroon needs `info:read`, `invoices:read` and `invoices:write`, not
payment permissions. Invoice-read credentials can reveal preimages, so never
proxy raw LND responses to customers.

### API

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/intents` | Create an authoritative order intent |
| `POST /v1/intents/{id}/attempts` | Request its invoice attempt |
| `GET /v1/intents/{id}` | Read payment status |
| `GET /v1/intents/{id}/events` | Read signed acceptance history |

The authenticated commerce backend creates an intent with
`{orderRef, amountMsat, expiresAt}` and a stable `Idempotency-Key`, then
requests an attempt with `{}` and another idempotency key. Keep admin
credentials server-side, and take prices from trusted commerce logic, never
from the browser. Intent creation returns an opaque read token; send it only
as `Authorization: Bearer ...`, never in a query string.

A failed issuance is reconciled as the same operation, never replaced with a
new invoice. The server worker runs every five seconds and keeps observing
expired issued invoices.

### Existing stores and keys

Provisioning is explicit and one-time. Opening a ledger never creates,
resets, scans or migrates a missing or older store; do not reprovision an
existing installation to resolve a startup error. Changing the issuance key
changes the issuer identity and the existing ledger is refused. Changing the
status or event keys breaks existing capabilities or key pins. Key rotation
is not supported.

## Payment methods and integrations

| Method or integration | Current scope |
| --- | --- |
| Lightning | Regtest CLI and local demo checkout with merchant acceptance |
| Bitcoin through RillSwap | Development swap to a merchant Lightning invoice |
| ERC20 native receipt rail | Local Anvil fUSDC/fUSDT checkout; separate experimental Sepolia ledger and verifier |
| Monero | Local regtest receipts only, with a separate ledger and signed events |
| WooCommerce | Opt-in authoritative BTC order pricing and test-store fulfillment |
| Lightning Address / LNURL-pay | Discovery and invoice acquisition utilities, not wired into merchant issuance |
| LayerZero | Inactive quote, receive and retry utilities, not an enabled payment rail |

Demo prices are fixed-rate test prices, not live exchange quotes. Native
sandbox receipts and Monero regtest events are local evidence only and must
not authorize production fulfillment.

WooCommerce fulfillment requires `testStoreOnly: true` and a separate
read-write REST key. It is caller-driven, not automatic. After an unknown or
unconfirmed write, resolve the outcome before calling fulfillment again.

## Signed acceptance

Wallet success is progress, not merchant acceptance. For Lightning events,
`verifyAcceptance` from `/server` checks the signature against an
independently pinned public key; never trust a key that arrives with the
event. The shop must also match merchant, intent, amount and order, then
atomically deduplicate the event ID and fulfillment, because a valid
signature alone does not prevent replay.

For durable order verification, use the Bun-only
`LightningAcceptanceConsumer`:

1. Provision its private store with the independently pinned merchant origin,
   signing public key, receiver and network.
2. Call `bindOrder(orderRef, authoritativeOrderAmountMsat, terms)` from the
   trusted backend after issuance, before showing the invoice to the buyer.
3. Call `consume(envelope, now)` to verify and persist acceptance.
4. Read verified order state with `getOrder`.

Events without a prior binding are refused. The consumer does not fulfill
orders. Event delivery retries unchanged IDs until acknowledged, and the
history stays available afterward.

## Safety rules

- Terms parsing and eligibility checks do not establish payment acceptance.
  Amounts are canonical decimal-string millisatoshis; the Lightning invoice
  profile requires whole satoshis. Times are Unix seconds.
- Pin merchant origins, keys, receiver identities, networks and asset
  deployments independently of buyer input and discovery results.
- One Lightning attempt per order. Timeouts and ambiguous wallet results
  never trigger automatic redispatch or invoice replacement.
- Resume with the same intent and checkpoint store. Erased browser storage
  cannot prove that no payment happened.
- Late, excess or insufficient Lightning settlement goes to reconciliation,
  with no automatic delivery or refund.
- Token receipt observers are not fulfillment systems. Multistep routes are
  sequential and not atomic; route progress is not merchant acceptance.

## Tests

From `rill-payments/`:

```sh
bun run check:schemas
bun run check:sandbox-fixture
bun run typecheck
bun run test
bunx playwright install chromium
bun run test:browser
```

Opt-in diagnostics use disposable fixtures:

| Flag | Command | Needs |
| --- | --- | --- |
| `RILLSWAP_RUN_MERCHANT_BROWSER=1` | `bun test tests/regtestMerchantHttpsDiagnostic.test.ts -t 'default browser reads actual merchant HTTPS'` | Installed Chromium |
| `RILLSWAP_RUN_NATIVE_SANDBOX=1` | `bun run test:native-sandbox` | Pinned Foundry 1.8.4 Anvil (see `tests/nativeSandbox.test.ts`) |
| `RILLSWAP_RUN_WOOCOMMERCE=1` | `bun run test:woocommerce` | Docker, OpenSSL and network access for pinned images |

The native sandbox and WooCommerce scripts set their flags themselves. Funded
disposable LND diagnostics run from `rill-provider`; see its
[README](../rill-provider/README.md).

## Further reading

- [Development walkthrough](../DEVELOPMENT.md)
- [Architecture](../rill-docs/ARCHITECTURE.md)
- [Protocol specifications](../rill-docs/specs/)
- [Security policy](../SECURITY.md)
