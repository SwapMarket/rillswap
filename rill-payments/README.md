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

Pinned LND v0.21.0-beta diagnostics exercise ordinary REST invoice creation,
duplicate-hash rejection, hash-based lookup recovery and actual settlement over
a disposable private regtest channel. They verify the wire fields
`value_msat`, `amt_paid_msat` and `settle_date` without printing raw invoice
responses. These tests use Python REST inside isolated containers; they do not
prove the Bun HTTPS transport, full merchant service or funded swap checkout
end to end. From `rill-provider`, run:

```sh
RILLSWAP_RUN_LND=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/test_lnd_payment_pinned.py::test_pinned_lnd_unfunded_invoice_observation \
  tests/test_lnd_payment_pinned.py::test_pinned_single_part_hold_bound_settled
```

An additional independent opt-in test, `test_bun_merchant_pinned.py`, now runs
the actual Bun TLS/macaroons adapter, merchant SQLite ledger and HTTP Fetch
service over a funded disposable private channel. It injects losses after actual
invoice issuance and settlement lookup, restarts the owned Bun process with the
same private database/keys, and verifies one invoice dispatch, one payer HTLC,
one acceptance event and stable delivery retry/history. The scripted controller
does not prove browser-to-wallet checkout, CLI/reverse-proxy deployment, LND
daemon restart, funded swaps, arbitrary commit interruption or machine-crash
durability. Setup and invocation are documented in `rill-provider/README.md`.
The baseline uses the disposable node's admin macaroon. A second independent
case proves that the documented `info:read,invoices:read,invoices:write` set
suffices for the same Bun checkout/restart flow. It separately verifies read-only
issuance refusal, invalid-signature and foreign-CA refusal, and denial of an
empty `SendPaymentV2` call. This is not formal minimum privilege, comprehensive
spending isolation or production key custody. No raw secrets leave the sidecar.

### Disposable web-to-merchant swap diagnostic

The explicit fresh-regtest happy-path diagnostic exercises the actual
`executeMerchantSwap` SDK adapter with Core standing in for the payer wallet.
It requires a settled merchant invoice, confirmed provider claim, all three
CLI-inspectable encrypted recovery files and independently verified, stable
signed merchant acceptance. Provider completion alone never marks the order paid.

From the repository root, with Docker, the CLI environment/native library and
frozen payments/web dependencies installed, run:

```sh
rill-cli/.venv/bin/python scripts/regtest_e2e.py \
  --web --merchant-checkout \
  --crypto-library rill-provider/tmp/native/librill_crypto.so
```

Install the standard Linux x64 Bun 1.3.11 release at
`tmp/toolchains/bun-v1.3.11/bun`. Preflight requires executable SHA256
`6d5bb405b1d037a2a466b92757de7e47e4369930fa94bd42f8ff44ba49de6c57`;
the merchant also checks full revision `af24e281ebacd6ac77c0f14b4206599cf4ae1c9f`.
The standard binary requires AVX2. Both owned Bun processes use this exact path.
The merchant is a test-owned loopback service, explicitly provisioned in the
private run directory, with invoice-scoped LND credentials and pinned TLS/node
identity. Host children are trusted test code, not credential-isolated processes.

This mode refuses reverse, unpaid-refund and reconciliation-crash scenarios.
It validates newly created container mounts before funding and removes only
recorded owned containers and their reviewed anonymous volumes; `--keep`
preserves those resources, but still stops the merchant child. Cleanup failures
produce a nonzero result and require inspection. The existing default cleanup
behavior is unchanged. Private artifacts under `tmp/e2e-*` retain recovery and
credentials, so do not publish them.

Append `--merchant-restart-after-issue` for a graceful merchant-only restart
after issuing the invoice and before payer dispatch. This reuses the original
bundle/config, signing keys, scoped credentials and database through ordinary
open-only startup. Original authenticated waiting checkout/history and logical
SQLite state must survive before funding is allowed. Final assertions bind the
original attempt/invoice/hash to one provider dispatch and funding reference.
Missing, changed or partial state refuses without provisioning or replacement
funding. This is not a postsettlement receipt-loss or machine-crash test.

Alternatively append `--merchant-crash-after-settled` (not together with the
prepayment restart flag). The initial test-owned observer persists a private
marker and exits after real LND settlement lookup, before returning that
observation to the receipt ledger. Persistence failures terminate without
acceptance. The controller requires the expected owned-child exit, bound marker
and unchanged unaccepted logical state before ordinary same-state reopening.
Reopening cannot rearm or consume the marker as a receipt: the normal backend
must observe settlement again, and the ledger must independently accept it.
Payer dispatch remains one-shot. This isolates backend-observation loss before
acceptance, not transport-level response loss or power-loss durability.

The internal CLI merchant-credit verifier has a frozen public fixture exercising
this service's actual PureEd25519 acceptance signature in Python and TypeScript,
including exact canonical-origin edge cases. It establishes provenance only:
typed acquisition wrappers do not authenticate HTTP/RPC reads, and historical
acceptance does not authorize treasury spending. Real acquisition, invoice
decoding and receipt-to-treasury conversion remain separate runtime gates.

The funded scripted happy path and graceful prepayment merchant restart passed
locally. This is not browser-wallet,
merchant/LND restart, machine-crash durability, production deployment or
stablecoin route conformance. Ordinary installations have no startup or storage
migration changes. Existing checkpoints never authorize replacement funding.

### Isolated HTTPS listener profile (diagnostic only)

The existing `scripts/regtest-merchant.ts provision|serve` configuration and
ephemeral plain-HTTP listener remain unchanged. That diagnostic records
`https://merchant.invalid` as an application origin but does **not** establish
authenticated HTTPS acquisition under that origin.

Select the separate profile explicitly:

```sh
RILLSWAP_REGTEST_MERCHANT=1 bun scripts/regtest-merchant.ts provision-https /absolute/private/config.json
RILLSWAP_REGTEST_MERCHANT=1 bun scripts/regtest-merchant.ts serve-https /absolute/private/config.json
```

The strict configuration has the original ten string fields plus
`profile: "regtest-merchant-https/1"`, `listenerPort` (canonical decimal string,
1024 through 65535), `listenerCertificatePath`, and `listenerKeyPath`. Its origin
must be exactly `https://127.0.0.1:<listenerPort>`. Listener TLS files are separate
from `certificatePath`, which authenticates outbound LND REST. All inputs belong
to the same canonical, private, current-UID-owned directory. Protect that directory
and its ancestors; this is trusted fixture code, not same-UID credential isolation.

Provide certificates and keys explicitly. The factory validates certificate
validity, the `127.0.0.1` IP SAN, key compatibility and authentication inputs before
provisioning or opening the ledger. It does not generate certificates, repair
state, choose a fallback port, migrate an old origin, or support receipt-loss fault
injection in this profile. Ordinary reopening retains the configured origin/port
and original store; missing, partial or invalid TLS/configuration/store refuses.
Listener certificate identity is not stored in ledger metadata: an operator-owned
replacement valid certificate/key pair can serve. A mismatched key is refused;
this is not enforcement of original-certificate continuity. Acquisition clients
must independently retain and verify their original leaf pin.

Offline tests use actual certificate-validated HTTPS and SQLite with a synthetic
LND identity endpoint. They exercise wrong trust/hostname, malformed/mismatched
or expired TLS, occupied-port refusal, retained inputs/history, and legacy HTTP
compatibility. They issue no invoices or payments and do not establish real LND
identity, source-credit provenance or funded conversion. Exact leaf pinning before
sending a capability remains a separate acquisition-client requirement. Existing
installations receive no automatic profile selection, listener or migration.

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

## Experimental EVM receipt verification

`@rillswap/payments/evm-receipt` verifies prebound direct EOA ERC20 transfers.
It is an observer, not an enabled checkout rail. Ethereum mainnet and Sepolia
canonical genesis identities and Ethereum L1 `finalized` semantics are required;
no L2 or custom-fork finality inference is made. A trusted RPC can still present
a dishonest chain view, and chain ID plus genesis does not exclude a later fork.

The authoritative merchant intent and asset deployment are loaded independently
of buyer input. `prepareEvmBinding` verifies an EIP-712 debit-wallet signature,
unused nonce, exact merchant/asset/recipient/amount/window and historical token
pins before funding. The caller must atomically reserve network/wallet/nonce
globally and durably preserve preparation before publishing instructions.
Never fabricate missing preparation for an already-known transaction or give
a buyer control over the persisted preparation record.

`observeEvmReceipt` checks exact transaction calldata and a unique Transfer log,
successful debit from the bound EOA, actual pinned token behavior, historical
code/decimals/proxy identity, preparation anchor and finalized canonical receipt.
Late receipts are returned as `timing: "late"` for reconciliation, not acceptance.
Globally deduplicate the returned transaction/log key in a ledger transaction.
The verifier alone cannot allocate an order or fulfill it.

Smart accounts, fee-on-transfer/rebasing tokens, relayers, exchange withdrawals,
beacon proxies and nonstandard proxy upgrades require dedicated adapters.
ERC-1967 proxy support requires independently vetted upgrade-event behavior;
same-block upgrades are refused. Historical-state and standard-token conformance
flags must be affirmative deployment evidence supplied by trusted configuration,
not assumed from a symbol or copied from customer requests. No production token,
live native checkout pricing or public-network receipt conformance is claimed here.

### Sepolia native payment and inventory ledger

`NativeReceiptLedger` from `@rillswap/payments/native-ledger` explicitly provisions
a separate private Sepolia database, or an explicitly scoped disposable sandbox
database as described below. It leaves Lightning and provider stores
unchanged. Ordinary open rejects missing, partial, foreign and unsupported stores;
it performs SQLite integrity checks, but no network scan, migration or spending.
Each configured exact asset/recipient/cap is immutable for this store version.

Trusted commerce creates intents, then `prepare` verifies the buyer binding and
atomically reserves the nonce and inventory capacity before returning funding
instructions. Use one shared database as the reservation authority, not separate
databases for competing processes. Expired reservations are not automatically
released: expiry cannot prove funds were never sent. `observe` runs the trusted
receipt verifier internally and atomically allocates the transaction/log key,
replaces the reservation with held inventory and creates one native acceptance
event. Native events carry exact asset base units, never a Lightning amount.

Late receipt stays in reconciliation with held inventory and no acceptance.
Explicit `recordReorg` impairs inventory and blocks admission while preserving
paid history and prior events. It is an administrative evidence update, not an
automatic scanner or a claim that Ethereum finalized receipts ordinarily reorg.
Native events currently have only an internal outbox, not a signed public API.
No native SDK send path, deployed affordable asset, or automatic merchant
conversion is enabled. Operational native checkout remains a separate gate.

### Disposable native RPC conformance

The opt-in native sandbox test deploys the source-controlled `SandboxToken.sol`
fixture and exercises real RPC transactions against a private Anvil child.
It verifies exact receipt/log ingestion, five-versus-six local confirmations,
durable prebinding and acceptance across ledger reopen, late receipt handling,
and a controlled chain rewind followed by explicit inventory impairment.
No public endpoint, fork, existing wallet or real asset is used.

The affirmative asset `localSandbox` profile requires chain `31337`, version
`anvil-local/1`, a unique delimiter-safe namespace and exactly six confirmations,
counting inclusion as one. The actual block-zero hash is pinned in the ordinary
asset `genesisHash`. Observation uses local head depth, never the `finalized`
tag, and persists `finality: "local_sandbox_confirmed"`. Canonical Ethereum and
Sepolia policy cannot acquire this profile. Missing, partial or incompatible
profiles do not enable local-chain support.

Sandbox namespace scopes receipt and nonce bookkeeping; it is not authenticated
by the wallet signature and cannot distinguish cloned RPC environments. The
internal SQLite `finalized` allocation marker is not a consensus guarantee.
Receipt payloads retain the explicit local evidence label; sandbox outbox events
have sandbox-scoped keys and must stay inside the disposable harness, not real
fulfillment consumers. Native public API/event integration is still disabled.
Previous version-one Sepolia config, keys and stores open unchanged without
migration or backfill. A sandbox store reopens only with its exact profile.

On Linux amd64, install the official pinned toolchain from the repository root:

```sh
mkdir -p tmp/toolchains/foundry-v1.8.4
curl -fL --retry 3 \
  -o tmp/toolchains/foundry-v1.8.4/foundry_v1.8.4_linux_amd64.tar.gz \
  https://github.com/foundry-rs/foundry/releases/download/v1.8.4/foundry_v1.8.4_linux_amd64.tar.gz
printf '%s  %s\n' \
  699e2207a6a9b27ca17c48c81e56f1677ed9c58b623b59128b4e15ec9da0625e \
  tmp/toolchains/foundry-v1.8.4/foundry_v1.8.4_linux_amd64.tar.gz | sha256sum -c - && \
  tar -xzf tmp/toolchains/foundry-v1.8.4/foundry_v1.8.4_linux_amd64.tar.gz \
    -C tmp/toolchains/foundry-v1.8.4 anvil
cd rill-payments
bun install --frozen-lockfile --ignore-scripts
bun run check:sandbox-fixture
bun run test:native-sandbox
```

Foundry version is `1.8.4`, source commit
`50af4efe189dc64bad2b75ed6990b835de66c4ae`. The harness checks the extracted
binary SHA256 as well as version/commit, launches its own nonforking process
on numeric loopback with an OS-assigned port, and waits for owned-process
termination before deleting its unique local `tmp/` directory. Startup and RPC
calls have deadlines. Test keys are public and disposable. No untrusted RPC URL
or automatically downloaded executable is accepted. Nonfork/loopback settings
do not provide OS-enforced outbound network isolation.

Solidity fixture generation uses pinned npm `solc@0.8.30`, compiler
`0.8.30+commit.73712a01`, targeting Prague. `bun run generate:sandbox-fixture`
reproduces the checked-in ABI/bytecode, and CI checks fixture freshness offline.
The actual process test is manual and skipped unless
`RILLSWAP_RUN_NATIVE_SANDBOX=1`; an opted-in missing toolchain fails, not skips.
This test proves local execution and ledger conformance for this fixture only.
It does not prove Ethereum consensus finality, production token behavior,
pricing, provider settlement, or native checkout SDK/service integration.

### Sandbox-only native HTTP service

`createNativeSandboxService` from `@rillswap/payments/native-server` is a separate,
manually mounted Fetch handler. It requires an explicitly provisioned local
chain-31337 ledger, a trusted RPC reader and supplied persistent private keys.
It rejects canonical-network ledgers. Existing Lightning endpoints, signing
bytes, CLI configuration and ordinary startup remain unchanged. It starts no
provisioning, network connection, scanner, wallet or delivery worker.

| Endpoint | Authority | Exact JSON body |
| - | - | - |
| `POST /v1/native-sandbox/intents` | Merchant admin bearer | `orderRef`, `amountBaseUnits`, `expiresAt` |
| `GET /v1/native-sandbox/intents/{intentId}` | Scoped read/payment capability or admin | None |
| `POST /v1/native-sandbox/intents/{intentId}/prepare` | Scoped payment capability | `binding`, payer EIP-712 `signature` |
| `POST /v1/native-sandbox/intents/{intentId}/observe` | Scoped payment capability | `txHash` lookup hint only |

Creation and preparation require an `Idempotency-Key` header. Creation returns
separate HMAC-scoped `readCapability` and `paymentCapability`; use each as a
Bearer header, never a URL parameter. The read capability cannot reserve funds
or inventory, and admin credentials alone cannot prepare or observe. A payment
capability authorizes durable mutation: a holder can reserve with their own
signing wallet without funding. Restrict issuance to controlled sandbox clients;
no reservation expiry, quota or production admission policy is supplied here.

Preparation verifies merchant-owned terms and payer signature, checks the exact
network/nonce/deployment, and commits the reservation before returning. The
service never signs for the payer. Observation independently queries its trusted
reader; hints and provider success cannot allocate a receipt. Scoped status
returns only explicit terms, recorded receipt and historical signed event, not
payment authority, binding signatures, keys or wallet recovery data.
Preparation replay returns the original durable record, not fresh authorization
to fund after expiry. A future wallet consumer must recheck deadlines and retain
its own private operation checkpoint before signing or dispatching funds.

Status uses `awaiting_funds`, `sandbox_receipt_recorded`,
`sandbox_reconciliation`, or `sandbox_evidence_impaired`, never production
`paid`/fulfillment. Evidence is historical bookkeeping, not a fresh canonical
chain assertion. Late receipts survive without an outbox acceptance or event.
Explicit administrative impairment changes status while preserving the original
signed event and paid history; no automatic reorg monitoring is claimed.

`native-sandbox-event/1` is distinct from Lightning events. Its signed type is
`sandbox.receipt_recorded`, scope is `local_sandbox_only`, and receipt finality
is `local_sandbox_confirmed`. The signature covers complete normalized terms,
deployment/profile, exact receipt and original event ID/time. Verify with
`verifyNativeSandboxReceipt` from `@rillswap/payments/native-contract`, supplying
an independently pinned merchant key and authoritative expected terms. Replay
remains authentic historical evidence; it never authorizes real fulfillment.
Acknowledging the internal outbox does not erase public historical retrieval.

The transport origin is separately pinned. It defaults to the merchant HTTPS
identity; manual mounting may explicitly override it with an exact numeric
loopback HTTP origin. `Host`/forwarded headers do not establish trust. Requests
with mismatched URL/Origin, query tokens, unexpected fields or oversized bodies
are refused. Mounting must supply socket isolation, deadlines, concurrency
limits and private key custody; origin checks do not enforce those properties.
Preserve capability and signing keys across restarts, never generate replacements
on ordinary startup. Key rotation/public fulfillment is not implemented.

The opt-in sandbox suite mounts a real Bun loopback HTTP server and records
actual Anvil transfers through this API, reopening ledger/listener before funding
and after signed evidence. It also exercises the sandbox SDK below with a
private file-backed scripted wallet. No production deployment or supported
browser-wallet adapter is enabled.

### Native sandbox funding SDK

`createNativeSandboxCheckout` from `@rillswap/payments/native-sdk` requires
authoritative sandbox terms, an independently pinned merchant event key, scoped
payment capability, fixed token/gas/fee ceilings, and a trusted
`NativeSandboxWallet`. Keep the normal Lightning SDK and its invoice semantics
separate. The optional native bundle is built with `bun run build:native-sdk`.

Explicit `pay()` atomically reserves an operation checkpoint before any wallet
identity or signature request. Only the successful reservation owner proceeds.
Payer binding goes through merchant preparation with the same operation ID;
successful preparation is required before token signing/dispatch. A dispatched
checkpoint is durable before invoking the wallet. Deadline, merchant evidence,
network and wallet identity guards run after awaits, before signing and before
every broadcast. Unused nonce is required for new signing, not private wallet
lookup or merchant observation of an already-published transaction.

The wallet must durably bind each operation to the entire immutable request,
preserve private signed raw/hash before publication, honor fee caps and invoke
the supplied guard immediately before signing and every broadcast. Reentry may
only use the identical private raw transaction, never a fresh nonce or repricing.
Signing the EIP-712 receipt binding must not fund anything. `lookup` is read-only.
Interface flags state these requirements; they do not prove an arbitrary wallet
implements them. Only the scripted disposable adapter has been exercised here.

`open()` never dispatches. Missing storage yields an explicit-payment requirement,
not evidence that no prior payment exists. Loaded unknown/older/conflicting
records fail without replacement. Existing reservations reconcile only their
operation/hash; missing private lookup data requires intervention. Expiry or an
advanced nonce does not block receipt observation. Recovery does not write stale
checkpoint snapshots, but `/observe` can record verified merchant evidence.
A successful wallet result only starts merchant observation.
Contradictory status/evidence, substituted receipt events or preparation identities
are refused. Receipt reporting stays explicitly `sandbox_receipt_recorded`, never
production paid or fulfillment.

`indexedDbCheckoutStore<NativeSandboxCheckpoint>(name)` reuses the existing
version-one `attempts` store and `attemptId` key. The generic change is type-only,
with no database migration. Use the same database and key domain for competing
consumers. Existing Lightning checkpoints retain their behavior; native consumers
reject incompatible records without releasing the reservation. `update` remains
an unconditional put, so only the reservation owner writes funding progress.
Do not put keys, signed raw transactions or capabilities in these public-reference
checkpoints. Erased browser storage cannot recover private wallet history.

Tests cover genuine IndexedDB native/native and native/Lightning contention,
reopen without dispatch, malformed records, deadline/failure injection, erased
metadata refused by existing merchant preparation, and same-operation lookup
after ambiguous publication. The actual Anvil/HTTP scenario persists private raw
before broadcast, loses the response, then recovers and independently observes
the same hash without another broadcast. The browser fixture uses a wallet stub
and does not establish browser-wallet private durability. Real wallet deployment,
pricing, ecommerce hosting and production fulfillment remain separate gates.

## Constrained treasury payout foundation

`TreasuryTransferJournal` from `@rillswap/payments/treasury` is an explicitly
provisioned private Sepolia journal, not an automatic conversion adapter or a
wallet balance. Immutable policy pins the source wallet/token, recipient
allowlist and lifetime token/gas authorization ceilings. Unknown/partial state
never starts spending. Startup checks persisted transaction and reservation
invariants and does not repair inconsistent records.

Prepare a fixed nonce and exact EIP-1559 token transfer before invoking an
isolated `MerchantTransferSigner`. That wallet/process must durably deduplicate
operation IDs and never broadcast while signing. The journal independently
checks the signed transaction's source, chain, calldata and fee bounds, persists
it privately and records dispatch before invoking the broadcaster. Ambiguous
broadcast resumes with the exact raw transaction, never a fresh nonce. Public
operation views exclude signed raw transactions and keys.

An independently conformant `MerchantTransferObserver` must establish the exact
canonical finalized debit/credit and gas cost. A reverted or contradictory
operation requires intervention. Failed and ambiguous jobs retain their entire
authorization ceilings, even after settlement; these are conservative lifetime
spend budgets, not inventory balances. No signer/observer deployment, native
inventory synchronization, batching, conversion output or automatic job runner
is enabled. Payout failure cannot reopen a paid native or Lightning order.

## LayerZero quote/receive/retry artifacts

`@rillswap/payments/layerzero` implements an inactive, source-pinned PacketV1
observer and unsigned direct-delivery retry builder, not an enabled bridge rail.
Protocol source pin is `9c741e7f9790639537b1710a203bcdfd73b0b9ac`; OFT source
pin is `4973ba8bef7b0fdf7268469abea3ea50dbd4bbd8`. Package metadata alone does
not establish that a deployed USDT0 contract matches either source.

`quoteOftSend(path, request, sourceReader, destinationReader, clock)` reads
`quoteOFT` and `quoteSend` for an explicit source wallet/recipient, amount,
minimum, original extra options, native transport fee cap and receive gas cap.
It checks both pinned deployments and libraries at block-bound snapshots, then
revalidates both anchors. This supports only equal-sent/received default-debit
quotes with no fee details, native fee payment, no compose/command, and one
merged type3 positive-gas, zero-native-value receive option. Other semantics
are unsupported, including zero-valued fee detail entries and custom options.

Amounts round down to shared-unit precision. Reported nominal limits apply to
the actual rounded debit, not unspent dust; they do not establish available
liquidity or sendability. Shared amount fits uint64, while each chain's local
amount uses its own decimals. Original extras are quoted, not the combined
options (which would double-apply enforcement). The frozen JSON-safe quote
includes dust, exact units, transport fee, public pins and block coordinates.
`amountSentLD` and `amountReceivedLD` use source local units;
`destinationAmountLD` independently converts the received shared units.
Source gas/approvals and other downstream costs are not included. Sufficient
delivery gas and actual deployed behavior still require independent conformance.

The 60-second construction/use expiry is advisory, not a firm quote or freshness
guarantee enforced by the chain. Requoting is required before any separately
authorized execution. This API neither signs nor sends, grants spending or
recovery rights, proves payer balances, nor establishes delivery/merchant receipt.
Matching read responses do not discover conformance or enable production routes.

Trusted configuration must independently validate both directional EIDs,
endpoint/OFT/token/library code, peers, units and standard zero-value credit.
Only nonupgradeable Ethereum L1/Sepolia profiles are handled; proxies, L2s,
custom implementations and compose require dedicated profiles. No deployed
USDT/USDT0 pathway or operational fee/recovery conformance is configured here.

`readSourceOftPacket` verifies finalized endpoint PacketSent routing evidence,
not payer debit ownership or order acceptance. `observeOftReceive` distinguishes
exact destination commitment, nilification, unresolved state and finalized
destination token credit. Zero payload hash and advanced nonces do not prove
delivery. Endpoint PacketDelivered alone can come from `clear`; exact OFTReceived
and actual token Transfer must also match the GUID/origin/recipient/quantity.
Token credit still does not establish a subsequent Lightning payment.

`buildOftRetry` derives zero-value `EndpointV2.lzReceive` calldata from an exact
committed noncompose packet, validates a bounded predecessor nonce window,
simulates and estimates gas, then rechecks those conditions. It produces no
signature or transaction submission, has no principal-refund mechanism and
requires no Scan service. The 60-second artifact expiry is advisory: EndpointV2
does not enforce it. A signing consumer must persist operation identity,
enforce expiry and full fresh pathway/commitment/nonce/simulation checks before
authorizing gas. Permissionless receive retry does not bypass verification.

## Sequential admission and resume controls

`@rillswap/payments/routing` evaluates explicit merchant-approved frozen routes,
not untrusted discovery catalogs. Capabilities must have exact adapter/deployment
identities, independently established operational conformance, per-step atomicity,
owned source/destination and recovery assets, compatible signers and approved
gas budgets. Firm quote IDs, deadlines and complete buyer costs must bind the
same merchant intent/attempt/payment hash and shared fee policy. No current
external capability registry is populated by this package.

Every multistep route is `sequential_nonatomic`; independent atomic swaps do not
make their composition atomic. Intermediate ownership/asset allowlists are
explicit. Current observer admission ends at the pinned Lightning destination;
bridged-native allocation needs a dedicated binding profile and is refused here.

`nextRouteAction` consumes privileged journal checkpoints. Missing, older,
partial, conflicting or out-of-order records require intervention. Dispatched
operations reconcile the same identity even after expiry; an expired next-step
quote cannot start a new funded operation or replace an unresolved invoice.
Owner recovery can leave funds on an intermediate network. Even fully observed
steps yield only `awaiting_merchant_receipt`, never payment acceptance.

These are pure controls, not a durable route journal or executor. A consumer
must durably publish frozen operation identities before requesting wallet
approval, validate actual destination evidence before advancing a step, obtain
explicit quote-refresh approval while retaining custody/recovery history, and
rerun admission immediately before spending. No hub wallet or sequential route
is currently activated by the native checkout SDK/service.
