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

## Recognizable RillPay checkout

`@rillswap/payments/rillpay` exports `mountRillPay(container, options)`, or build
the browser module with `bun run build:rillpay`. The demo shop uses this same
renderer. Supply merchant/item/total text, a list of `RillPayMethod` rows, and
an `onPay(methodId)` callback that creates and displays merchant payment
instructions. It does not itself contact a wallet, create an order, send funds,
persist state, or establish acceptance.

Each row declares eligibility and an unavailable reason, price, merchant fee,
provider fee, wallet/network fee, and confirmation time. Use `null` for unknown
values; they remain visibly unknown, never silently zero. The merchant owns
eligibility and must enforce it again on order creation. All methods remain
visible, including amount-restricted or unavailable methods. Text is rendered
inertly, pending selection is pinned, errors are redacted, and all-ineligible
checkouts disable the payment action. `destroy()` removes the mounted view.
The scoped built-in stylesheet requires the host's inline-style CSP allowance
(or an approved stylesheet policy); it does not modify global document styles.

Demo prices are fixed-rate fake-money prices, not live exchange quotes. Bitcoin
swap costs/confirmation targets come from the provider quote; wallet fees stay
unknown until the wallet supplies them. Native token confirmations are local
Anvil targets, not production timing guarantees. The Bitcoin handoff uses an
invoice URL fragment, not a server-visible query; RillSwap removes it after
inertly prefilling, without automatically requesting a quote or moving funds.
Existing order persistence and signed-acceptance verification are unchanged.

## Explicit invoice metadata binding

`@rillswap/payments/bolt11` exports `invoiceMetadataBinding(invoice, network,
metadata)` for an optional strict hash-bound invoice profile. It uses the
shared invoice admission policy, requires exactly one canonical `h` tag and
no `d` tag, and hashes the exact original metadata UTF-8 bytes. Whitespace,
Unicode normalization and JSON reserialization change that hash. Metadata must
be well-formed Unicode and at most 16 KiB encoded. Every reader rejects
wrong-length `p/h/s/n` tags according to current BOLT11 requirements, despite
the contradictory historical upstream example. Duplicate description hashes
and noncanonical description-hash padding are rejected by the metadata helper;
ordinary admission retains its existing policy for those cases. Duplicate
payment-binding fields remain a stricter application policy. The seven-field
invoice binding shape and original-text/signature hashing are unchanged.

Current [LUD-06](https://github.com/lnurl/luds/blob/913c49e5b65081473eed7889eee5f806dd30f049/06.md)
no longer mandates metadata hash binding. This helper is not universal LNURL-pay
compliance or the default for current Lightning Address services. It performs
no HTTP request or invoice issuance. Signature authentication and a metadata
match do not independently establish the expected merchant/order/amount,
current expiry, custody or settlement. Those checks remain the caller's duty.

## Lightning Address discovery (no invoice request)

`@rillswap/payments/lnurl-pay` exports
`discoverLightningAddress(address, approvedOrigins, transport?)`. The caller
independently approves canonical HTTPS receiver/callback origins. This strict
profile accepts lowercase ASCII addresses, public DNS-form hostnames and default
HTTPS ports. It rejects literal IPs, local/onion host profiles, unknown delegated
callbacks, unsafe numeric bounds, duplicate-key JSON and missing identity metadata.
These restrictions are toolkit policy, not universal LUD compliance.

One GET retrieves the pay-request descriptor, with redirects refused,
credentials/referrer omitted, a 10-second abort through streaming consumption,
and a 64 KiB response limit. Non-success HTTP, non-JSON media types, malformed
UTF-8 and metadata over 16 KiB are refused. Original metadata is preserved;
claimed identifiers and description remain untrusted informational content.
Use text rendering, never interpret the description as HTML.

Default transport is available only in a browser document. Other hosts require
an explicitly trusted transport enforcing DNS resolution, private-address
rejection, connection pinning and egress policy. Origin approval alone is not
general server SSRF protection, and browser CORS is not request-side protection.
Injected transports must honor the abort contract through response-body reads.
An empty `Response.url` is allowed only for explicitly trusted transports,
including synthetic responses; default browser responses must retain the exact
canonical discovery URL. Nonempty response URLs are always checked.
Merchant browser CSP must separately permit its approved discovery origin.

The frozen descriptor is transient, not a stored quote or execution capability.
Its callback may contain sensitive capabilities: do not log it, persist it in
ordinary checkout records, or expose it in status/explorer links. This function
never calls that callback, requests an invoice, retries, or activates funding.
Separate invoice retrieval can cause remote issuance and needs original order
authorization, independent payee/amount/network/expiry validation and an explicit
hash-profile choice. It does not establish recoverable merchant issuance or
receipt verification; funded invoices must not be silently replaced.

`validateLnurlPayInvoice(descriptor, response, expected)` is a separate pure
validator. Independently trusted expectations pin the compressed payee key,
whole-satoshi amount, network, current time, minimum expiry and explicit
`not_required` or `strict_hash` metadata policy. The ordinary policy accepts
modern unhashed invoices; strict mode uses the optional exact-byte helper above.
Requested amounts must fit the descriptor's advertised range. The invoice must
not be future-created or expired, and its expiry may equal the required minimum.
Missing/nonempty response `routes` and service errors are refused. Verification
and success-action extensions are neither inspected nor returned.

The frozen result retains only the original invoice, its seven-field binding
and the chosen hash policy. Matching contents do not authenticate the order or
establish recoverable issuance, payment permission or settlement. Never derive
the trusted payee pin from descriptor metadata or the returned invoice itself.
BOLT11 uses `tb` for both testnet3 and testnet4, so that encoding cannot distinguish
those networks; independently configured rail identity remains necessary.

`requestLnurlPayInvoice(descriptor, expected, approvedOrigins, clock, transport?)`
is a separate, explicitly invoked acquisition utility. Its expectation omits
`now`: the trusted clock supplies fresh Unix seconds before invocation and after
the response. It validates independent pins and approved receiver/callback
origins before one callback GET, adding the canonical requested amount. The same
bounded HTTP policy applies. A separate 10-second elapsed transport budget
includes response validation; invoice minimum expiry is not an order deadline.
The return value is only the frozen validated invoice result described above.
Existing query escapes and duplicate non-amount values retain their bytes when
the amount is appended. That does not establish compatibility with a callback
signature covering the complete URL; actual provider conformance is required.
The response clock sample precedes signature validation, not the return instant.
Consumers must independently recheck freshness before any separately authorized
payment; this utility does not grant payment permission.

`LnurlInvoiceAcquisitionError.state` distinguishes `not_requested` (transport
was never invoked) from `issuance_unknown` (every failure after invocation,
including remote errors, timeout, malformed response or mismatched invoice).
Neither state grants retry permission. A callback may have issued an invoice
even when no valid response arrives. Error messages contain no callback
capabilities, remote reasons or causes. Trusted transports must not retry,
redirect or delegate requests internally.

The guarantee is one transport invocation **per explicit call**, not once per
order. There is no automatic discovery, invoice refresh, payment, reconciliation
or recovery. Do not call again to clear an unknown outcome or replace a funded
invoice. This utility is deliberately not wired into `InvoiceIssuer`, checkout
dispatch or merchant polling: their recoverable same-invoice contract requires
durable original-operation recording, provider-backed invoice correlation and
an independent settlement observer. A local marker alone cannot recover an
unknown remote invoice. Existing installations gain no startup, migration or
automatic network behavior; production integration remains disabled.

## Durable bound Lightning acceptance consumer

`@rillswap/payments/acceptance-consumer` exports the Bun-only
`LightningAcceptanceConsumer`. Explicit `provision(path, identity)` creates a
fresh private store; `open` never initializes, migrates or repairs a missing,
partial, unsupported, foreign or altered store. Independently pin the merchant
origin, signing public key, Lightning receiver and network. Mainnet stays disabled.
Existing merchant version-1 stores and their startup behavior are unchanged.

Call `bindOrder(orderRef, authoritativeOrderAmountMsat, terms)` from the trusted
ecommerce backend after invoice issuance, but before buyer exposure/payment.
The independent order price must equal the merchant terms; their origin,
receiver and network must match the configured identity. Registration is
immutable and allocates each intent, attempt and payment hash to one order.
An event without an existing binding is refused, never historical auto-binding.
Exact registration replay is harmless; unknown orders cannot be reconstructed
from browser status, discovery metadata or signed event history.

`consume(envelope, now)` verifies the existing signed Lightning acceptance
contract and matches the bound identifiers, hash, amount and origin. Event
storage and deduplication are transactional; repeated stable IDs return the same
result, while changed content, cross-order IDs or replacement events are refused.
`getOrder` derives `waiting`/`accepted` from stored evidence. Accepted reads and
replays reverify the stored signed envelope and its binding/index consistency,
not merely an unauthenticated paid marker. SQLite integrity checks alone are
not acceptance provenance. `acceptedAt` is the producer's observation time:
timely settlement may be observed after terms expire, so that timestamp does
not supply an independent settlement-deadline check.

This consumer does not execute fulfillment, reserve inventory, pay invoices,
grant recovery rights or provide rollback-resistant custody. Persisted exact
replay causes no external effects. A bound order without acceptance remains
waiting; native sandbox, bridge/provider evidence and public status are not
Lightning acceptance. Actual ecommerce order authentication, external effect
idempotency and production deployment remain separate release gates.

### Opt-in merchant invoice exposure gate

Pass an already opened `acceptanceConsumer` to `createMerchantService` to require
existing full order bindings before exposing invoices. The configured merchant
origin, receiver, network and event signing key must match the consumer. This
mode pins a copy of the event key; it does not perform key rotation. Default
service behavior is unchanged when the option is absent.

Every invoice-bearing snapshot, including status reads and admin creation
replays, returns `attempt: null` if the original binding is missing. Conflicting
or corrupt stored provenance produces HTTP 503 without invoice data. No GET,
polling tick, constructor or historical event creates a binding. The consumer's
`existingBinding(orderRef, amountMsat, terms)` performs the nonmutating full-term
check, returning null only for an absent binding.

Explicit admin `PUT /v1/intents/:id/order-binding` accepts exactly
`{ "orderRef": "...", "amountMsat": "..." }` after the invoice is issued.
The trusted backend must establish that price independently from its order
system; an admin token alone does not prove price provenance. Both fields must
match the original merchant intent. A successful registration authorizes invoice
exposure, so it is not merely bookkeeping. Buyer status tokens cannot register.
Resource-level exact replay is safe without an Idempotency-Key header; conflicting
registration is refused. Responses may advance as acceptance status changes.

Upgrading without opting in leaves merchant version-1 behavior unchanged. Opting
in with missing bindings withholds existing invoices, including previously
exposed or funded ones, without replacing them or proving any historical fact.
Only explicit backend registration allocates matching original terms. Paid
legacy orders may be registered for reconciliation, but that does not prove
binding before their historical payment. New flows should register before buyer
exposure. Consumer files are never initialized or migrated by the service.
Signed event delivery remains caller-controlled; this mode neither consumes
events automatically nor executes fulfillment or renews SDK dispatch rights.

The opt-in provider test `test_merchant_https_admission_pinned.py` bundles the
owned `tests/regtestMerchantHttpsAdmission.ts` runner for actual isolated
regtest Core/LND/HTTPS conformance. Parent-owned order/price and authenticated
HTTPS retrieval pin the invoice before one original SDK native-wallet dispatch.
The fixture checks receiver settlement separately, then acceptance commit,
acknowledgment loss, application reopen and stable-ID redelivery. It neither
uses the provider cooperative paid collector nor proves its historical failures
resolved. This is not production fulfillment or process-crash/power-loss proof.
Execution requires both existing LND/Bun opt-ins and pinned disposable fixtures.

## Keyless acceptance signing

`createMerchantService` also accepts `KeylessMerchantServiceOptions`: omit
`eventSigningKey` and supply `acceptanceSigner: { publicKey, sign }` instead.
The dedicated signer receives only canonical `rillswap-payment-event/1` bytes
and asynchronously returns a 64-byte signature. Both or neither signing source
is refused; a configured signer failure never falls back to local private bytes.
Its public key and bound method are captured once. Custom keys must be canonical,
nonidentity prime-subgroup Ed25519 keys, not small-order verification keys.

The signer must produce **standard RFC 8032 deterministic Ed25519** signatures
for identical bytes across retries, concurrency, restarts and provider replacement.
Signature validity alone cannot prove deterministic conformance. Before adopting
an external provider, compare its output byte-for-byte against the existing
implementation. The consumer deduplicates complete serialized envelopes, so a
different valid signature on replay is still a conflict. Nondeterministic
providers are unsupported; no new signature cache or stored format is introduced.

Authenticated event reads and explicit outbox delivery await signing, then verify
the returned signature against the captured original event/key before exposing
or acknowledging it. Returned bytes cannot change event terms. Failed signing
returns no envelope and leaves the paid state/event pending; sanitized errors
contain no signer reason or cause. Publication uses the pinned public key without
invoking the signer. Manifest, consumer and event pins must still match.

Existing `MerchantServiceOptions`, synchronous `signAcceptance`/`verifyAcceptance`,
signature bytes and raw-key behavior remain compatible. Unconfigured raw mode
retains its original mutable key reference; consumer/publication opt-in still
copies Buffer-backed keys. No migration, backfill, automatic signing job, invoice
refresh or new spending authority is added. Launcher key files remain unchanged;
this capability is programmatic, not an automatic custody reconfiguration.

An owned test-only child key holder exercises actual IPC, concurrent HTTP reads,
lost acknowledgment and application/signer reopen with stable envelopes. It does
not establish different-UID isolation, hardware custody, human approval or
production signer conformance. Dedicated acceptance keys must never be reused
as wallet/spending keys. Production custody remains a separate release gate.

### Weak acceptance-key rejection and upgrades

Public `verifyAcceptance` and consumer identity validation now reject small-order
public keys. Those points have no nonzero prime-order component: the underlying
consensus-oriented ZIP-215 verifier can otherwise accept a matching unsigned
event with a zero signature. An independently configured pin is not sufficient
if that pin is itself a weak key. Ordinary generated keys, including keys from
an all-zero private seed, are not this weak-public-key case.

The legacy verifier retains ZIP-215 mixed-order and noncanonical point behavior,
including its original textual key handling. Consumer pins still require lowercase
64-character hex. The new `hasNontrivialAcceptanceKey` guard explicitly decodes
with ZIP-215 semantics; it does not impose the custom signer's stricter canonical
prime-subgroup contract on existing consumers. Generated-key signatures, envelope
bytes and valid-store replay are unchanged.

Small-order or undecodable consumer identities refuse before file creation or
opening, even when an older store contains a matching identity and historical
acceptances. No repair, deletion, key rotation, migration or history rewrite is
performed. Existing valid-key stores reopen unchanged; missing/partial/unsupported
stores retain their existing refusal. Operators with weak-key state must preserve
that evidence and independently investigate original payment provenance before
any separately authorized replacement provisioning. Changing configuration cannot
bless its old acceptances. This intentional availability loss applies to weak-key
installations, not to normal generated-key or supported mixed-order installations.

## Advisory native Lightning merchant manifest

`createMerchantService({ ...options, publishManifest: true })` explicitly
publishes public `GET /v1/manifest`. The default and explicit false retain 404.
This fixed `merchant-manifest/native-lightning/1` profile advertises only regtest
native Lightning, its intent API, protected signed-event path and original event
public key. Publication snapshots that key, including Buffer-backed inputs.
No backend probe, invoice issuance, ledger write or order authorization occurs.
Non-regtest publication and nonboolean options are refused. Existing service and
store behavior remains unchanged without the option; launcher configuration does
not enable it automatically. The trusted HTTPS diagnostic exposes the explicit
`manifestProfile` selection described below; the separate CLI is unchanged.

`@rillswap/payments/manifest` exports the browser-compatible constructor and
`parseNativeLightningMerchantManifest(value, expectedOrigin, expectedPublicKey)`.
Both pins must come from independent trusted configuration. The parser accepts
bounded plain JSON data, rejects nested extensions/accessors, checks the exact
intent URL and returns a deeply frozen snapshot. The published canonical schema
is `rill-docs/schemas/checkout/native-lightning-manifest.schema.json`; generated
validator parity is checked by the existing schema command.
Bound the transport response before decoding (this profile fits within 8192
bytes). This parser is not a sandbox for arbitrary JavaScript objects or Proxies;
introspection traps and initial property enumeration are not isolated or bounded
by its profile limits. The public conformance fixture and independent Python
schema checks live alongside the schema in `rill-docs`.

This manifest is unsigned. Matching public pins does **not** authenticate its
contents or receiver: the caller must authenticate HTTPS delivery from the
expected origin. Never replace independently trusted invoice/order/receiver pins
with advertised values. Event retrieval still requires its status/admin
capability. Advertisements establish neither live payability nor settlement,
deployment conformance, execution rights or production readiness.

Asset decimals are relative to BTC (`11` for msat); quantum `1000` is measured
in msat and describes this whole-satoshi checkout profile, not Lightning's
general precision. Token contract/mint and token behavior are not applicable.
The named regtest network does not identify a unique private chain or topology.
`productionEnabled` is always false; no bridge, swap or sandbox-native route is
advertised. Publication is an in-memory opt-in, not a migration or funding gate.

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

To opt into the accepted order-binding gate, first provision the merchant with
the unchanged configuration above. Then explicitly add `acceptanceConsumerPath`
as a canonical absolute path in the same private directory and provision only
that fresh consumer:

```sh
RILLSWAP_REGTEST_MERCHANT=1 bun scripts/regtest-merchant.ts provision-acceptance-https /absolute/private/config.json
RILLSWAP_REGTEST_MERCHANT=1 bun scripts/regtest-merchant.ts serve-https /absolute/private/config.json
```

The new command requires a matching existing merchant ledger and live LND
identity. It exclusively creates one consumer, never overwrites or removes a
failed/partial store. `provision-https` refuses consumer-configured input rather
than attempting cross-file provisioning. Consumer paths and SQLite sidecar
namespaces must not overlap the merchant store, configuration or credentials.
The optional field is not accepted by legacy HTTP commands or the separate CLI.

With the option present, serving opens both matching stores before any listener
or timer. Missing, partial, unsupported, foreign or invalid consumer state
refuses startup, never downgrades to unbound service. A valid empty consumer
withholds invoices until explicit admin order registration. Existing invoices
and history are retained; no historical binding, acceptance consumption or
fulfillment happens at startup. Setup failure and shutdown close both handles.
Old HTTPS configurations retain their original behavior. This remains a trusted
regtest diagnostic, not a production service or rollback-resistant store.

Optional HTTPS configuration `manifestProfile: "merchant-manifest/native-lightning/1"`
selects the fixed advisory manifest published by public `GET /v1/manifest`.
Omit the field to retain 404. It is an exact string profile, not a boolean or an
arbitrary registry: unsupported values and legacy HTTP usage are refused before
backend calls or state creation. Both provisioning commands retain their existing
single-store responsibilities and do not start a publisher. Normal startup still
checks live LND identity. Manifest construction and retrieval add no probe or
order-state change; publication snapshots the configured identity/key.

An independent opt-in browser test now reads this actual Bun HTTPS service using
the SDK's default fetch (not an injected adapter or intercepted status response).
The owned synthetic LND endpoint supplies identity only; a signed fixture invoice
is withheld until parent-only admin registration binds the original order price.
The browser receives only a scoped status capability, retains independent
origin/receiver/network pins, and never invokes a wallet or dispatch checkpoint.
After binding it observes the same original invoice. No settlement or fulfillment
is inferred. With pinned Chromium installed, run from `rill-payments`:

```sh
RILLSWAP_RUN_MERCHANT_BROWSER=1 bun test tests/regtestMerchantHttpsDiagnostic.test.ts \
  -t 'default browser reads actual merchant HTTPS'
```

Two fresh private browser profiles use a selective exception for one independently
known fixture leaf's SPKI. Actual main-browser arguments are checked for absence
of broad TLS-ignore flags. The correct exception permits the real status GET;
the wrong fixture leaf produces `ERR_CERT_AUTHORITY_INVALID` on that exact GET
with no wallet/store effects. Only the owned app document and external modules
are routed, on the same merchant origin under self-only CSP; status requests are
never routed and service workers are blocked. Profiles and browser processes close
before fixture cleanup. This exception is not restrictive certificate pinning
(ordinary trusted CAs still apply), ordinary CA trust or hostname-enforcement
proof. No system trust changes, production TLS bootstrap, remote invoice issuance,
payment, funded capture, runtime or upgrade changes are introduced. The normal
unit suite skips this case; CI explicitly runs it after installing Chromium.

Publication alone does not enable order-binding enforcement. Configuring a
consumer still requires its matching existing store; missing state refuses the
whole listener rather than publishing with a downgraded gate. Previous configs
without the field are unchanged, and older launchers safely reject the new field.
Clients must independently provision TLS trust and identity pins. Public endpoint
access and a declared key matching launcher output are not merchant authority,
invoice permission, settlement proof or production readiness.

Offline tests use actual certificate-validated HTTPS and SQLite with a synthetic
LND identity endpoint. They exercise wrong trust/hostname, malformed/mismatched
or expired TLS, occupied-port refusal, retained inputs/history, and legacy HTTP
compatibility and explicit consumer startup/reopen. Additional gate cases use
signed synthetic invoice fixtures, never remote invoice issuance or payment.
They do not establish real LND
identity, source-credit provenance or funded conversion. Exact leaf pinning before
sending a capability remains a separate acquisition-client requirement. Existing
installations receive no automatic profile selection, listener or migration.

## Regtest merchant API and SDK

Lightning SDK merchant status reads now use a setup-inclusive ten-second
header/body/decode budget. `merchantReadTimeoutMs` selects an integer from 1
through 30000 milliseconds, captured at construction. This is not a wallet RPC
deadline, invoice lifetime or settlement guarantee. Each explicit read makes
one GET with bearer status capability, no credentials/referrer, no redirect or
cache. No automatic retry or fallback is added.

Reads require status 200, an `application/json` media type (case-insensitive,
parameters allowed), valid UTF-8 and at most 8192 actual streamed bytes. Reported
delivery URLs must equal the original intent URL and redirected responses are
refused. Default fetch must report its delivery URL; an explicitly supplied
trusted transport may return URL-less in-process responses. Injected transports
must authenticate the pinned HTTPS origin and honor request policy; server
adapters also own DNS/egress safeguards. Neither response URL fields nor matching
body pins authenticate a privileged adapter that lies about delivery.

These are deliberate availability restrictions: slow merchants, successful
non-200 statuses, missing/unconventional JSON headers and oversized valid
extensions that older readers accepted now refuse. Supported canonical views
fit the cap; only request-budget configuration is adjustable. Timeout aborts and
cancels best-effort without awaiting hung cleanup. Late transport completion
cannot change checkout state/progress, create checkpoints or dispatch a wallet.
The transport is trusted in-process code, not a JavaScript execution sandbox.
Synchronous blocking code can delay timers and return; overdue results are then
refused by monotonic admission checks. Abort/cancel cannot guarantee termination
of a privileged adapter. The deadline bounds asynchronous waiting, not arbitrary
JavaScript execution.

Upgrading does not change stored checkpoints or grant recovery/retry rights.
Failed reads create no checkpoint; older dispatched records retain duplicate
payment protection. Partial/conflicting records retain existing verification.
A user can explicitly request another status read, but timeout is never payment
retry permission. Wallet dispatch barriers and financial deadlines are unchanged.

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

## WooCommerce-priced buyer checkout (opt-in)

`createWooCommerceOrderSource` (`@rillswap/payments/woocommerce`) reads an order
through the WooCommerce REST API v3 (`GET /wp-json/wc/v3/orders/:id`, HTTPS basic
auth with a read-only `ck_`/`cs_` REST key). Passing
`wooCommerce: { source, intentTtlSeconds, orderKeyGrantsStatusAccess: true }`
(TTL 60 to 86400) to `createMerchantService` mounts
`POST /v1/woocommerce/orders/:id/checkout`, body exactly
`{ "orderKey": "wc_order_..." }`. The buyer supplies only the order ID and the
order key that WooCommerce shows on its order pages; the price always comes from
the store.

- Pay-by-link policy: `orderKeyGrantsStatusAccess: true` is a required
  acknowledgment that anyone holding an order ID and key receives the intent's
  status token, which also reads signed events and survives order-key rotation.
  This is weaker authentication than WooCommerce's own `order-pay` page, which additionally
  checks `pay_for_order` and guest email verification.
- Payable means: matching order key (timing-safe), status `pending`, currency
  `BTC` and a positive `total` with at most 8 decimals, converted exactly to
  millisatoshis. Set the store currency to Bitcoin with 8 decimals. Fiat-priced
  stores are refused (`409`), because no exchange-rate authority is configured.
  WooCommerce 11.1.2 includes BTC in core; no currency plugin is required.
  Configure precision before creating orders: changing it later cannot repair
  already-rounded totals. WooCommerce uses PHP floats when formatting totals;
  this adapter exactly converts the returned total, not the unrounded catalog
  price. Store arithmetic and discounts remain the merchant's authority.
- A wrong key and a missing order both return `404`; store errors, redirects,
  non-JSON, bodies over 256 KiB, mismatched order IDs and reads over the budget
  return `503`. The budget (default 10 s, 1 to 30000 ms) is a hard deadline
  over the request and every body read, even when the transport ignores abort;
  late responses are discarded and the body is cancelled best effort.
  Malformed IDs or keys never reach the store, and issuer/observer health runs
  only after the store admits the order.
- Order references are store-bound: `woocommerce:<sha256 tag of the store
  origin>:<id>`. The first admitted request creates that intent under a
  route-specific idempotency key, with expiry `now + intentTtlSeconds`, one
  attempt and one invoice. Replays (including a concurrent first request that
   lost the race) return the same intent and invoice. An existing intent without
   the matching route-specific key, for example an ordinary admin intent with
   the same reference and amount, is refused (`409`). The key is a consistency
   linkage, not proof of authorship: admins can deliberately supply it and
   already have order-binding authority.
- A later store total that differs from the persisted intent, or a non-pending
  order, is refused (`409`); persisted terms are never replaced. Refusal does
  not revoke an issued invoice, so store cancellations and price changes after
  issuance still need fulfillment reconciliation.
- Ambiguous issuance returns `202` with `actionRequired: "issuance_reconciliation"`;
  later requests (or `tick`) retry the same issuer operation.
- With an acceptance consumer configured, the invoice stays hidden until the
  trusted backend registers the order binding, as for admin intents. Optional
  `wooCommerce.bindVerifiedOrders: true` explicitly delegates registration to
  this verified-store backend instead of requiring a second admin request;
  it requires a configured consumer. Absent/false preserves manual registration.
  Each checkout must first admit a fresh store read, match the persisted amount
  and route key, resolve issuance, and reverify the invoice amount/payee/hash
  before binding complete terms and exposing the invoice. Binding conflicts or
  corruption refuse with `503`; unknown issuance stays unbound (`202`). New
  bindings require waiting state and an unexpired invoice (`409` otherwise), so
  historical paid/reconciliation state cannot create a missing binding. Original
  bindings replay without extending expiry or replacing terms.
  The waiting-state check and consumer insertion are separate transactions;
  this does not claim cross-database serialization against another process.
  Configuration, source methods and returned price scalars are captured before
  backend awaits. Custom source implementations are trusted backend code, not
  untrusted transports.
- The adapter never writes to the store and does not mark orders paid. The route
  is unauthenticated by design, so each well-formed request may cause one
  bounded store read; deploy it behind rate and concurrency limits.

Upgrades: nothing changes unless the option is supplied. No schema or stored
format changed. Existing intents without the route key are never adopted by this
route. Missing consumer bindings alone prove nothing: no startup, tick or status
read registers them. Explicit true plus a fresh admitted checkout can register
an older matching, waiting, unexpired invoice. A store read is a snapshot, not an
order lock: price/status can change during issuance or after exposure, so this
policy does not guarantee current Woo fulfillment eligibility. Actual receipt
verification is unchanged. Mainnet remains disabled by the merchant ledger.

Public references: [REST API v3 order retrieval](https://woocommerce.github.io/woocommerce-rest-api-docs/#retrieve-an-order),
[HTTPS authentication](https://woocommerce.github.io/woocommerce-rest-api-docs/#authentication-over-https),
[WooCommerce 11.1.2 BTC currencies](https://github.com/woocommerce/woocommerce/blob/11.1.2/plugins/woocommerce/i18n/currencies.php),
and [decimal formatting](https://github.com/woocommerce/woocommerce/blob/11.1.2/plugins/woocommerce/includes/wc-formatting-functions.php).

### Disposable real-store diagnostic

`bun run test:woocommerce` explicitly starts isolated WordPress, MariaDB and
WP-CLI containers with pinned official-image digests, verifies the SHA-256 of
the public WooCommerce 11.1.2 plugin, and creates a synthetic pending BTC order
with 8-decimal precision and a disposable read-only REST key. Requires Docker,
OpenSSL and public artifact download access. The ordinary test suite skips this
fixture; the `woocommerce-conformance` CI job runs on manual workflow dispatch.

Only the TLS proxy exposes a loopback listener; the store and database have no
published ports and run on an invocation-owned internal Docker bridge. For
rootless Docker compatibility, the host-local proxy forwards through a bounded
PHP HTTP client executed inside the owned store container to its real Apache
REST endpoint (it does not mock the order response). Child-process
`NODE_EXTRA_CA_CERTS` trust admits the disposable store; ordinary trust, a wrong
CA and a wrong hostname must refuse. The production default fetch reads the
actual store total and rejects a wrong order key and invalid REST credentials;
negative TLS cases also assert the underlying certificate/hostname error code.
TLS terminates at Bun; the HTTP hop inside the store container is plaintext.
Checkout replays one synthetic
invoice and never marks the order paid. No TLS validation is disabled and no
system trust store is modified. Cleanup removes only invocation-labeled objects;
it never prunes unrelated containers, networks, volumes or images.

This proves local REST compatibility and CA/hostname checks, not a deployed
store's hosting configuration, checkout plugin, rate limits, settlement, signer
custody, mainnet authority or production readiness. The synthetic invoice issuer
does not contact a Lightning node and the fixture never spends funds.

### Fulfillment writeback to a test store (opt-in, best effort)

`createWooCommerceFulfillment({ storeOrigin, consumerKey, consumerSecret,
acceptances: consumer, testStoreOnly: true })` marks a WooCommerce order paid
after the acceptance consumer holds a verified acceptance for it. Use a
separate `read_write` REST key; checkout keeps its read-only key. Acceptances
only exist for regtest/signet, so `testStoreOnly: true` is required and the
store must not be a production store: the flag cannot verify that for you.

`fulfill(orderRef)` is caller-driven. Nothing calls it on startup, `tick` or
event delivery, and it persists no local state, so upgrading changes nothing
and historical acceptances are only written back when you call it for that
order. It refuses references from another store, and returns:

- `not_accepted`: the consumer has no verified acceptance; the store is not contacted.
- `fulfilled`: the order is `processing` or `completed` with `transaction_id`
  equal to the payment hash, the exact bound BTC total and a valid paid time.
  `wrote` says whether this call performed the write.
- `reconciliation_required` (`missing`, `status`, `price`, `transaction`): the
  store disagrees with the acceptance (for example cancelled, on-hold, failed,
  different total or another transaction ID). Nothing is written.
- `unavailable`: the first read failed; nothing was written.
- `unknown`: the write was dispatched and may have committed, or may still be
  executing (for example after a timeout).
- `write_unconfirmed`: the write succeeded but the read-back does not prove
  payment completion (for example the order was cancelled meanwhile).

After `unknown` or `write_unconfirmed`, do not call `fulfill` again for that
order until an operator has resolved it: a later read showing `pending` with an
empty transaction ID does not prove the earlier request stopped executing.

The only write is `PUT /wc/v3/orders/<id>` with exactly
`{ "set_paid": true, "transaction_id": "<payment hash>" }`, never a `status`
field, and only for a `pending` order with the exact BTC total and an empty
transaction ID. WooCommerce has no conditional update (WooCommerce 11.1.2
source), so the checked status and price are not atomic with the write: a
concurrent store change can still land between the read and the write, and the
read-back only detects it after store hooks (emails, stock) ran. Concurrent
calls for one order on the same adapter instance share one attempt; other
instances and processes are not serialized. The diagnostic's fixture order has
no line items and goes straight to `completed`; orders that need processing
end in `processing`.
The disposable real-store diagnostic exercises the full path (checkout,
synthetic settlement, signed delivery, consumer acceptance, writeback, replay)
and checks that a cancelled order stays untouched.

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

## Monero regtest receipt rail

A separate, local-regtest-only Monero rail, used by the demo shop in the dev
stack (`DEVELOPMENT.md`). Modules: `@rillswap/payments/monero-rpc` (minimal
monerod and `monero-wallet-rpc` client), `monero-ledger`
(`MoneroReceiptLedger`, `classifyMoneroPayment`), `monero-server`
(`createMoneroRegtestService`) and `monero-contract` (terms, view, signed
events, `verifyMoneroRegtestReceipt`). It has its own ledger file and keys; the
Lightning merchant ledger, endpoints and CLI are unchanged.

Regtest uses mainnet address formats, so the network is affirmed instead of
inferred: the ledger config pins a `monero-regtest/1` profile (namespace,
confirmations of at least 10, block-1 hash), the merchant origin and the wallet
primary address. Before every allocation and observation the daemon must report
`fakechain`, block 1 and the primary address must match, and the wallet must
have scanned up to the daemon height; otherwise nothing changes. Mainnet,
stagenet and testnet are not supported.

| Endpoint | Authority | Exact JSON body |
| - | - | - |
| `POST /v1/monero-regtest/intents` | Merchant admin bearer, `Idempotency-Key` | `orderRef`, `amountAtomic` (piconero string), `expiresAt` |
| `GET /v1/monero-regtest/intents/{intentId}` | Scoped read capability or admin | None |

Each intent gets a fresh subaddress of account 0. Because `monero-wallet-rpc`
forgets unstored subaddresses when it crashes, indices already in the ledger
are skipped and the wallet is stored before the intent commits. Buyers never
write: the host calls the service's `tick()` periodically. Each observation
counts confirmed incoming transfers to the subaddress (`in`, enough
confirmations, unlocked, no unlock time, no double spend), one receipt per
transaction. Amounts are parsed losslessly as `bigint`.

- Exactly the price in blocks timestamped in `[createdAt, expiresAt)`:
  `regtest_receipt_recorded`, with an outbox acceptance and a signed
  `monero-regtest-event/1` (scope `local_regtest_only`).
- More than the price (including dust from anyone who knows the address), any
  transfer outside the window, or a short sum after expiry with nothing
  pending: `regtest_reconciliation` with reason `overpaid`, `late` or
  `underpaid`. Reconciliation is terminal; later funds are not recorded.
- Expiry alone decides nothing: on-time funds confirming after expiry are paid.
  Evidence timestamped after the observation time defers the decision, so an
  acceptance never predates the blocks it cites.
- An exact confirmed sum is paid even if another transfer is still pending;
  funds arriving after acceptance are not recorded (handle them out of band).
- A paid receipt no longer backed by the same qualifying entry in a later
  caught-up view (gone, re-mined in another block, or no longer meeting the
  confirmation rules) is latched as `regtest_evidence_impaired`; the
  acceptance and event are kept and never reissued.

Verify events with a pinned key and the expected terms. They are local regtest
evidence only, never a mainnet payment claim.

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

### Explicit ULN302 configuration observations

`observeUln302Configuration(request, reader)` now observes one caller-recognized
send or receive library's effective messaging configuration. Its separate
`layerzero-uln302-observation/1` request requires independently supplied chain,
genesis, endpoint EID, remote EID, endpoint/OApp/library addresses and raw runtime
hashes, recognized library direction, and a reference block number/hash. It does
not discover a trusted library from its version or adopt RPC results as pins.
The returned frozen, JSON-safe artifact always says `authority: "none"`.

The four-method reader only supplies network, block, code and read-only calls.
Pins and methods are captured before awaiting. Code, endpoint identity, selected
library and version `(3,0,2)` are checked at the explicit reference block; the
network, genesis and block anchor are rechecked before returning. This is
consistency under a trusted reader, not cryptographic authentication of RPC or
protection against a dishonest reader. The adapter owns RPC deadlines and egress.

Endpoint `getConfig` supplies the effective, already merged ULN configuration:
confirmations, sorted required/optional DVNs and optional threshold. The observer
never merges raw override sentinels itself. Literal zero confirmations are valid;
cross-array DVN overlap is permitted. Each list supports the pinned protocol's
full 127-address maximum. Canonical outer and inner ABI encodings are checked
before accepting bounded configuration bytes (32768 inner, 33024 outer bytes).
Source executor configuration is read only for send libraries. Unset executor
size/address values remain visible with `configured: false`; nonzero fields are
not proof of executor identity, sufficient gas or operational delivery.

Receive observations select the default or OApp timeout getter from the selected
library's `isDefault` flag. Expiry is compared to the reference block number,
not wall time. Zero-library/positive-expiry and expired tuples are preserved.
`nonzeroLibraryWithinWindow` describes those fields only: timeout-library code,
configuration, usability and security approval remain unobserved. No timeout
library is silently treated as having the selected library's configuration.

Caller hashes and the ABI source commit do not prove deployed source correspondence,
ownership, upgrade authority, peer connectivity or security-policy approval.
Actual USDT0 deployment conformance remains unproved; published directory entries
are not reciprocal peer evidence. This diagnostic supports explicit observation
requests without changing the old quote/receipt profile's network/proxy restrictions.
It produces no quote, pathway, signing payload, route approval, merchant acceptance
or recovery authority. It makes no automatic requests or writes. Existing stores,
startup, persisted formats and upgrade behavior are unchanged.

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
