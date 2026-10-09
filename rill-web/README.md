# rill-web

Independent strict TypeScript RillSwap client SDK and static browser UI.

All runtime assets are bundled locally. Localhost static serving is supported;
reliable `file://` operation is not promised.

Status: pre-release and not suitable for real funds.

## Merchant invoice adapter

`src/swap/merchantCheckout.ts` adapts the existing regtest BTC-to-Lightning
flow to independently pinned merchant checkout terms. Supply the merchant's
approved provider IDs, explicit wallet/refund/fee limits and a payer-controlled
durable encrypted recovery store. All fee ceilings together must satisfy the
buyer cap, and the invoice needs at least 1,800 seconds before initial quoting.
Native checkout and swap dispatch share the same attempt reservation, preventing
automatic payment by another rail after an ambiguous attempt.

The adapter returns public tracking references, never the preimage or claim
secrets. Provider completion means waiting for merchant receipt, not fulfillment.
Expired terms are rechecked after prompts and before giving a signed funding
transaction to the provider. Once that transaction has been shared, retain
recovery and monitor it even if the customer's broadcast callback fails.
Existing payer recovery works through the CLI; a closed tab cannot autonomously
sign refunds. This adapter is not yet advertised by the native-only merchant
HTTP service. An explicit disposable scripted BTC-to-LN merchant checkout now
has funded happy-path conformance evidence, not browser-wallet, restart or
production conformance.

The site has two pages. `index.html` is a **local-only development preview**
that makes no connection: chain-mode selection does not contact or verify a
node; the provider-description field renders only inert pasted text; the
manual signed-advertisement panel verifies either canonical PUBLIC application
metadata or, when explicitly selected, a PUBLIC raw signed NIP-01 kind-39417
event object for one supported network against an independently entered
identity and locally defined network/profile, holding a revision maximum in
memory for this tab only. Never enter secrets or send funds to this preview.

`swap.html` is the **experimental BTC to LN swap client** (signet, testnet4,
and regtest; mainnet is refused until release acceptance). `src/swap/` ports
rill-cli's `run_swap`:

- bounded provider discovery across up to four configured relays (highest valid
  kind-39417 revision per provider slot; same-revision equivocation and a flood
  of more than 256 combined distinct events are refused), the RS-001
  handshake (epoch-bound when the signed announcement requires it), signed
  envelopes, and strict NIP-59 receive rules ported from rill-provider;
- BOLT11 decoding and rill-provider's invoice admission policy (the browser
  has no Lightning node), wire schema validation with build-time generated
  Ajv validators, and the ContractTerms/`check_terms_offer` rules;
- Taproot contract reconstruction (ordered BIP327 KeyAgg) and RS-007 recovery
  documents byte-identical to rill-cli's, encrypted to the user's age X25519
  recipient;
- funding from the user's own wallet: the user pastes a **finalized PSBT**
  (native segwit inputs with `witness_utxo`, so the signed maximum funding fee
  is checkable), the client requires exactly one contract output with the
  exact amount and P2WPKH/P2TR other outputs, and the user broadcasts;
- the mandatory cooperative MuSig2 claim (`cooperative-claim/v1`): every
  handshake requests it and accepts or terms without it are refused. After the
  provider pays, the client verifies the preimage, echoes one readiness
  challenge, reconstructs the proposed key-path claim byte for byte (outpoint,
  provider destination, fee within the signed cap, non-dust output, BIP341
  sighash), journals a reservation, and cosigns once with the vendored
  rill-crypto WASM build (`src/vendor/rill-crypto`, the same libsecp256k1
  MuSig2 code as the CLI and provider). It then verifies the provider's
  partial and the aggregate signature before its receipt.

The swap page uses a compact card, a settings dialog for provider/network and
fee caps, progressive wallet setup, a simple progress indicator, and collapsed
technical activity. Public builds default to **mainnet preview**, with the
start action disabled and an independent runtime refusal before any relay
connection. Select a test network in Settings to use the experimental flow.
Loading the page or changing settings does not contact a relay.

Deployment defaults are validated at build time:

```sh
VITE_RILLSWAP_NETWORK=signet bun run build
```

Supported values are `mainnet` (the unconfigured default), `signet`, `testnet4`,
and `regtest`. `VITE_RILLSWAP_RELAYS` optionally sets a whitespace- or
comma-separated relay list. The older single-relay `VITE_RILLSWAP_RELAY`
setting still works; specifying both fails the build. Public defaults use
`wss://relay.damus.io`, `wss://nos.lol`, and `wss://relay.primal.net`; regtest
uses `ws://127.0.0.1:7777`. Plaintext relays
are restricted to loopback on regtest, and malformed configuration fails the
build. Switching networks resets the relay preset instead of retaining a
local deployment endpoint. Relay settings are public, not wallet credentials.
Relay operators can see IP and transport metadata; encrypted swap messages do
not hide that metadata. A relay preset is not an endorsement of providers.

`dev/devctl` explicitly builds the browser with regtest/local-relay defaults.
An older public installation reloading an unconfigured build now opens the
blocked mainnet preview instead of signet. No stored settings or journal
records are migrated, and no swap or background work is resumed. The relative
Vite asset base supports static hosting under a repository or signet subpath;
this configuration does not authorize a funded mainnet release or publish it.

### Automatic quote selection

Leave the provider identity empty for automatic discovery, or pin it in
Settings. **Get quote** queries the configured relays, filters authenticated
announcements by amount, and requests up to eight firm offers on separate
single-relay sessions. Indicative fees order the bounded shortlist; only
locally verified signed terms determine the displayed winner. The winner has
the lowest contract amount among those responding offers (ties use identity
and slot). Wallet network fees are additional and are not estimated here.
Unpinned identities are self-authenticated, not approved or reputation-rated;
identities and slots can be created by one operator. There is no global
best-price or independent-provider guarantee.

The quote screen offers manual selection under provider details. **Use this
quote** executes that exact displayed offer on its original session. Preparing
a quote does not accept terms, export recovery, request funding, or share a
signed transaction. Editing discards the quotes and closes their transports;
unused offers expire without funding. After execution starts there is no
automatic switch to another provider. Expiry and funding checks remain active
through recovery saves and every acceptance/funding publish attempt.

Quote requests disclose the invoice to the queried providers. Partial relay
results and failed providers are disclosed, not treated as complete discovery.
Provider-advertised endpoints are never automatically contacted. Existing
manual `runSwap` callers retain their prepare-and-execute behavior, and no
persisted state or journal schema changes.

### Browser recovery wallet primitives

`src/browserRecoveryWallet.ts` provides a browser-stored recovery identity,
matching-backup checks, and atomic refund-address allocation. The swap form's
automatic defaults are being integrated separately; these primitives do not
enable mainnet swaps or constitute a complete browser refund flow.

The v1 identity uses a 128-bit, 12-word English BIP39 mnemonic, NFKD
normalization, and an empty passphrase. It stores one validated record in
IndexedDB database `rillswap-browser-wallet-v1`, containing the identity,
next-unused address counters, and matching-backup verification status. Keys
are **not encrypted at rest**. Same-origin scripts and anyone with access to
browser storage can access them. URL paths, including `/signet/`, are not
storage security boundaries.

Refund destinations are P2WPKH. Paths are `m/84'/0'/0'/0/index` on mainnet,
`m/84'/1'/0'/0/index` on signet, `m/84'/1'/1'/0/index` on testnet4, and
`m/84'/1'/2'/0/index` on regtest. Allocation commits before returning an
address, never rolls back on cancellation, and stops at index exhaustion.
Skipped BIP32 children are refused rather than silently relabeled. Restoring
old browser state or using a cloned mnemonic on another device can reuse
indices; atomic transactions only coordinate this browser's origin-local
storage.

The age X25519 encryption identity is derived independently with
HKDF-SHA256: BIP39 seed as input, UTF-8 salt
`RillSwap/browser-recovery/v1`, UTF-8 info `age-x25519/v1`, and 32 output bytes.
The output is encoded as a native `AGE-SECRET-KEY-1...` identity. Neither
deployment URL nor an unversioned derivation setting affects these keys.

The JSON recovery-key backup is `{format: "rillswap-browser-recovery",
version: 1, scheme: "bip84-rillswap-v1", mnemonic: "..."}`. A matching check
does not replace the active identity or restore unknown counter history.
**This key backup is not enough to recover a swap:** retain the encrypted
per-swap recovery documents too, because contract secrets are independently
random. Verification proves a matching key, not backup durability or swap
recoverability.

Previous versions stored no browser wallet identity. First use under the new
API creates one on genuinely absent state, without scanning, resuming, or
funding anything. Existing swaps keep their original keys and destinations.
Valid records are reused; partial, malformed, unreadable, and unsupported
records are preserved and block initialization. No memory-only replacement
or implicit migration occurs. Complete storage loss is indistinguishable from
first use, so a newly created identity does not restore earlier swaps. Keep
the original backup files and do not clear browser storage while funds remain.

There is no chain backend in the browser. The user enters the current block
height; it sets the refund-height ceiling (`tip + max refund delay`) and the
recovery scan birthday, so a wrong height can only lengthen the user's own
lock or make offers fail. Keys exist only in the tab's memory. The terms
recovery file must be downloaded before accepting terms, and the funded one
before the funding binding is sent and before broadcast. If the provider does
not pay, refund from the funded recovery file after the refund height (see
"Refunding a stopped swap" below); the browser does not refund. The only thing stored in the
browser is the cooperation journal below, which never grants anything, so an
upgrade or reload reads, migrates, or resumes nothing; an interrupted swap
continues only through the downloaded recovery file.

### Refunding a stopped swap

You need `rill-cli` (see its README), a synced Bitcoin Core node for the same
network, the funded recovery file, its age key, and the funding attempt ID that
the page printed (`attempt <ID> revision 0`). After the refund block shown by
the page, run (it waits for that block if started earlier):

```sh
mkdir -m 700 refund-attempts
rill recover watch-refund --chain-only --network signet.json \
  --crypto-library /path/librill_crypto.so \
  --funding-attempt-id ATTEMPT_ID --binding-revision 0 \
  --rpc-cookie ~/.bitcoin/signet/.cookie --rpc-port 38332 \
  --identity rillswap-recovery.key --intent-dir refund-attempts \
  --initial-fee-sat 300 --max-fee-sat 3000 rillswap-funded-recovery-....age
```

`--network` is the trusted network file (`rill-docs/networks/signet.json`). The
refund pays the refund address you entered. `rill recover sign-refund` with
`--output refund.tx` instead writes the signed transaction without sending it.
`--chain-only` means the refund relies on the contract alone: it is sent only
after the refund block while the provider has not claimed. If the invoice is
your own node's, use `--lnd-port`, `--lnd-tls-cert`, and
`--lnd-invoice-macaroon` instead so it also refuses once the invoice is paid.
`rill recover broadcast-refund` (one fixed `--fee-sat`, `--intent FILE`) sends
a single refund without escalation.

Cooperation never blocks the swap. The client cosigns only after it holds the
verified payment preimage, and BIP341 signatures commit the exact outpoint,
amount, and output, so a cosignature can only let the provider take the output
it is already owed. Without a chain backend the browser cannot check
confirmations or fee policy like the CLI does; it trusts the provider for
confirmation and fee liveness only. That costs the user nothing: the claim fee
is capped by the signed terms and comes out of the provider's own output, and a
wrong report only delays the provider's claim. Any refusal, timeout, or missing browser
capability abandons cooperation and the provider claims with the preimage
instead, costing privacy only. Before allocating its nonce the client holds an
exclusive Web Lock and commits a create-only IndexedDB record (database
`rillswap-cooperation`, keyed by contract hash, code in
`src/swap/cooperationJournal.ts`, browser tests in
`tests/cooperationJournal.spec.ts`, holding the cooperation ID and
sighash, no secrets or preimage) with strict durability. An existing record
refuses whatever its age or shape; an absent one proves nothing. Records are
never pruned (one small record per swap): neither age nor a free lock proves
that every context able to sign for that contract is gone. The secret nonce lives only inside one
WASM handle and is never stored, and a page restored from the back/forward
cache never signs. After payment the page offers an optional paid recovery file
with the preimage and any reservation.
There is no service worker or in-page update check: a new release takes
effect only when the user reloads, which also discards the in-memory keys.

What relays learn: each gift wrap shows its recipient key (the provider's
epoch inbox or session key, or this tab's fresh session key), a randomly
backdated timestamp, and its size, and the client's subscription names its
session key; payloads, invoices, payment hashes, and session IDs are encrypted.
The relay also sees the client's IP address unless the browser uses Tor or a
VPN. This is not anonymity.

The swap page's CSP allows `connect-src wss:` plus plain `ws://` to loopback
(for a local regtest relay); `RelayConnection` enforces the same rule. It also
allows `connect-src 'self'` and `script-src 'wasm-unsafe-eval'` so the page can
fetch and compile its own bundled MuSig2 WASM (loaded only after funding). The
preview page keeps `connect-src 'none'`.

The HTML contains a meta Content Security Policy that restricts later script,
style, and connection loads. It is **not** an HTTP response-header policy:
it provides no anti-framing `frame-ancestors` protection, and the documented
Python loopback server does not add such a header. A production host must
configure and test its actual response headers rather than treating this meta
tag as a complete CSP.

The "Test browser storage" button is an explicit, synthetic IndexedDB write,
read, and best-effort deletion in a unique diagnostic database. It may request
persistent browser storage. Startup and reload do not open a database or ask
for persistence. A successful diagnostic proves neither long-term durability
nor recovery; interruption may leave an inert diagnostic database. The preview
never scans, repairs, or reuses old/partial databases automatically. There is
no swap database, encrypted-record format, or auto-migration to claim; the
swap page's cooperation journal is separate and refusal-only.
Absence of a database proves nothing about prior browser use or safe funding.

`src/nip59Transport.ts` is the gift-wrap producer the swap client uses
(`src/swap/session.ts` owns the keys, envelopes, and relay publishing). Given an already application-validated
canonical RS-001 envelope, a caller-owned ephemeral session secret, and an
independently selected recipient mailbox key, it constructs a NIP-59 gift wrap
using pinned `nostr-tools`. It checks the canonical JSON bytes, envelope sender
key, experimental binding, outer signature/recipient, and size cap. It does
**not** validate the complete RS-001 schema/signature/transcript, choose or
persist any key, contact a relay, establish session authority, or enable funds.
Additional transport padding
requires a future binding; this one uses NIP-44's mandatory padding only.
An installation upgrading from the prior version receives no listener, key,
database read/migration, reprocessing, or swap action, regardless of absent,
partial, old, or restored browser state. `bun test unit/nip59Transport.test.ts`
checks the isolated producer with disposable synthetic keys.
`scripts/emit-nip59-test-wrap.ts` is test-only stdin/stdout glue for a local
provider interoperability test. It must never receive production secrets.

`src/manualProviderAdvertisement.ts` is a **read-only** application verifier
used only by the explicit manual-import panel. It verifies the RS-005
*application-signed* canonical manual
advertisement against an identity approved independently by the user, a
complete selected network and profile, supported suite, bounded creation and
expiry times, strict vendored JSON schemas, and RS-001 numeric bounds. The
local profile additionally requires positive advertised amount-band minima
and valid x-only epoch inbox keys. The two vendored schemas and expired,
disposable signed fixture are SHA-pinned to rill-docs in the unit test. Ajv
validators are generated at build time and `bun run build` checks them, so
Chromium's existing no-`unsafe-eval` CSP remains effective. Use
`bun test unit/manualProviderAdvertisement.test.ts` for the focused tests.
The result is an authenticated **historical offer**, not evidence of liquidity,
currentness beyond signed expiry, owner-controlled endpoint availability, or
signing/admission authority. Advertised endpoints and mailbox keys are inert
proposals; no connection or key allocation occurs. It does **not** verify
NIP-01 announcement IDs/signatures/tags. There is no registry, relay
discovery, trust-pin persistence, or automatic refresh. Same/lower revisions
cannot replace an offer already observed in this tab, but reload loses that
history and **cannot prove** global currentness or absence of a newer offer.
The five locally defined network identities are vendored from rill-docs; custom
networks are not selectable here. A missing, partial, older-version, or
restored cache proves no revision/currentness and triggers no automatic repair,
rescan, network access, or state migration on upgrade.

`src/nostrProviderAnnouncement.ts` is an offline-only verifier for the
private-regtest RS-005 kind-39417 event binding. It requires a separately
approved provider identity and complete network/profile, authenticates the
outer NIP-01 ID/signature and the nested application signature, and checks
exact ordered tags, address `d`, matching signer/timestamp, size and nesting
bounds, and the single-regtest-network restriction. The manual-import panel
calls it only after explicit selection of the private-regtest NIP-01 paste
format and a verification click. Its default application-signed import mode
is unchanged. It does not subscribe to a relay; the swap client's
`src/swap/relay.ts` caps each raw relay message at 128 KiB **before**
extracting the event-object bytes. It returns a historical signed candidate, not globally
current revision, endpoint approval, session ownership, or financial
authority. No new state is read or written during startup or upgrade.

`src/recoveryAgeContainer.ts` is the age boundary the swap client's
`src/swap/recovery.ts` uses.
Using pinned `age-encryption`, it accepts *caller-validated* canonical RS-007
UTF-8 plaintext bytes and exactly one independently selected age X25519
recipient, and returns bounded binary age v1 ciphertext. It does not inspect
full recovery schema, verify signatures/contract/secrets, prove recipient
ownership or decryptability, persist/export a file, or offer any recovery UI.
Never pass real recovery secrets to the development preview or test glue.
Unit and Chromium CSP tests use synthetic public fixtures for both profiles.
The opt-in `RILLSWAP_RUN_WEB_CLI_AGE=1 RILL_CRYPTO_LIBRARY=<local native path>
AGE_BINARY=<Go age v1.3.1 path> bun run test -- tests/recovery-cli-interop.spec.ts`
checks actual browser-produced bytes with independent Go age decryption and
CLI native offline inspection, and verifies that the CLI refuses browser-age
containers with missing required recovery fields or inconsistent contract
hashes without emitting a report; missing native/Go prerequisites fail that
explicit opt-in. This is age-container interoperability, **not W03** browser
recovery generation, durable verified export before funding, or authority to
sign, send, pay, or recover. Upgrading from previous versions introduces no
secret entry, database access, migration, rescan, export, or automatic action;
absent, partial, older, or restored browser state proves no recovery safety.

The embedded build label is disclosure, **not** authenticated release pinning.
There is no automatic update check, but reloading a mutable hosted URL can run
different executable code. Active-swap upgrade handling, independent recovery,
and the full W01/W07/W11 matrix gates remain open.

Develop and test from this directory with Bun and a Playwright Chromium build:

```sh
bun install --frozen-lockfile
bunx playwright install chromium
bun run build
bun run test
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

`bun test unit` runs the SDK unit tests, including parity against the
rill-docs vectors, the BOLT11 specification examples, a Bitcoin Core regtest
PSBT, and a gift wrap produced by rill-provider. From the repository root,
`scripts/regtest_e2e.py --web --crypto-library <path>` runs a live regtest
swap with `scripts/web-swap-e2e.ts` driving `runSwap` (Core's wallet stands in
for the user's wallet) and then requires `rill recover inspect` to accept both
browser-written recovery files. Adding `--unpaid-refund` makes the provider
fail after dispatch and refunds with `rill recover watch-refund` from the
browser-written funded recovery file alone.

Adding `--merchant-checkout` to `--web` instead drives the actual
`executeMerchantSwap` adapter using a separately owned merchant's invoice and
terms. Acceptance requires independently verified merchant paid status and its
stable signed event, in addition to the existing swap and recovery assertions.
This happy-path-only mode rejects unpaid-refund, reconciliation-crash and
LN-to-BTC combinations. See [payments diagnostic setup](../rill-payments/README.md#disposable-web-to-merchant-swap-diagnostic)
for the required verified Bun path and scoped cleanup behavior. Core is still
the scripted payer wallet, not a browser wallet integration.
The optional `--merchant-restart-after-issue` variant gracefully restarts only
the merchant before payer dispatch, preserving the original invoice, keys and
store. It is not browser restart or postsettlement receipt-loss evidence.
The alternative `--merchant-crash-after-settled` variant loses a real settled
backend observation before merchant ledger acceptance, then recovers through
ordinary serving of the same state without another payer dispatch. It is not
transport-level response loss, browser restart or power-loss durability proof.

`bun run test` checks the same built bytes at `/` and `/repository/` on
loopback. All runtime assets are local. Browser tests need a supported
Chromium environment; opening the source directly via `file://` is not a
supported execution mode.
