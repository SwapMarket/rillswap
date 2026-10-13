# rill-web

The RillSwap browser app: a static site that swaps Bitcoin to or from
Lightning, and USDC/USDT to or from Lightning, with no backend of its own.
It discovers providers over Nostr, validates contracts, transactions and
signatures locally, and keeps encrypted recovery records in the browser.

Lightning to stablecoin claims can use a configured gas sponsor, so the
receiving address needs no ETH, or an injected EVM wallet that pays its own
gas. `swap.html` is the swap app; `index.html` is a disconnected diagnostic
preview.

**Status:** experimental and unaudited. Mainnet funding is disabled.

## Install

Use Bun 1.3.11, matching CI. This component depends on the `rill-payments`
directory of the same checkout.

```sh
cd rill-web
bun install --frozen-lockfile
```

## Quick start

Run the complete Docker development stack from the repository root:

```sh
dev/devctl up
```

Open http://127.0.0.1:5273/swap.html. The demo shop is at
http://127.0.0.1:8090/. See [DEVELOPMENT.md](../DEVELOPMENT.md) for a
walkthrough of each swap type against the local Bitcoin, Lightning, EVM and
gas sponsor services.

For standalone development, from `rill-web/`:

```sh
VITE_RILLSWAP_NETWORK=signet bunx vite --host 127.0.0.1   # dev server, open /swap.html
VITE_RILLSWAP_NETWORK=signet bun run build                # static files in dist/
```

## Configuration

Deployment defaults are set at build time and validated:

| Variable | Meaning |
| --- | --- |
| `VITE_RILLSWAP_NETWORK` | `mainnet`, `signet`, `testnet4` or `regtest` |
| `VITE_RILLSWAP_RELAYS` | Nostr relay URLs, comma or whitespace separated |
| `VITE_RILLSWAP_MEMPOOL_API` | Esplora-compatible chain API |
| `VITE_RILLSWAP_BROADCAST_API` | Explicit transaction broadcast API |
| `VITE_RILLSWAP_NODE_API` | Optional user-node browser transport |
| `VITE_RILLSWAP_EVM_RPC` | Read-only EVM RPC endpoint |
| `VITE_RILLSWAP_EVM_SPONSOR` | Gas sponsor endpoint |
| `VITE_RILLSWAP_EVM_ENTRY_POINT` | Pinned ERC-4337 EntryPoint address |
| `VITE_RILLSWAP_EVM_7702_DELEGATE` | Pinned EIP-7702 delegate address |
| `VITE_RILLSWAP_EVM_SPONSOR_POLICY` | Optional sponsor gas policy ID |

Set the sponsor endpoint, EntryPoint and delegate together or omit all three.
The Alchemy Wallet API sponsor path has not been tested live yet (CORS and
responses). Builds without configuration open a blocked mainnet preview.

## Scripts

```sh
bun run typecheck
bun test unit
bunx playwright install chromium
bun run test
bun run build:pages
bun run test:pages
```

`build:pages` creates `tmp/pages/` for GitHub Pages, with the mainnet preview
at the root and a signet site under `/signet/`. It discards local overrides
and never publishes anything. The `Publish static RillSwap` workflow
(`.github/workflows/pages.yml`) tests and deploys it to GitHub Pages on every
push to `main`.

The reference below covers detailed behavior and safety rules.

## Reference

- [Merchant invoice adapter](#merchant-invoice-adapter)
- [Preview and experimental swap pages](#preview-and-experimental-swap-pages)
- [Swap interface and deployment defaults](#swap-interface-and-deployment-defaults)
- [Reverse execution and payment authorization](#reverse-execution-and-payment-authorization)
- [Reverse recovery and claim construction](#reverse-recovery-and-claim-construction)
- [Funding checks and refund actions](#funding-checks-and-refund-actions)
- [Cooperative claims and nonce custody](#cooperative-claims-and-nonce-custody)
- [Privacy and browser security](#privacy-and-browser-security)
- [Nostr transport and advertisement verification](#nostr-transport-and-advertisement-verification)
- [Recovery encryption and release limitations](#recovery-encryption-and-release-limitations)
- [Development and integration tests](#development-and-integration-tests)

### Merchant invoice adapter

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

### Preview and experimental swap pages

The site has two pages. `index.html` is a **local-only development preview**
that makes no connection: chain-mode selection does not contact or verify a
node; the provider-description field renders only inert pasted text; the
manual signed-advertisement panel verifies either canonical PUBLIC application
metadata or, when explicitly selected, a PUBLIC raw signed NIP-01 kind-39417
event object for one supported network against an independently entered
identity and locally defined network/profile, holding a revision maximum in
memory for this tab only. Never enter secrets or send funds to this preview.

`swap.html` is the **experimental swap client** for BTC to and from Lightning
and USDC/USDT to and from Lightning (signet, testnet4, and regtest; mainnet
funding is refused until release acceptance). See
[Swap direction and assets](#swap-direction-and-assets) for the four profiles.
For BTC to LN, `src/swap/` ports rill-cli's `run_swap`:

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
- funding from the user's own wallet. By default the page shows the contract
  address, the exact amount, a `bitcoin:` link and its QR code (`src/qr.ts`,
  an inline SVG built from `qrcode-generator`'s module matrix), and the user sends from any
  native segwit wallet; the page polls the configured mempool API for the
  address (`src/swap/depositWatch.ts`), waits for the first confirmation (a
  wallet may replace an unconfirmed transaction, and the provider accepts one
  binding per swap), fetches the deposit and each parent transaction by hash
  so the fee rests on verified bytes, then signs and shares the binding. The
  same rules apply as to a PSBT: exactly one contract output with the exact
  amount, native segwit inputs, P2WPKH/P2TR other outputs, fee within the
  signed cap. A confirmed deposit that breaks them stops the swap with its
  txid and refund height (it is not bound; refunding it is not yet supported
  by the recovery panel). Several confirmed deposits are never chosen between.
  Under **Advanced**, the user can instead paste a **finalized PSBT** (native
  segwit inputs with `witness_utxo`), which the page checks and shares before
  asking the user to broadcast it. After acceptance the funding deadline is the
  invoice (and checkout) expiry, as RS-003 bounds `terms_expiry` to acceptance
  only;
- the mandatory cooperative MuSig2 claim (`cooperative-claim/v1`): every
  handshake requests it and accepts or terms without it are refused. After the
  provider pays, the client verifies the preimage, echoes one readiness
  challenge, reconstructs the proposed key-path claim byte for byte (outpoint,
  provider destination, fee within the signed cap, non-dust output, BIP341
  sighash), journals a reservation, and cosigns once with the vendored
  rill-crypto WASM build (`src/vendor/rill-crypto`, the same libsecp256k1
  MuSig2 code as the CLI and provider). It then verifies the provider's
  partial and the aggregate signature before its receipt.

### Swap interface and deployment defaults

The swap page uses a compact card, a settings dialog for provider/network and
fee caps, progressive wallet setup, a simple progress indicator, and collapsed
technical activity. Public builds default to **mainnet preview**, with the
start action disabled and an independent runtime refusal before any relay
connection. Select a test network in Settings to use the experimental flow.
Loading the page or changing settings does not contact a relay.
It creates or reuses an origin-local recovery key without network access.
Refund addresses and encryption recipients are automatic; height is fetched
only when requesting a quote. The collapsed **Privacy & terms** section
explains the configured connections, IP visibility, invoice disclosure,
and browser-key storage. Requesting a quote authorizes that attempt's
connections, not later background work or legal acceptance. Advanced
overrides remain under the recovery details. A matching key-backup check is
required before accepting a quote using either browser-wallet default. The
separate encrypted per-swap backup gates are unchanged.

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

#### Chain API and hosting configuration

`VITE_RILLSWAP_MEMPOOL_API` configures an Esplora-compatible chain API. Defaults
are `https://mempool.space/api`, `/signet/api`, or `/testnet4/api` on that
origin, and `http://127.0.0.1:8091/api` on regtest. Switching networks resets
the preset and updates the disclosure. Requests omit credentials and referrers, refuse
redirects, and bound response size and duration. They check genesis and a
stable sampled tip, not independent canonical-chain validity or a signet
challenge. Height reads reveal your IP; recovery funding reads also reveal the
selected public transaction/output and therefore its public addresses/amounts.
No keys, recovery files, or invoices are sent.
The swap CSP admits only mempool.space, blockstream.info, explicit loopback
port 8091, and the build-configured chain/broadcast API origins. A runtime endpoint on another
origin requires rebuilding with its `VITE_RILLSWAP_MEMPOOL_API` allowance;
there is no HTTPS wildcard. The separate preview page still cannot connect.

`dev/devctl` explicitly builds the browser with regtest/local-relay defaults.
An older public installation reloading an unconfigured build now opens the
blocked mainnet preview instead of signet. No stored settings or journal
records are migrated, and no swap or background work is resumed. The relative
Vite asset base supports static hosting under a repository or signet subpath;
this configuration does not authorize a funded mainnet release or publish it.

#### Mainnet and signet Pages artifact

```sh
bun run build:pages
bun run test:pages
```

The tested artifact is `tmp/pages/`: `/` opens the mainnet swap UI, `/signet/`
opens the signet swap UI, and network links work under a repository subpath.
The diagnostic page remains at `diagnostic.html` on each site. Relative assets
and `.nojekyll` support GitHub Pages without a backend. Public builds discard
local `VITE_RILLSWAP_*` overrides so regtest endpoints cannot leak into this
artifact. Mainnet new funding stays blocked; existing refund actions remain
explicitly approved. Neither site connects on load or network navigation.

Enable GitHub Pages with **GitHub Actions** as its source. **Publish static
RillSwap** (`.github/workflows/pages.yml`) then runs on every push to `main`
(or manually), tests the source and assembled sites, and uploads and deploys
them. Pull requests never deploy, and local build/test commands never
publish.
`component-checks.yml` also tests the assembled artifact without publishing.

#### Swap direction and assets

The card's **You send / You receive** selectors and the switch button choose
the pair. `src/swapPairs.ts` is the single table mapping display assets to
protocol profiles: BTC to LN (`btc-to-ln/v1`) is quotable and payable; LN to
BTC (`ln-to-btc/v1`) supports indicative comparison followed by explicitly
approved execution paid from any Lightning wallet (or, under Advanced, a
configured LND node); USDC or USDT to LN (`erc20-to-ln/v1`, RS-010) is
quotable and payable from an injected EVM wallet; LN to USDC/USDT
(`ln-to-erc20/v1`) supports indicative comparison, external Lightning
payment, and a claim to a typed address through a gas sponsor (or, without a
sponsor, a direct claim from an injected EVM wallet). Unavailable pairs explain
why and never connect anywhere.

#### Stablecoin swap execution

Stablecoin to LN (`src/swap/erc20Swap.ts`, `src/erc20Ui.ts`) discovers
providers announcing the `rillswap/evm-assets-v1` extension, picks the
cheapest eligible provider's asset matching the chosen symbol (a dev chain's
`fUSDC` serves USDC) and quotes only providers serving exactly that asset.
The wallet extension (`window.ethereum`, EIP-1193) connects on the asset's
chain before the firm quote names its address; the configured **EVM RPC**
(`VITE_RILLSWAP_EVM_RPC`, loopback Anvil on regtest) is read-only. After
acceptance the wallet signs an ERC20 approval when needed and the lock in the
Boltz ERC20Swap v6 HTLC; the page then learns the preimage from the provider's
settlement observation or its on-chain Claim. The encrypted swap record
(`rillswap-evm-recovery`) carries the signed terms and lock transaction; the
wallet keeps the refund key. Reopening the swap link shows the lock, checks it
on request, and offers a wallet refund once the timelock block has passed.

LN to stablecoin (`src/swap/lnErc20Swap.ts`) quotes the token payout before
creating a hold invoice. The selected firm price may not exceed the estimate.
With a configured **Gas sponsor** (`VITE_RILLSWAP_EVM_SPONSOR` plus the
pinned `VITE_RILLSWAP_EVM_ENTRY_POINT` and `VITE_RILLSWAP_EVM_7702_DELEGATE`,
all three or none; the dev stack sets them) the user only types the receiving
address: the browser generates a per-swap claim key, names its address as the
HTLC claim address, and after the lock confirms submits one sponsored ERC-4337
user operation from that address as an EIP-7702 account that claims and
forwards the tokens (`src/swap/gasSponsor.ts`). The sponsor is untrusted: the
page recomputes the EIP-7702 authorization digest and the EntryPoint v0.7 user
operation hash over calldata it built, pins chain, delegate, and EntryPoint,
refuses any other signature request, and confirms the destination's Transfer
in the included transaction. The sponsor learns the preimage and destination.
On public networks the intended sponsor is Alchemy's Wallet API (what Boltz uses behind its
own proxy): set `VITE_RILLSWAP_EVM_SPONSOR=https://api.g.alchemy.com/v2/<key>`
(restrict the key to your origin in the Alchemy dashboard), the canonical
EntryPoint `0x0000000071727de22e5e9d8baf0edac6f37da032` and SMA7702 v1.1.0
delegate `0x77021100bd87b7008e5e1989d0eb38555d0d0000`, and
`VITE_RILLSWAP_EVM_SPONSOR_POLICY` to the gas policy UUID (sent as
`paymasterService.policyId`; leave it unset for a proxy that applies its own).
A prepared call whose `feePayment` is not sponsored is refused. CORS from the
browser and Alchemy's live responses have not been tested yet; check them on a
supported testnet before relying on them. Without a sponsor, the connected EVM wallet's address is the destination and
it needs native gas for the claim. Pay the QR invoice
from any Lightning wallet, without configuring a Lightning node. The browser
stores the encrypted preimage before the firm request, then commits the signed
terms and invoice in IndexedDB before accepting or displaying the invoice.
It verifies the exact confirmed lock, vendored contract bytecode, live refund
margin, wallet chain/account, and gas balance before claiming. It does not
simulate or estimate claim calldata before recording exposure (those calls
would disclose the preimage). A five-second freshness budget covers final
live checks through the exposure commit. Wallet prompt delays are still a
risk: claim promptly, and never assume a failed request kept the preimage private.

`src/evmClaimJournal.ts` commits an atomic exposure-unknown marker before
sending the preimage to the wallet. Reload never creates another hold invoice
or automatically retries a claim. The recovery view can explicitly check and
claim an unexposed swap in the same browser, even without its relay. Missing
or unknown exposure state cannot authorize a claim: importing a reverse file
in another browser is currently inspection-only. This is a release limitation,
not evidence that the swap was never attempted. Older forward recovery files
remain readable; upgrading does not start chain scans or alter existing records.
Regenerate the standalone bytecode fingerprint after a contract artifact update
with `bun scripts/generate-evm-identity.ts`; unit tests compare it to the source artifact.

#### Lightning to BTC estimates

LN to BTC estimates (`src/swap/reverseSwap.ts`) send RS-004 *indicative*
requests naming only the payout, over the same authenticated handshake as
BTC to LN. No address, payment hash, key, or chain API request is involved,
and nobody is committed. Offers must satisfy the RS-004 economics and the
Settings limits (minimum claim fee reserve 500 sat, minimum provider refund
delay 72 blocks, maximum Lightning hold 432 blocks, matching `rill swap
reverse`); the lowest `hold_invoice_sat` wins. RS-004 requires the preimage
to be durably saved before any *firm* request, so signed terms and the hold
invoice (`checkReverseTermsOffer` in `src/swap/wire.ts`) are requested only
after persistence. Continuing pins the chosen provider and opens a fresh firm
session, as RS-003/RS-004 require. Indicative sessions never become firm sessions.

#### Provider directory

**Providers** opens a directory of every provider announced for the selected
network, before any amount or invoice is entered. Nothing connects until
**Load providers**, which queries the configured relays once and verifies
each announcement for both profiles (`discoverDirectory` in
`src/swap/marketplace.ts`). Each entry shows the directions it serves, its
announced amount limits, its indicative fee (base plus proportional, with a
sample on 100,000 sat), full identity, slot, relays, and announcement expiry.
Choosing an entry pins its identity (the same field as Settings); the form
shows the current choice. Announced limits and fees are indicative; only a
signed quote binds a provider.

#### Automatic quote selection

Leave the provider identity empty for automatic discovery, choose one under
Providers, or pin it in Settings. **Swap** queries the configured relays, filters authenticated
announcements by amount, and requests up to eight firm offers on separate
single-relay sessions. Indicative fees order the bounded shortlist; only
locally verified signed terms determine the displayed winner. The winner has
the lowest contract amount among those responding offers (ties use identity
and slot). Wallet network fees are additional and are not estimated here.
Unpinned identities are self-authenticated, not approved or reputation-rated;
identities and slots can be created by one operator. There is no global
best-price or independent-provider guarantee.

**Show fees** loads the provider directory once (relays only, no chain API)
and keeps the estimate line (`#swap-estimate`) current as the invoice or
amount changes: the lowest announced fee for the amount (`estimateFromDirectory`),
or the reason no announced provider serves it. With that estimate shown, **Swap**
is one step: the winning signed offer executes directly when its total is at
or below the estimate (and, for Lightning to Bitcoin, the address was entered
up front). A higher signed total, a missing estimate, or a missing address
falls back to the review screen below, so a provider cannot quietly charge more
than it announced.

The review screen offers manual selection under provider details. **Use this
quote** executes that exact displayed offer on its original session. Preparing
a quote does not accept terms, export recovery, request funding, or share a
signed transaction. Editing discards the quotes and closes their transports;
unused offers expire without funding. After execution starts there is no
automatic switch to another provider. Expiry and funding checks remain active
through recovery saves and every acceptance/funding publish attempt.

Quote requests disclose the invoice to the queried providers. Partial relay
results and failed providers are disclosed, not treated as complete discovery.
When no announced provider serves the amount, the status lists each provider's
announced limits (`ineligibilityReason`); when providers answer but none
returns acceptable terms, the status lists each provider's typed refusal
(`QuoteFanOut.reasons`, from `SwapError`/`ProtocolError` only, never raw
transport details).

Links can prefill the form through a URL fragment, never a server-visible
query: `#invoice=` selects BTC to LN, and `#address=`/`#amount=` (whole sats)
select LN to BTC. Prefilling is inert (no connection or quote starts) and the
fragment is removed from the address bar; oversized or malformed values are
ignored.
Provider-advertised endpoints are never automatically contacted. Existing
manual `runSwap` callers retain their prepare-and-execute behavior, and no
persisted state or journal schema changes.

#### Swap links and the tracking view

Starting a swap replaces the form with a tracking view. Each time the swap
produces an encrypted recovery container (terms, funded, paid, or claim
stage), `src/swapLink.ts` publishes it into the page address as
`#swap=<base64url age container>&network=<name>` (`pushState` once, then
`replaceState`). Fragments never reach a server, so the address can be
bookmarked, copied, or found in history. Opening such a link renders the
tracking view and loads the record into the **Recover a swap** panel, which
decrypts it locally with the browser recovery key (or an uploaded older key)
and offers the same funding checks, refunds, and reverse claims as a chosen
file; nothing connects until an explicit check. Malformed or oversized
fragments are ignored entirely. The link is as sensitive as the `.age` file:
anyone holding it and the recovery key can act on the swap, and in-tab
protocol sessions are not resumed from it, only recovery.

#### Browser recovery wallet

`src/browserRecoveryWallet.ts` provides a browser-stored recovery identity,
matching-backup checks, and atomic refund-address allocation. The swap form
uses these defaults without manual key or address input. Mainnet funding
remains disabled, and this is a swap recovery identity, not a general-purpose
Bitcoin spending wallet.

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

Encrypted per-swap files include the optional public
`rillswap/browser-refund-wallet` extension with the exact version, scheme,
identity fingerprint, network, index, path, destination script, and address.
It survives funded and paid exports, including cooperative reservations.
These are derivation hints, not signed authority: recovery must derive and
compare against the signed `client_destination_script`. Manual destination
overrides omit the extension. Existing recovery files remain unchanged.

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

#### Recovery backups and refund timing

The observed or explicitly overridden block height sets the refund-height
ceiling (`tip + max refund delay`) and the recovery scan birthday. A wrong
height can lengthen the lock or make offers fail. Contract secrets exist only
in the tab's memory; the separate wallet root is persisted locally. The terms
recovery file must be downloaded before accepting terms, and the funded one
before the funding binding is sent and before broadcast. If the provider does
not pay, refund from the funded recovery file after the refund height (see
"Refunding a stopped swap" below). Browser contract refund construction and
broadcast are supported. The recovery wallet is not a general-purpose Bitcoin
spending UI: its standard BIP39/BIP84 backup can be restored in a compatible
wallet, or use the external refund-address override for a conventional wallet.
No upgrade or
reload resumes a swap; retain the original downloaded recovery files.

#### Refunding a stopped swap

`src/recoveryDocument.ts` currently provides a local, bounded plaintext
admission building block. It requires fatal UTF-8 decoding, Core-compatible
integer/string/member/depth limits, duplicate-free JSON, byte-exact JCS, and
the authoritative closed RS-007 schema. Its deeply frozen result is explicitly
**unverified** and contains secrets; it is not a redacted inspection report.
Never log or persist it. Generated schema code is compiled at build time from
`rill-docs`, not fetched or evaluated at runtime. This code does not verify
signatures, contract-secret consistency, complete funding history, or
cooperative reservations, and does not itself authorize recovery actions; UI
imports and refund actions apply separate authentication and chain checks.

`inspectRecoveryPlaintext(bytes, independentlySelectedNetwork)` in
`src/recoveryInspection.ts` adds offline, historical BTC to LN inspection.
It checks the complete network identity, handshake and contract semantics,
embedded signatures, secret/public-key and preimage consistency, every
Taproot artifact, all signed funding revisions, and any retained cooperative
reservation. Expired contracts and legacy empty feature lists are accepted;
a reservation can refer to an older retained funding revision. Recognized
reverse-only extensions are rejected for BTC to LN, while optional unknown
extensions remain opaque. Empty history is valid for an initial record, but
proves no funding. Errors are generic and the frozen report contains only
public metadata, never keys, preimages, or the document.
Its explicitly projected, deeply frozen `fundingHistory` contains only the
public binding fields, not signatures or the secret-bearing record. These
fields are still not transaction or chain evidence.

Inspection proves internal consistency under the embedded signers, **not**
provider provenance, your ownership of the destination, chain inclusion,
unspent state, maturity, or permission to sign/broadcast. It makes no network
or storage calls. The collapsed **Recover a swap** panel opens a local age file
with the saved browser key by default, or with an explicitly selected original
age key file. The key override never replaces the saved identity. Choose the
original swap's network in Settings before inspecting; a different network
selected when opening finishes discards the result. No decrypted document or key is shown or stored,
and neither files nor reports are uploaded. The refund
planner authenticates its own byte snapshot and separately verifies the
funding output and refund conditions; a report is never authorization.
Upgrades perform no startup work, migration, or automatic recovery; absent or
partial records trigger nothing and failed imports do not modify the input.

The shared synthetic signature corpus runs in unit tests and the browser
under a no-network CSP. To compare every case against Core's real native
verifier using an **already running** `rillswap-dev-tools-1` container:

```sh
RILLSWAP_TEST_RECOVERY_NATIVE=1 bun test unit/recoveryInspectionNative.test.ts
```

The opt-in inspection test is read-only and does not create containers or
access the chain.

#### Offline refund construction

`constructSelectedRecoveryRefund` in the same module is a pure offline BTC to
LN refund constructor used by the browser refund action (`browserRefund.ts`). It reauthenticates its own recovery bytes, selects
an explicit signed funding attempt/revision, and verifies the actual funding
transaction's identity, anchor, inputs, and exact contract output. It uses the
signed client destination only, caps the fee, enforces the 294-sat P2WPKH or
330-sat P2TR dust floor, requires an observed height strictly above the refund
lock, and signs a fixed BIP341 script-path transaction with fresh Web Crypto
auxiliary randomness. The result contains only immutable public transaction
bytes and metadata. Construction supports the exact mainnet, default signet,
testnet4, and namespaced default-regtest execution identities used by Core;
other identities remain inspectable but cannot sign. This does not enable new
mainnet funding. Secret-bearing authenticated state remains private and
uncached; temporary byte buffers are cleared best-effort, not guaranteed erased
from browser memory.

Its caller-supplied transaction and height do **not** prove inclusion, an
unspent output, maturity, destination ownership, or permission to spend.
Returned signed bytes are a **broadcastable spending capability**: a future
real-funds caller must independently verify the chain and obtain explicit
approval **before signing or export**, then recheck before broadcasting. The
constructor itself has no network or storage side effects. The browser action
layer described below owns explicit approval, observations, and durable intent.
Missing/partial inputs never trigger automatic work.

To compare the synthetic refund corpus's digest, signature, witness, exact
transaction, txid, and vsize with Core's native implementation (public fixture
keys only, no chain access):

```sh
RILLSWAP_TEST_RECOVERY_NATIVE=1 bun test unit/recoveryRefundNative.test.ts
```

### Reverse execution and payment authorization

The recovery panel now supports explicit BTC to LN refund preparation,
identical-byte download, and broadcast, including existing mainnet contracts.
New mainnet funding remains blocked. Reverse execution uses the separate
explicit-action controller described below.

By default the reverse execution exposes the provider's hold invoice
(`exposeInvoice` in `swap/reverseExecution.ts`) for any Lightning wallet:
the page journals an `external-wallet` payment intent (one per payment hash
across tabs) and encrypts the terms snapshot before the invoice, its QR code,
`lightning:` link, and a copy button appear. The invoice is the one bound by
the signed terms, so the wallet pays the hash whose preimage the browser
holds. From then on the wallet owns the routing fee and how long its payment
may stay pending: the browser's maximum HTLC expiry bound applies only to the
node path, while the provider still enforces the minimum earliest HTLC expiry
before locking. The page then listens for the provider's signed
`funding_binding` on its own (the funding button stays for a manual check
after the invoice expiry). Expiry alone never ends a swap as unpaid: a paid
invoice may still be held or funded. One invoice per swap; nothing is renewed.
Settlement for an external payment is reported by the wallet; the page verifies
the claim's confirmation and explains that the preimage it revealed settles the
Lightning payment.

`swap/browserHoldPayer.ts` implements exact-route LND planning
and one-shot dispatch for the Advanced node path. Construction never
connects. Planning independently checks the original signed invoice against
LND, pins the node/network, validates one full-amount route under absolute
expiry/fee limits, and sets its final MPP record. Dispatch refreshes node and
route-height checks on both sides of the durable authorization callback, then
submits once with `SendToRouteV2`. It tracks a bounded streamed status rather
than waiting for hold settlement. Errors remain UNKNOWN and never authorize
repayment. The in-memory one-use plan guard is not a cross-tab payment journal;
the execution controller supplies cross-tab durable payment authorization.

#### Reverse journals and node configuration

`browserReverseJournal.ts` stores encrypted snapshots for the explicit
`swap/reverseExecution.ts` controller. Fresh sessions retain separate secrets,
terms, payment-attempt, funded, and signed-claim snapshots. Funding never clears
the UNKNOWN payment attempt. Strict three-store transactions check predecessor
elections before writing, then verify committed readback. Payment elections
bind the full network, payer, and payment hash across sessions/tabs; claim
elections bind the full network/outpoint and immutable exact-byte digest.
There is one first exposure transition; UNKNOWN/accepted allow only identical
manual re-export after caller reauthentication, never another dispatch.

No database opens on load, no migration runs, and no missing marker proves
absence of prior execution. Partial/corrupted records or incompatible schemas
are preserved and refused. `createFresh` is not a recovery/import fallback.
Encrypted storage is not an external backup or authentication of its private
contents. The execution caller must authenticate snapshots, acknowledge backups,
check current approvals and chain evidence, and never restore payment authority
from an imported file. Browser storage eviction or deletion can defeat these
origin-local guarantees. Upgrade from previous releases initiates no work.

The optional disposable regtest node adapter on 8093 preserves upstream TLS
and scopes its baked macaroon to five RPCs. See `DEVELOPMENT.md` for explicit
provisioning, credential risks, and read-only validation. No public build
discovers it on load.
`VITE_RILLSWAP_NODE_API` admits one concrete node origin into the deployment CSP
and prefills its public endpoint. Public builds supply no node by default;
regtest defaults to loopback 8093. Custom nodes need browser-trusted TLS, CORS,
and scoped LND permissions. Never put a macaroon in build configuration.
Wildcard, credential-bearing, and non-regtest HTTP API URLs are refused.

#### Funded browser acceptance checks

For an opt-in real browser acceptance check, use a **separate disposable
Compose project** and the already-built development images. From the repository
root (these commands create only new fake-money wallets):

```sh
export COMPOSE_PROJECT_NAME="rill-reverse-browser-$RANDOM"
export RILL_DEV_WEB_PORT=15273 RILL_DEV_CHAIN_PORT=18091
export RILL_DEV_BROADCAST_PORT=18092 RILL_DEV_NODE_PORT=18093
export RILL_DEV_RELAY_PORT=17777
docker compose -f dev/compose.yaml up -d --no-build \
  tools maker-ln-to-btc chain broadcast user-node web
(cd rill-web && RILLSWAP_RUN_BROWSER_REVERSE_REGTEST=1 bun run test:regtest:reverse)
docker compose -f dev/compose.yaml down -v
```

The bidirectional stablecoin check runs against the ordinary development stack
(`dev/devctl up`): it spends dev fUSDC and regtest Lightning funds and needs no
manual mining. A fake EIP-1193 wallet forwards signing to Anvil's unlocked account 1.
It checks both live flows and explicit reverse recovery after reload.

```sh
(cd rill-web && RILLSWAP_RUN_BROWSER_ERC20_REGTEST=1 bunx playwright test --config playwright.regtest.config.ts regtest/erc20.spec.ts)
```

Do not reuse the default project or reset its wallets. No automatic miner is
started: the test explicitly mines only the funding and claim confirmations.
It verifies one exact-route payment, native unilateral four-item witness,
nominal payout, provider SETTLED, held invoice SETTLED, payer SUCCEEDED, and
read-only reload recovery with identical saved bytes and no renewed submission.
Fake-money encrypted backups and diagnostics remain under repository `tmp/`.
Ordinary CI runs the unit, disconnected browser, and Pages regressions; the
real-node check requires this explicit opt-in and isolated resources.

#### Reverse execution approvals

The reverse execution UI connects to a node only through the Advanced
node-connect action; the default path connects nowhere but the relays and the
configured chain API. The browser-stored recovery key is the approval
for a swap: no key-backup upload or acknowledgment checkbox gates acceptance,
claims, or preimage exposure; the consent text next to each action states what
continuing authorizes, and per-swap backups stay downloadable above the steps.
The payout address is only required, checked, and sent at continuation, not
for an estimate. On the node path, the route
and routing fee require a separate one-shot payment approval. The controller
binds the approved transport to the payer's immutable normalized endpoint.
Its initial private intent is encrypted before a firm request; native terms,
funding, and exact claim backups are saved separately before later actions.
Neither reload nor import restores acceptance or payment authority.

### Reverse recovery and claim construction

Explicit funded recovery also works without the original browser execution
history. `browserReverseRecovery.ts` authenticates the file, actual funding
transaction and fresh trusted-API observations, then reserves a **claim-only**
owner in the same global network/outpoint election as live execution. Its
encrypted funded predecessor is durable before private preparation and is
authenticated again on resumption, including after another tab wins a race.
There are no payment fields or fabricated payment routes. Prior exposure stays
UNKNOWN. Private interrupted preparation may be resumed explicitly; only one
exact encrypted fallback can win selection, and exposure UNKNOWN is committed
before any plaintext export or one-shot broadcast. Imported already-signed
fallbacks start UNKNOWN and cannot gain new broadcast authority.

Missing election metadata never overrides a retained owner. Explicit import
conservatively inspects at most 256 local records before creating a reservation;
more records or unrelated damaged records can block import rather than risk
replacing an existing claim. No startup scan, migration, eviction, or record
repair runs. An installation upgrading from the previous release keeps its
existing records intact; partial or incompatible state remains blocked.
Deleting all browser storage defeats origin-local elections: explicit recovery
still cannot prove a preimage was private or an earlier claim never existed.

Offline reverse recovery shares canonical admission, handshake/terms signatures,
purpose-key checks and Taproot reconstruction with forward inspection. It
requires the client's known preimage and provider-session-signed funding
history. `constructSelectedReverseClaim` authenticates selected raw funding
bytes and caller assertions of depth/height, then signs only the client claim
leaf with locktime zero and witness `[signature, preimage, script, control]`.
The resulting transaction is a preimage-disclosing capability, not permission
to export or broadcast. Callers must approve destination/fee before signing,
verify fresh unspent funding/chain evidence, and durably authorize exposure.
Saved bytes are reauthorized without re-signing.

`appendReverseClaimFallback` produces a native RS-007 successor from an already
funded predecessor, retaining funding and knowledge unchanged. Keep both
encrypted snapshots separately. Static inspection grants neither provenance,
chain inclusion nor disclosure authority. Missing fallback proves nothing
about prior exposure. No migration, storage repair or automatic recovery runs.

The browser refuses mining prepayment, cooperative reservation/disclosure
extensions in reverse records, and claim fees above the smaller of the signed
claim cap and reserve. It requires the quoted nominal payout to remain intact.
This last bound also applies to **historical fallback inspection**: an otherwise
native-valid saved fallback that spends more than its reserve remains preserved
but uninspectable here. Native recovery may accept it under its larger signed
fee cap. This conservative browser policy protects new quoted payouts but can
block higher-fee urgent historical claims; it is not full native acceptance
parity. Differential tests classify native construction independently from
browser results and separately validate funded/fallback successor ordering.

#### Funding mailbox recovery and unilateral negotiation

`restoreReverseFundingReader` restores only an authenticated funding mailbox
from the original client session secret and independently checked transcript.
It has no send/handshake/acknowledgment API and cannot renew payment authority.
`recoverReverseFundingEnvelopes` explicitly queries one to four selected relay
archives by original recipient and kind 1059, without outer-author or two-day
filters. Signed-session candidates still require independent binding-signature,
contract and raw funding transaction validation before persistence or spending.
Duplicate copies are discarded; failed, partial or truncated archives remain
visibly incomplete. Empty EOSE results prove neither no payment nor no funding.
If the provider never published its binding or relays no longer retain it,
recovery must remain blocked instead of repaying or inferring a signed binding
from a script-matching UTXO. Receiver disposal erases its private key copy;
immutable parsed strings and caller-owned keys cannot be guaranteed erased.

New browser reverse handshakes explicitly negotiate unilateral settlement:
cooperation is absent from both authenticated halves and their signed terms,
while required epoch binding is preserved. Forward cooperation remains
mandatory; a peer cannot introduce/drop a commitment in its reply or terms.
Providers still advertise cooperation and accept cooperative reverse clients.
Only the reverse profile is exempt from fresh mandatory-cooperation admission.
Historical signed sessions and stored provider policy are not rewritten,
and upgrades trigger no new negotiation, scan, funding, or payment. Unfeatured
reverse sessions gain no cooperative nonce/signing authority. This explicit
authenticated mode is not inferred from missing browser or provider metadata.

### Funding checks and refund actions

After local inspection, **Check funding** explicitly connects to the API
selected in Settings. It reopens and authenticates the selected file, checks
the chosen revision's real transaction bytes locally, then repeats confirmed
inclusion, block-hash, unspent-output, and stable tip/genesis observations.
HTTP errors, missing/spent outputs, malformed or inconsistent responses,
nonexistent output indexes, cancellation, and timeouts remain unavailable.
The total attempt has a 20-second ceiling (each tip check also has its own
10-second ceiling). There is no automatic retry, revision fallback, or polling.
Only Core's supported execution identities can be checked; unsupported
historical identities remain inspectable without making a connection.

Multiple retained revisions have an explicit selector, initially showing the
newest. A failed newest revision never silently switches to an older one.
Zero funding history exposes no chain check. Changing a file/key clears the
report; network/API Settings changes also clear completed observations and
invalidate pending results. A different file, key, or revision at completion
discards the result. A coherent immature observation displays a waiting state. The
result is labeled **trusted API observation**, and `refundMatureAtObservedTip`
means only that its reported tip is above the signed lock height. Agreement
does not prove a canonical chain, a global mempool view, destination ownership,
or permission to sign. A separate destination/fee approval is required to sign.

The selected API sees your IP and the public funding transaction/output,
which can reveal public addresses and amounts. It receives no keys, recovery
files, or invoices. This is explained in collapsed **Privacy & terms**.
Importing, page load, and Settings changes still make no connections.

`BrowserRefundJournal` stores immutable, public signed refund
intents in IndexedDB. Its states are `prepared`, `submission-unknown`, and
`accepted` (API acceptance is not confirmation). Strict transaction durability,
completion, and readback precede exposure. An atomic transition elects one
winner across tabs; failures never reset or replace intent. Unknown/accepted
records permit explicit identical-byte export, not another application POST.
These integrity checks do not replace recovery-file signature authorization.

Upgrading performs no startup action or migration. Explicit use may create an
absent store; absence proves nothing about previous external exposure. Partial
records or incompatible stores remain preserved and block the action. Storage
durability is not protection against eviction, deletion, or another browser.
Keep the original encrypted backups. Chromium fault/concurrency tests cover
the journal, not a universal browser durability guarantee.

#### Refund preparation and exposure

Review the fixed signed destination and prefilled total fee, confirm ownership,
then click **Approve and prepare refund**. The button is the approval: a consent
note states what it confirms, and no checkbox gates it (the same holds for the
Lightning to Bitcoin claim buttons). Preparation reopens/authenticates the
file and freshly checks mature, confirmed, unspent funding before signing.
Saved plans are loaded and reauthorized, never re-signed or replaced. Fee and
destination changes cannot replace an existing intent. No keys or plaintext
imports are persisted in the refund journal.

**Download signed transaction** rechecks a prepared plan and durably marks its
exposure before starting the download. Export disables application broadcast,
because someone else could already have broadcast those bytes. Unknown or
accepted plans still permit explicit identical-byte download after reloading.
**Broadcast refund** separately rechecks the prepared plan and wins an atomic
durable UNKNOWN transition before one POST of signed transaction hex. Exact
matching txid responses mark API acceptance, not chain confirmation. Response
loss, HTTP errors, cancellation, or storage uncertainty never reset intent or
authorize retry. Settings/approval changes across awaits block signing/exposure;
after durable exposure they preserve UNKNOWN rather than rolling it back.

The collapsed broadcast API setting defaults to the selected public explorer,
or the separate loopback regtest adapter on port 8092. The read-only regtest
adapter on 8091 remains read-only. Both deployment defaults are configurable
through `VITE_RILLSWAP_MEMPOOL_API` and `VITE_RILLSWAP_BROADCAST_API`; custom
origins need deployment CSP allowance. Browser POST availability/CORS depends
on the operator; unavailable transport still permits approved signed export.

#### Native CLI refund recovery

You need `rill-cli` (see its README), a synced Bitcoin Core node for the same
network, the funded recovery file, its age key, and the funding attempt ID that
the page printed (`attempt <ID> revision 0`). After the refund block shown by
the page, run (it waits for that block if started earlier):

For the default browser identity, download the optional
`rillswap-recovery.age-key` from the recovery details and pass it as
`--identity` below. The JSON mnemonic backup is not a native age identity
file. If you overrode the recipient, use that recipient's original private key.

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
refund pays the signed destination (your derived browser-wallet address or
the external override), never an arbitrary replacement. `rill recover sign-refund` with
`--output refund.tx` instead writes the signed transaction without sending it.
`--chain-only` means the refund relies on the contract alone: it is sent only
after the refund block while the provider has not claimed. If the invoice is
your own node's, use `--lnd-port`, `--lnd-tls-cert`, and
`--lnd-invoice-macaroon` instead so it also refuses once the invoice is paid.
`rill recover broadcast-refund` (one fixed `--fee-sat`, `--intent FILE`) sends
a single refund without escalation.

### Cooperative claims and nonce custody

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

### Privacy and browser security

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
never scans, repairs, or reuses old/partial databases automatically. Swap
records (for example `browserReverseJournal.ts` and the cooperation journal)
live in separate encrypted stores that this diagnostic never touches.
Absence of a database proves nothing about prior browser use or safe funding.

### Nostr transport and advertisement verification

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

#### Signed Nostr announcement verification

`src/nostrProviderAnnouncement.ts` verifies one RS-005 kind-39417 event for
mainnet, signet, testnet4 or regtest. Live discovery
(`src/swap/marketplace.ts`) and the manual-import panel both use it. It requires a separately
approved provider identity and complete network/profile, authenticates the
outer NIP-01 ID/signature and the nested application signature, and checks
exact ordered tags, address `d`, matching signer/timestamp, and size and
nesting bounds. The manual-import panel calls it only after explicit selection
of the NIP-01 paste format and a verification click; its default
application-signed import mode is unchanged. It does not subscribe to a relay
itself; the swap client's
`src/swap/relay.ts` caps each raw relay message at 128 KiB **before**
extracting the event-object bytes. It returns a historical signed candidate, not globally
current revision, endpoint approval, session ownership, or financial
authority. No new state is read or written during startup or upgrade.

### Recovery encryption and release limitations

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

### Development and integration tests

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
