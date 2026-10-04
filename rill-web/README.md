# rill-web

Independent strict TypeScript RillSwap client SDK and static browser UI.

All runtime assets are bundled locally. Localhost static serving is supported;
reliable `file://` operation is not promised.

Status: pre-release and not suitable for real funds.

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

- provider discovery on one relay (highest valid kind-39417 revision;
  equivocation or a flood of more than 256 events is refused), the RS-001
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

There is no chain backend in the browser. The user enters the current block
height; it sets the refund-height ceiling (`tip + max refund delay`) and the
recovery scan birthday, so a wrong height can only lengthen the user's own
lock or make offers fail. Keys exist only in the tab's memory. The terms
recovery file must be downloaded before accepting terms, and the funded one
before the funding binding is sent and before broadcast. If the provider does
not pay, refund with `rill recover watch-refund` on the funded recovery file
after the refund height; the browser does not refund. The only thing stored in the
browser is the cooperation journal below, which never grants anything, so an
upgrade or reload reads, migrates, or resumes nothing; an interrupted swap
continues only through the downloaded recovery file.

Cooperation never blocks the swap. The client cosigns only after it holds the
verified payment preimage, and BIP341 signatures commit the exact outpoint,
amount, and output, so a cosignature can only let the provider take the output
it is already owed. Without a chain backend the browser cannot check
confirmations or fee policy like the CLI does; it trusts the provider for
confirmation and fee liveness only. Any refusal, timeout, or missing browser
capability abandons cooperation and the provider claims with the preimage
instead, costing privacy only. Before allocating its nonce the client holds an
exclusive Web Lock and commits a create-only IndexedDB record (database
`rillswap-cooperation`, keyed by contract hash, holding the cooperation ID and
sighash, no secrets or preimage) with strict durability. An existing record
refuses; an absent one proves nothing. The secret nonce lives only inside one
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

`bun run test` checks the same built bytes at `/` and `/repository/` on
loopback. All runtime assets are local. Browser tests need a supported
Chromium environment; opening the source directly via `file://` is not a
supported execution mode.
