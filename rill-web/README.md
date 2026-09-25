# rill-web

Independent strict TypeScript RillSwap client SDK and static browser UI.

All runtime assets are bundled locally. Localhost static serving is supported;
reliable `file://` operation is not promised.

Status: pre-release and not suitable for real funds.

This is a **local-only development preview**, not a swap client. It bundles a
strict TypeScript/Vite static shell with relative asset paths. Chain-mode
selection does not contact or verify a node; the provider-description field
renders only inert pasted text. The manual signed-advertisement panel verifies
either canonical PUBLIC application metadata or, when explicitly selected, a
PUBLIC raw private-regtest signed NIP-01 event object against an independently
entered identity and locally defined network/profile. It holds a revision maximum in memory
for this tab only. Endpoints remain inert plain text, not approved connections.
There is no relay discovery, quote, contract verification, wallet, signer,
swap, watcher, recovery import, or payment UI.
No financial action exists even if a diagnostic succeeds. Never enter secrets
or send funds to this preview.

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
no swap database, encrypted-record format, per-swap lock, or auto-migration to
claim. A future release must establish those together before any commitment.
Absence of a database proves nothing about prior browser use or safe funding.

`src/nip59Transport.ts` is an **unused, disconnected private-regtest producer**,
not a browser feature or relay publisher. Given an already application-validated
canonical RS-001 envelope, a caller-owned ephemeral session secret, and an
independently selected recipient mailbox key, it constructs a NIP-59 gift wrap
using pinned `nostr-tools`. It checks the canonical JSON bytes, envelope sender
key, experimental binding, outer signature/recipient, and size cap. It does
**not** validate the complete RS-001 schema/signature/transcript, choose or
persist any key, contact a relay, establish session authority, or enable funds.
The browser preview does not import or call it. Additional transport padding
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
is unchanged. It does not subscribe to a relay. A future relay caller
must also cap the entire raw `EVENT` message to 128 KiB **before** extracting
the event-object bytes. It returns a historical signed candidate, not globally
current revision, endpoint approval, session ownership, or financial
authority. No new state is read or written during startup or upgrade.

`src/recoveryAgeContainer.ts` is a third **unused, disconnected** boundary.
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
CLI native offline inspection; missing native/Go prerequisites fail that
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

`bun run test` checks the same built bytes at `/` and `/repository/` on
loopback. All runtime assets are local. Browser tests need a supported
Chromium environment; opening the source directly via `file://` is not a
supported execution mode.
