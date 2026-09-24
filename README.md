# rill-web

Independent strict TypeScript RillSwap client SDK and static browser UI.

All runtime assets are bundled locally. Localhost static serving is supported;
reliable `file://` operation is not promised.

Status: pre-release and not suitable for real funds.

This is a **local-only development preview**, not a swap client. It bundles a
small strict TypeScript/Vite static shell with relative asset paths. Chain-mode
selection does not contact or verify a node; the provider-description field
renders only inert pasted text. There is no provider discovery, quote, contract
verification, wallet, signer, swap, watcher, recovery import, or payment UI.
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
`scripts/emit-nip59-test-wrap.ts` is test-only stdin/stdout glue for a pinned
provider interoperability test. It must never receive production secrets.

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
