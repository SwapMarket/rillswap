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
