# Contributing

RillSwap is security-sensitive financial software. Start with a focused issue
or proposal, keep changes reviewable, and include tests or byte vectors for
normative behavior. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), not in public issues.

## Ground rules

- Contributions must be original or identify their source and a compatible
  license. Vendored or generated material records its origin.
- Never rewrite a published protocol version in place; protocol changes go
  through `rill-docs/specs/` with updated schemas and vectors.
- Add focused tests for every change. Money-path changes also need coverage
  against real nodes in the regtest environment (`dev/devctl up`, see
  [DEVELOPMENT.md](DEVELOPMENT.md)).
- Run `prek run --all-files` (or `pre-commit run --all-files`) and the checks
  of each component you touch. The per-component commands are in its README
  and in `.github/workflows/component-checks.yml`.

## Component rules

**rill-docs.** Normative behavior needs byte vectors. Keep specifications,
schemas and vectors versioned together.

**rill-crypto.** Changes to the cryptographic boundary require focused misuse
tests, upstream vector coverage and a review of key and nonce lifetimes. No
custom curve arithmetic, nonce generation or signature algorithms.

**rill-core.** Keep the domain core deterministic and free of network, disk,
database, clock and notification effects. Externally supplied values need
strict boundary validation. Preserve serialized forms and state transitions
unless a new protocol version changes them.

**rill-provider.** Preserve crash safety, idempotency, secret redaction,
reservation accounting and reconciliation after ambiguous external effects.
Network calls must not occur inside SQLite transactions.

**rill-cli.** Keep recovery usable without a provider, discovery service, old
browser origin or hosted RillSwap service. Never accept secrets as
command-line arguments. Preserve machine-readable output and exit codes.

**rill-web.** The TypeScript client is an independent implementation, not
generated Python logic. Keep runtime validation bounded, render provider text
as plain text, preserve explicit chain-trust and recovery behavior, and bundle
all runtime assets locally. `src/vendor/rill-crypto` holds the exact output of
`rill-crypto/scripts/test-wasm.sh`: after changing `rill-crypto`, rerun that
script, copy `tmp/wasm/rill_crypto_wasm.{mjs,wasm}` there and regenerate
`SHA256SUMS`. CI rebuilds the WASM and requires byte equality.
