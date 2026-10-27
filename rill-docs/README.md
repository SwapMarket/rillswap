# RillSwap specifications

Normative protocol specifications, schemas, test vectors and network
definitions for RillSwap, plus the design document and release test matrix.

**Status:** no specification here is approved for funded mainnet use yet.

| Path | Contents |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Design overview: goals, decisions, state machines, security invariants, release gates |
| [`specs/`](specs/) | Normative specifications RS-000 to RS-010 and extensions |
| `schemas/` | JSON schemas for wire messages, advertisements and recovery files |
| `vectors/` | Byte-level test vectors |
| `networks/` | Versioned network identity definitions |
| [`compatibility/TEST-MATRIX.md`](compatibility/TEST-MATRIX.md) | End-to-end and security acceptance matrix |
| `proposals/` | BIP and NIP drafts (unassigned, not submitted) |
| [`SOURCES.md`](SOURCES.md) | External standards referenced by the specifications |

Interoperability is defined by the versioned `specs/`, `schemas/` and
`vectors/`. The proposal drafts summarize them for the BIP and NIP processes.

| Spec | Topic |
|---|---|
| [RS-000](specs/RS-000-scope-and-security.md) | Scope and security boundary |
| [RS-001](specs/RS-001-wire-and-types.md) | Wire format and types |
| [RS-002](specs/RS-002-taproot-contract.md) | Taproot contract |
| [RS-003](specs/RS-003-btc-to-ln.md) | BTC to Lightning profile |
| [RS-004](specs/RS-004-ln-to-btc.md) | Lightning to BTC profile |
| [RS-005](specs/RS-005-discovery.md) | Provider discovery |
| [RS-006](specs/RS-006-nostr-transport.md) | Encrypted Nostr transport |
| [RS-007](specs/RS-007-recovery.md) | Recovery files |
| [RS-008](specs/RS-008-backend-capabilities.md) | Backend capabilities |
| [RS-009](specs/RS-009-conformance.md) | Conformance |
| [RS-010](specs/RS-010-erc20-swaps.md) | ERC20 to and from Lightning |

## Tests

Run the static conformance suite from `rill-docs/` with Python 3.14:

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python --require-hashes -r requirements-dev.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -m 'not bitcoin_core'
```

The optional Bitcoin Core suite starts a disposable regtest container. It
needs Docker and the pinned linux/amd64 image recorded in the test:

```sh
RILLSWAP_RUN_BITCOIN_CORE=1 .venv/bin/python -m pytest -q -m bitcoin_core
```

## Fixture notes

- Synthetic-outpoint vectors have stable transaction bytes; wallet-selected
  funding transactions do not.
- The initial recovery fixtures are unfunded decoded objects with public
  test-only secrets. Their invoice-binding fixtures are not verified BOLT11
  invoices.
- Canonicalize recovery objects to UTF-8 JSON before using them as age
  plaintext. The fixtures never authorize signing or broadcasting.
- The base-profile LN to BTC fixture includes the user preimage and uses no
  mining prepayment.
