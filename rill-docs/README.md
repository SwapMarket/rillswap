# RillSwap specifications

Normative protocol specifications, schemas, test vectors and network
definitions for RillSwap, plus the design document and release test matrix.

Status: pre-release. No specification here has been audited or approved for
funded mainnet use.

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

## Local conformance tests

Run the static specification and vector suite with `.venv/bin/pytest -q`.
`../.github/workflows/static-conformance.yml` defines a read-only, source-checkout
GitHub Actions job using Python 3.14, pinned actions and uv, hash-locked test
dependencies, and an explicit exclusion of the Docker-only Core marker. It
does not run the pinned Core integration case, publish artifacts, attest
provenance, or constitute a release gate.
The Bitcoin Core execution suite is opt-in because it starts a container and
mines a regtest chain:

```sh
RILLSWAP_RUN_BITCOIN_CORE=1 .venv/bin/pytest -q -m bitcoin_core
```

That test requires Docker and the pinned linux/amd64 image recorded in the
test. The image digest is immutable but the image publisher is unofficial.
RPC calls use `bitcoin-cli` through `docker exec`, so no daemon port is exposed
to the host. Bulk `generatetoaddress` calls have a bounded 180-second process
timeout (other RPC calls retain 30 seconds); a timed-out mining request is not
retried blindly because its regtest chain may already have advanced. The test
removes its disposable container on failure.
Wallet-selected funding transactions are intentionally dynamic; only the
versioned synthetic-outpoint vectors have stable transaction bytes.

`vectors/recovery/initial-btc-to-ln-v1.json` is a synthetic decoded-object
fixture for an initial plaintext export, assembled from signed
authentication/economics and independently
reconstructed Taproot vectors. It is unfunded (empty funding history), includes
public test-only secret material, and uses a decoded invoice-binding fixture,
not a verified BOLT11 invoice. The test verifies the published signatures and
schema. The file is pretty-printed for review; canonicalize it to UTF-8 JSON
before using it as age plaintext. It is not an encrypted age interoperability
test, durable export proof,
recovery importer, live funding evidence, or permission to sign or broadcast.
`vectors/recovery/initial-ln-to-btc-no-prepayment-v1.json` adds a distinct
signed, base-profile initial export with the user's required preimage. Its
synthetic decoded invoice amount is recalculated for zero mining prepayment;
it does not change or activate the existing optional-prepayment vectors.
