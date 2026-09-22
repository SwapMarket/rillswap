# RillSwap specifications

Normative protocol specifications, schemas, vectors, network definitions,
security analysis, and operational guides for RillSwap.

Status: pre-release engineering work. No specification here has been audited
or approved for funded mainnet use.

The proposal drafts in `proposals/` are preserved inputs. Interoperability is
defined by the versioned `specs/`, `schemas/`, and `vectors/` artifacts.

## Local conformance tests

Run the static specification and vector suite with `.venv/bin/pytest -q`.
The Bitcoin Core execution suite is opt-in because it starts a container and
mines a regtest chain:

```sh
RILLSWAP_RUN_BITCOIN_CORE=1 .venv/bin/pytest -q -m bitcoin_core
```

That test requires Docker and the pinned linux/amd64 image recorded in the
test. The image digest is immutable but the image publisher is unofficial.
RPC calls use `bitcoin-cli` through `docker exec`, so no daemon port is exposed
to the host.
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
