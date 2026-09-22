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
