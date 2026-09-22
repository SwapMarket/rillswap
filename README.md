# rill-provider

RillSwap provider policy, treasury management, persistence, reconciliation,
watching, and the authoritative cross-repository integration harness.

Status: pre-release and not suitable for real funds.

The provider's first implementation is an append-only SQLite reservation
ledger. Its explicit `create` operation refuses existing files and remains
unreconciled; `open_existing` never creates or migrates a database. A recorded
reservation atomically covers one complete, immutable, single-cluster input
set. SQLite WAL, synchronous FULL, and a network-bound schema protect local
bookkeeping across ordinary process restarts, subject to SQLite, filesystem,
storage hardware, and backup handling. A missing row or restored snapshot does
not prove a coin is available. The ledger has no coin-selection permission,
release, Core RPC, or funding-ready flag. Funding must remain disabled until a
future wallet/chain and outstanding-intent reconciliation procedure exists.
Deployments sharing treasury coins need coordinated ownership, not just
separate ledgers or application-level network namespaces.

For development alongside the sibling `rill-core` checkout (Python 3.13 or
later, matching its current supported version):

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
mkdir -p tmp
.venv/bin/pytest -q --basetemp=tmp/pytest
.venv/bin/mypy src
.venv/bin/ruff check src tests
```

No provider network service or release-safe funding workflow exists yet.

The separate `payment_journal` records immutable BTC-to-LN outgoing payment
requests and append-only backend-reported observations. Its database is bound
to an exact network and backend, must be created explicitly, and never
authorizes payment submission or retry. Missing results, reported failure,
contradictory statuses, and missing rows after a database restore remain
ambiguous until the real backend is reconciled. Opaque route bytes are stored
with a serialization identifier but are not validated by this journal; a
future pinned LND adapter must validate the route and limits before sending.
Route bytes are sensitive payment metadata and must not contain credentials or
signing secrets. Observations store only a caller-supplied SHA-256 digest of
backend response evidence, not raw responses, credentials, or preimages; the
journal does not verify the digest's provenance. Keep any secret-bearing
backend data in a separately specified encrypted store.
Separate journals cannot coordinate submissions to one shared backend; no
multi-instance fencing or backend attempt correlation has been implemented.
There is no RPC or automated reconciliation in this increment, so crash and
restart storage tests do not complete the D01, D02, or D09 release gates.
