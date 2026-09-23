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

The explicit `handshake_diagnostic.verify_handshake_diagnostic` uses the pinned
`rill-crypto` Python adapter and a caller-selected **absolute** native library
path to check the three RS-001 handshake envelopes using Core's strict static
verifier. Its caller supplies a trusted provider identity, complete network,
profile, and allowed feature/suite/capability sets independently of the peer's
documents. There is no library discovery fallback, startup loading, key
custody, transport, journal, or side effect. It returns only a transcript
digest. A recorded historical handshake passes again and **cannot** establish
a live session, local provider secret custody, freshness, received order,
payment authority, or permission to fund. Explicit operator installation of
the separately pinned native library is required, a native ABI load failure
is unavailable diagnostic evidence, and input errors are redacted. From a
sibling `rill-crypto` build and this virtual environment, run the opt-in
native interoperability check with:

```sh
RILLSWAP_RUN_NATIVE_CRYPTO=1 \
RILL_CRYPTO_LIBRARY=/absolute/path/to/pinned/librill_crypto.so \
  .venv/bin/pytest -q -m native_crypto --basetemp=tmp/pytest
```

Existing reservation and payment journals are neither opened nor migrated
by this diagnostic. Missing, partial, old, or restored session records prove
no historical safety and must not trigger reconstruction or an action.

The separate `core_tx_bytes.RegtestCoreTransactionReader` is an explicit,
read-only **regtest-only** Bitcoin Core v30 RPC probe. It takes a numeric
loopback address, port, owner-private Core cookie file, and a complete trusted
network identity. Construction and opening either existing ledger make no RPC
call. An explicit probe compares the configured identity to supplied contract
terms, checks Core's chain label and genesis hash, and fetches transaction
bytes by txid for the core static funding-binding byte check. A second explicit
`observe_candidate_outpoint` probe also samples chain-only `gettxout` evidence,
derives the reported inclusion height, fetches that height's block hash and
re-reads identical transaction bytes qualified by that block hash before the
final matching tip reading. It returns a **candidate** with sampled inclusion
fields at a named tip, not a serialized best-chain lineage entry. The RPC
sequence is non-atomic, can miss an ABA reorg, and does not check mempool
spends or establish action authority. It uses only
four read-only RPC methods (`getblockchaininfo`, `getblockhash`,
`getrawtransaction`, `gettxout`),
with no wallet route, redirects, environment proxy, automatic retry, or writes.
The deployment namespace and consensus profile are operator assertions, not
facts Core attests. Arbitrary old confirmed transactions need Core `-txindex=1`
already configured; this probe never enables indexing or initiates a reindex.
RPC errors, absent indexed transactions, timeouts, and partial/older local
state are **unavailable evidence**, never evidence of no funding. The result
does not authenticate the binding signature or wallet inputs, establish a
best-chain view, reserve funds, authorize funding, or close D07-D09. Existing
SQLite databases are neither modified nor migrated by this optional probe.
Its connect/read timeouts are inactivity limits, **not** a total deadline.
A malfunctioning or malicious configured listener can trickle headers and
block this synchronous call indefinitely. Do not integrate it into a daemon,
background polling, service handler, or time-critical action without a new
bounded transport contract and tests.
An opt-in integration check runs pinned Bitcoin Core v30 in an isolated Docker
network namespace with `-txindex=1` and a separate pinned Python test image:

```sh
RILLSWAP_RUN_BITCOIN_CORE=1 .venv/bin/pytest -q -m bitcoin_core --basetemp=tmp/pytest
```

It exercises real Core network preflight, confirmed transaction retrieval,
rejection of a mined coinbase as funding, sampled chain-only UTXO and
block-qualified transaction response,
and an unavailable txid. The UTXO transport test deliberately substitutes a
static checker after proving that the real checker rejects coinbase funding;
it does not claim a live signed binding. The fake
HTTP tests also pass a synthetic matching funding transaction through the
real core static checker. Neither test proves a live signed swap funding
workflow or complete backend reconciliation.

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

An **explicit outgoing-only LND observation diagnostic** is available as
`RegtestLndPaymentObserver.track(payment_hash)` in
`rill_provider.lnd_payment_observation`. It uses the vendored official LND
`v0.21.0-beta` protobuf definitions (source commit and hashes in
`proto/lnd-v0.21.0-beta/README.txt`), pinned Python gRPC runtime, a numeric
loopback endpoint, a locally configured TLS trust-root certificate with
hostname verification (not exact leaf-certificate pinning), and a protected
read-only macaroon. Operators must provision a narrowly restricted
`offchain:read` macaroon; this diagnostic cannot inspect its permissions;
never use an admin macaroon or expose it through CLI arguments, logs, or
backups. The observer uses only `TrackPaymentV2`, with one total gRPC deadline,
a 256 KiB response limit, 16-update limit, disabled gRPC RPC retries, and no
application reconnect loop. It returns only
typed payment-level and separately typed HTLC-attempt status/IDs. `INITIATED`
does not mean `IN_FLIGHT`, and LND's numeric HTLC attempt ID is **not** the
Rill journal's local attempt ID. No protobuf response, preimage, route, or
credential is returned or persisted. Missing history, not-found, timeout,
auth rejection, and interrupted tracking remain unknown, not proof of failure
or absence. The observer does not query backend identity or network consensus;
configured regtest identity is **not independently attested** by this method.
There is no startup call, journal mutation, submit, cancel, retry, invoice
lookup, payment reconciliation, or payment permission. Previous-release v1
journals remain untouched, including missing, partial, and restored states;
the observer cannot infer safety from absence. An opt-in pinned LND regtest
empty-wallet check exercises TLS, restricted `offchain:read` authorization,
raw `NOT_FOUND` for an unknown hash, and the observer's sanitized unknown
result. It does not exercise an initiated, failed, or settled real payment.
Actual payment-flow interoperability, multi-instance fencing, persisted
intent/backend correlation, and the L03/D01-D09 release gates remain open.

For developers, regenerate pinned messages (no generated payment-sending stub)
after installing `requirements-dev.txt` with
`.venv/bin/python scripts/generate_lnd_protos.py`. The pinned-source hashes
and exact generation-tool versions are checked. The focused fake transport
and real synthetic loopback gRPC TLS tests run in the normal pytest suite;
the synthetic tests alone are **not** a real LND regtest integration check.

To run the opt-in pinned **empty-wallet** check, keep `rill-core` and
`rill-provider` as sibling source checkouts. Install `requirements-dev.txt`
in this repository's local Python 3.14 `.venv` (including pinned
`grpcio-tools`), and have Docker capable of running the pinned `linux/amd64`
Core, LND, and Python images. From this repository:

```sh
RILLSWAP_RUN_LND=1 .venv/bin/pytest -q -m lnd --basetemp=tmp/pytest
```

The test creates uniquely named, run-labeled containers; Core has no network,
and LND and the test client share Core's loopback namespace without published
ports. It mounts the sibling source and local environment **read-only**, and
uses tmpfs for Core data, LND wallet/credentials, and the client credential.
The test-only wallet seed and admin macaroon are handled within the isolated
sidecar and are not printed. Tmpfs is not a guarantee against host swap or
crash dumps. No funds, blocks, channels, invoices, or payments are created.
Cleanup verifies each container's run label before removal and attempts every
container even if one cleanup step fails. If the runner is interrupted, check
for leftover `rillswap-lnd-*` containers with `docker ps -a`, then verify the
`org.rillswap.test-run` label and mounts using `docker inspect` on each exact
container. After confirming the associated runner is no longer active, use
`docker rm --force --volumes` only on those verified containers; do not delete
other test runs or any host wallet. A missing/older journal remains unknown
after this test, never a reason to send or retry.
