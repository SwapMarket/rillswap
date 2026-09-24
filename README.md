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

`handshake_signing.session_reservation_for_init` constructs a public,
independently constrained binding from bounded inner initiation bytes. The
purpose-scoped `sign_handshake_accept` requires a separately held, currently
available session-key reference and configured provider identity, validates
offered/selected negotiation and signer identity, verifies the returned BIP340
signature, and returns only the identity signature on the **inner** acceptance.
It never admits a session, persists a pending record, sends an accept, or
authorizes funding/payment. The only implementation of the live
`HandshakeCustody` signing interface is an **explicitly test-only in-memory
fixture**: it cannot resume on restart and must never be deployed. Production
signing integration, pending intent/replay store, transport, ordering, and
effect fencing are still missing. Without an independently authoritative,
durably committed response, no acceptance may be sent. Upgrading from the
previous provider release does not create, migrate, or scan any session state;
absent, partial, old, or restored state grants no key allocation or action
authority.

`handshake_custody_offline.OfflineHandshakeCustody` is an optional, **offline
key-availability primitive**, deliberately not an implementation of the live
signing interface. Its protected age X25519 identity is an external operator
root, supplied explicitly at `create_new` and `open_existing` and backed up
separately. The API explicitly provisions a new identity and then a session
key for one complete `SessionReservation` in immutable X25519-encrypted files.
It returns public `IdentityRef`/`SessionKeyRef` values, which the operator must
pin outside the writable store. `open_existing` requires the previously pinned
custody ID and complete network; `require_identity_exact` and
`require_session_exact` only check that the expected key is locally available
and bound to the recorded public intent. These calls never allocate missing
keys. No API exposes the decrypted private scalars for signing, sends or
receives a handshake, opens the PREPARED SQLite registry, or grants session,
funding, payment, or recovery authority. Treat the protected identity and the
trusted local private directory **and its ancestors** as sensitive. The
implementation uses owner-private directories and files, `O_NOFOLLOW` on the
final component, create-only hard links, bounded ciphertext/plaintext, exact
readback, and file/directory fsync; it does not defend against an untrusted
ancestor-path writer, a compromised process, or stolen decryption credentials.
An interruption after publication has an **uncertain** result and must be
reconciled manually; never retry, replace, or regenerate based on absent,
partial, older, newer, or restored files. Even a valid restored encrypted copy
can omit later allocations and can pass every exact local check: age encryption
protects confidentiality and integrity, **not freshness or provenance**.
These files have never existed in earlier releases, so upgrading does not
create or migrate them and no startup path reads them. Independent non-rollback
admission ownership, protected production signing, and authenticated ordered
delivery remain required before this primitive can be connected to live swaps.

An explicit local cross-repository baseline gate lives at
`scripts/check_integration_lock.py`. Run from this repository with a trusted
Python 3.14 environment, `uv`, CMake, a C compiler, and network access to
the pinned upstream native source and Python dependency index:

```sh
.venv/bin/python scripts/check_integration_lock.py --source-root .. --verify-only
.venv/bin/python scripts/check_integration_lock.py --source-root ..
```

`integration-lock.json` records **six exact Git commits and trees**, two
independently compared Python producer-wheel SHA-256 digests, and an exact
23-case provider native-test inventory. Missing, partial, unsupported,
unavailable, or changed source refs refuse execution. The runner reads the
explicit local repositories only as immutable Git object sources; it builds
the pinned crypto/core and provider wheels from isolated archives, compiles
and tests the pinned native library, installs **non-editable wheels** into a
new disposable venv, and requires every native provider case to execute
without skips or failures. It prints the actual consumed artifact digests as
a local run receipt; the native shared-library and provider-wheel digests are
**recorded, not independently release-pinned**, and the Python dependency
packages use version pins rather than verified hashes. The snapshot pins the
provider commit immediately **before** this runner was added: a file committed
inside the provider repo cannot contain its own resulting commit ID. This
baseline checks that historical provider behavior integrates with these exact
producers, not the working tree or later provider commits. Review and update
the snapshot deliberately before any future release. No hosted CI is claimed
without immutable, retrievable remote artifacts and appropriate host setup;
local success is not a release or live-swap authorization.

`handshake_store.PreparedHandshakeStore` is a separate **offline-only**,
explicitly bootstrapped SQLite PREPARED registry. It can record a canonical
RS-001 initiation and acceptance pair, a validated provider identity signature
on the inner acceptance, and a **public** custody reference in one committed
transaction. Both outer handshake envelopes are unsigned. It neither receives
or authenticates a live client, provisions a secret, signs, publishes, admits a
session, nor enables retry/send/payment. It requires a trusted local directory
and native signature verifier chosen by the caller. A result retrieved from
the local store is not freshly authenticated: its versioned checksum detects
accidental changes, not database writers who can recompute it, missing rows in
a restored snapshot, or changes on other replicas. A PREPARED row proves only
that this copy recorded those bytes, not key availability or delivery. An
UNKNOWN lookup is **not** proof of an unused session. Previous-release
installations have no such store and remain unchanged: creation requires an
explicit call, and opening absent, partial, older, newer, foreign, or corrupt
state fails closed without migration or replacement. A locally valid restored
copy can omit later prepared entries; no local marker can fence rollback or
establish globally exclusive acceptance. Any future sender requires durable
production custody, authoritative non-rollback writer fencing, inbox/outbox
ordering, transport authentication, and independent recovery handling for
already-funded or inflight sessions. No code calls this registry at startup.

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
