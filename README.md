# rill-cli

RillSwap command-line client, optional local watcher, static web server, and
independent recovery executable.

Status: pre-release and not suitable for real funds.

`rill recover observe-funding` is a **read-only, explicitly requested regtest
diagnostic**, not a refund transaction or an automatic watcher. It requires a
complete independently trusted network JSON file, protected age X25519
identity or passphrase prompt, pinned native crypto library, exact signed
`--funding-attempt-id` and `--binding-revision`, a local Core cookie and RPC
port, and an explicit encrypted recovery snapshot path. Example (test-only):

```sh
rill recover observe-funding \
  --network trusted-regtest-network.json \
  --crypto-library /absolute/path/to/pinned/librill_crypto.so \
  --identity /protected/age-identity \
  --funding-attempt-id EXACT_64_LOWERCASE_HEX \
  --binding-revision 0 \
  --rpc-cookie /protected/regtest/.cookie \
  --rpc-port 18443 \
  /path/to/selected-recovery.age
```

The selected file is decrypted and **all** recorded signed funding history is
checked before any Core RPC. Only a numeric loopback address (default
`127.0.0.1`) is accepted. The RPC client checks Core's regtest label and
genesis, the chain-only UTXO sample (`gettxout` with mempool excluded), exact
value and script, block-qualified transaction bytes against Core's funding
transaction matcher, and sampled tip/lookup-block consistency. No `txindex`,
wallet RPC, automatic scan, broadcast, or state update is required. Missing,
spent, unconfirmed, stale, partial, older, or restored evidence cannot prove
absence or latest funding, and a mempool spend can coexist with a chain-only
sample. The JSON result labels the transaction lookup block separately from
the sampled inclusion height and explicitly reports **no authority**. A
rapidly changing chain and a later tip can stale a successful observation;
the RPC listener is trusted by the operator, not cryptographically
authenticated by loopback Basic auth. Read timeouts are inactivity limits,
not a transaction deadline. Do not use this output to sign, fund, pay, or
claim refund eligibility. Real regtest byte-matching for both swap profiles
is opt-in with `RILLSWAP_RUN_BITCOIN_CORE=1 .venv/bin/pytest -q -m bitcoin_core`
and requires the locally built sibling native library plus pinned Docker
images. Neither test uses funds outside disposable regtest.

`rill recover sign-refund` constructs a **BTC-to-LN client refund only** for
one explicitly selected signed funding binding, on disposable regtest. It
accepts the same network, identity, native library, exact attempt/revision,
cookie, RPC port, and encrypted file arguments as `observe-funding`, plus
`--fee-sat` (an exact integer constrained by signed refund terms) and
`--output` (a new file in a **trusted local directory**). For example:

```sh
rill recover sign-refund \
  --network trusted-regtest-network.json \
  --crypto-library /absolute/path/to/pinned/librill_crypto.so \
  --identity /protected/age-identity \
  --funding-attempt-id EXACT_64_LOWERCASE_HEX \
  --binding-revision 0 \
  --rpc-cookie /protected/regtest/.cookie \
  --rpc-port 18443 --fee-sat 500 \
  --output /trusted/private/new-refund.raw \
  /path/to/selected-recovery.age
```

The complete selected encrypted record is validated before Core RPC, then
revalidated inside the secret-confined signer. The selected output is sampled
both chain-only and with mempool spends included, matched against the funding
transaction bytes, and checked at a sampled tip strictly after the signed
refund lock height. The signed refund is verified from the private, fsynced
temporary file before create-only publication, with no overwrite, wallet RPC,
network broadcast, or state update. **The output is not proof of complete or
current funding, payment failure, absence of competing bindings, safe
broadcast, or ongoing spendability.** A rapid reorganization, unobserved
mempool activity, restored/older snapshots, and later spending can invalidate
the sampled evidence. Recheck independently and reconcile every relevant
outpoint before contemplating manual broadcast. An LN-to-BTC user does not own
the refund key and must use a separate claim flow (not implemented). The local
directory must not be writable by untrusted actors; this tool is not a
hostile-directory or ancestor-symlink defense. An interrupted publication may
leave an artifact without a success report (exit 3 if detected), which requires
manual inspection and **no automatic retry**. Python does not guarantee
erasure of private key material from memory. The opt-in pinned Core test mines
to height T+1, checks `testmempoolaccept` without broadcasting, and never
uses funds outside disposable regtest.

`rill recover broadcast-refund` is a **separate, explicit, regtest-only
submission** of a BTC-to-LN client refund, not a retry of `sign-refund` and
not a production recovery workflow. Supply the same independent trusted
network, protected age identity, native library, exact attempt and revision,
Core cookie/loopback port, encrypted snapshot, and `--fee-sat` as
`sign-refund`, plus a **new** `--intent /trusted/private/new-intent.json`
instead of `--output`. The command revalidates the full signed snapshot and
exact outpoint, signs and validates only that refund, then durably creates and
reads back a private, canonical intent containing the exact transaction bytes,
txid, byte hash, network, selection, fee, and sampled tip. The intent is
marked `submission_may_occur` **before** the first send attempt. Publication
uncertainty (exit 3) prevents sending. It samples Core again, requires exact
`testmempoolaccept` on those bytes, and calls `sendrawtransaction` at most once
per invocation. A valid returned txid is reported as `node_accepted`, never
as confirmed, final, paid, or swap-recovered. A lost/malformed response after
the send begins returns **unknown** (exit 4) without an automatic retry.
Existing intent paths are never overwritten or automatically resumed; the
operator must reconcile exact txid, mempool, selected chain, conflicts, and
LN state before any separate manual action. Even a `node_accepted` response
can become stale or compete with a claim; `testmempoolaccept` is not a chain
reservation. The intent directory must be operator-trusted, fsync-capable
local storage. Partial or restored recovery files prove neither nonpayment
nor complete funding lineage. **Do not use this regtest-only command with
real funds or treat it as a production-ready refund broadcaster.** The
opt-in pinned Core test submits once, verifies mempool entry, mines the refund,
and checks exact block-qualified transaction bytes on disposable regtest.

The export, export-update, and inspect commands are **offline only**. `rill recover
export` explicitly creates a new binary age v1 X25519 file from canonical
RS-007 plaintext supplied on standard input. It requires one public age
recipient, a matching private age identity file, a separately trusted complete
Bitcoin network JSON file, and an explicitly selected native `rill-crypto`
library. The recipient secret is needed because export decrypts the stored
ciphertext and checks the exact plaintext and signed contract before reporting
success. The secret file must be regular, not a symlink, and accessible only to
its owner (`0600`). Export never overwrites an existing file (including a
symlink), makes no plaintext temporary file, and never sets a funding-ready
marker. It does not overwrite an existing recovery export after funding or RBF.

`rill recover export-update --previous OLD.age --output NEW.age` is an
explicit, **create-only successor snapshot**, not replacement-in-place.
It accepts new canonical RS-007 plaintext on standard input, decrypts and
validates the explicitly supplied prior X25519 age file using the same
protected identity, asks `rill-core` to check pairwise monotonic knowledge,
then publishes a separate verified age file under the existing no-clobber
durability protocol. It refuses absent, corrupt, partial, unsupported-format,
or symlinked prior files; an existing output path, including the prior path,
is never overwritten. No auto-discovery, migration, scan, or funding action
occurs. A valid older/restored prior snapshot remains eligible; an unselected
sibling may hold knowledge missing from the created successor. **Success proves
only a relationship between the two selected snapshots, not freshness,
authoritative client reconciliation,
or a safe RBF workflow.** Interrupted publication is still uncertain (exit 3)
and requires manual reconciliation. Client-state durability, atomic update
of active recovery records, and production-safe independent unilateral
recovery remain release gates.

`rill recover inspect` decrypts an explicitly selected X25519 or age scrypt
file and prints only redacted offline metadata and what remains unproved.
Passphrase input requires a protected terminal prompt; without echo control it
fails closed, never accepts a passphrase argument, and never reads echoed
standard input. **Passphrase export is not implemented**: pyrage's dynamic
encryption work factor cannot be bounded before performing its scrypt KDF.
Scrypt inspection rejects `logN > 19` before invoking the KDF. A logN of 19
uses roughly 512 MiB plus implementation overhead. These resource limits may
exclude otherwise valid age files. No automatically initiated scans, provider
contact, payment, funding, migration, or broadcasts are implemented by these
offline commands. The separate `sign-refund` command signs only after its
explicitly requested regtest checks.

The package declares dependencies on `rill-core`, `rill-crypto`,
`pyrage==1.4.0`, and `httpx==0.28.1`, but release wheels do **not** bundle the
native cryptographic library; a missing or wrong library fails closed. Test-only keys and fixtures
in `tests/fixtures` are public. To develop alongside the sibling repositories:

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
mkdir -p tmp
.venv/bin/pytest -q --basetemp=tmp/pytest
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

Set `RILL_CRYPTO_LIBRARY` to the pinned local `librill_crypto.so` to enable
native inspection tests. Optionally set `AGE_BINARY` to the Go `age` v1.3.1
binary for two-direction independent X25519 interoperability tests. The CLI
itself requires `--crypto-library` explicitly. Its `export`, `export-update`, and `inspect`
subcommands require `--network`; run `rill recover --help` for their exact
arguments. The pretty-printed JSON fixtures are decoded objects, **not**
canonical age plaintext. If export exits with code 3, the destination may
already exist but its directory durability could not be confirmed: inspect
and reconcile it manually, never retry or fund automatically. An absent path,
absent metadata, or restored older file proves nothing about previous exports.
The library-only `age_container.inspect_container_selected_funding_binding`
can explicitly decrypt and statically validate a recovery file, then project
one public funding binding by exact attempt ID and revision. This is not yet
a CLI command, selected-chain observation, wallet import, or signing path.
An older/restored file may omit later revisions; no latest or unspent binding
is inferred. Invalid and absent records return redacted errors.
The parallel `inspect_container_selected_funding_context` returns only public
validated terms alongside that exact candidate for future independent
transaction-byte checking; it does not grant authority or expose designated
recovery secrets. Signed public terms can include arbitrary extension values,
so do not log the returned object.

For a **fail-closed local backup interoperability gate** on Linux amd64,
download the official Go age v1.3.1 archive from
`https://github.com/FiloSottile/age/releases/download/v1.3.1/age-v1.3.1-linux-amd64.tar.gz`
into this repository's `tmp/` directory. The committed gate verifies its
SHA-256 `bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377`
before extracting or executing `age/age`. Separately build the pinned sibling
`rill-crypto` library and independently record its SHA-256. With the local
Python 3.14 `.venv` and both sibling checkouts installed:

```sh
.venv/bin/python scripts/check_age_interop.py \
  --age-archive "$PWD/tmp/age-v1.3.1-linux-amd64.tar.gz" \
  --native-library "$PWD/../rill-crypto/tmp/build/librill_crypto.so" \
  --native-sha256 YOUR_INDEPENDENTLY_RECORDED_LIBRARY_SHA256
```

The gate refuses a wrong archive digest/version, missing sibling source,
library digest mismatch, a skipped test, or fewer than three passing checks.
It uses a fresh private test directory rather than deleting an existing
scratch path, and requires a structured report with exactly the three intended
cases. Inherited pytest plugins, assertion mode, and Python optimization
settings cannot silently turn this check into a skipped or assertion-free run.
It exercises Python-to-Go and Go-to-Python age X25519 in both profiles plus
the separately generated Go scrypt fixture with native inspection. It records
each component source revision and whether its worktree is dirty; a caller-
supplied native hash identifies tested bytes but does not attest binary origin.
This is **local verification only**. There are no repository remotes or hosted
CI workflows configured yet, so required CI enforcement and independent
reproducible artifact provenance remain open release gates. None of these
checks permits refund signing, broadcast, funding, or payment.
