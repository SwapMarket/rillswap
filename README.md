# rill-core

Pure Python RillSwap protocol domain plus separately installable adapters.

The core package performs no network, disk, clock, database, or notification
side effects. It validates messages and observations, reduces verified events,
and returns explicit permitted effects.

The settlement package reconstructs RS-002 Taproot contracts and builds,
finalizes, parses, and authorizes unilateral claim/refund transactions. BIP340
signing stays outside core behind explicit key-operation and verifier protocols.
Callers must supply authenticated contract terms, a correct key-operations
implementation, and independently observed live funding outpoint data. Core
authorization is not chain confirmation or current mempool acceptance.

Funding-plan authorization compares version-two raw transaction bytes to an
exact local wallet plan: declared native witness inputs, one common lineage
anchor, the unchanged contract output, exact approved other outputs, and the
signed funding fee cap. It also accepts canonical unsigned or witness-bearing
serialization. The plan's prevout values and scripts are declarations, not
UTXO evidence; witness presence is not signature validity. A funding-plan
match must never be treated as authorization to pay, reveal a preimage, or
claim another deposit. Replacement lineage and extra-deposit reconciliation
require separately verified, durable observations.

`domain.funding_lineage` records accepted binding revisions separately from
reversible best-chain observations. It only accepts facts already authenticated
and independently checked by a host against live transactions and the current
chain view. A previously accepted revision may win on-chain even after a later
replacement was signed. Reorg invalidation removes the exact chain observation,
not the binding history. No reducer state permits funding, payment, settlement,
or recovery import by itself: storage, export verification, and any restored
state must be validated by separate boundaries. Missing or partial history
must not trigger an automatic rescan or reconstruct chain confirmation.

Run local tests with `.venv/bin/pytest -q`. For the native crypto contract test,
install the sibling `rill-crypto/python` package in the test environment, build
its pinned native library, and run:

```sh
RILLSWAP_RUN_NATIVE_CRYPTO=1 \
RILL_CRYPTO_LIBRARY="$PWD/../rill-crypto/tmp/build/librill_crypto.so.0.1.0" \
.venv/bin/pytest -q -m native_crypto
```

The native test is skipped by default and fails rather than skipping when
explicitly enabled without the library or Python binding. Its fixture keys
and deterministic signing randomness are public test data, never funds keys.

Status: pre-release and not suitable for real funds.
