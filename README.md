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
