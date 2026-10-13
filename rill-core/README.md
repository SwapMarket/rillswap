# rill-core

Pure Python protocol logic for RillSwap. It validates messages, reduces
verified events, inspects recovery records, and builds Bitcoin settlement
transactions. It does no network, disk, clock, database or notification IO.

**Status:** experimental and unaudited. Do not use with real funds.

## Install

Python 3.13 or newer. From `rill-core/`:

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -e ./packages/core
```

## Usage

The main API areas are `rill_core.wire`, `rill_core.domain`,
`rill_core.settlement` and `rill_core.recovery`. For example, to inspect raw
transaction bytes:

```python
from rill_core.settlement import inspect_transaction_outputs

def output_values(raw_transaction: bytes) -> tuple[int, ...]:
    report = inspect_transaction_outputs(raw_transaction)
    return tuple(output.value_sat for output in report.outputs)
```

Inspection reports facts about the bytes, not signature validity, ownership,
confirmations or spendability. Unsupported input raises `ValidationError`.

Hosts (the CLI, provider and browser) own authenticated inputs, durable
session state, chain observations and external actions. Claim transactions
built here can contain a preimage, so do not log them. See the
[specifications](../rill-docs/README.md) for protocol and security
requirements.

## Tests

From `rill-core/`:

```sh
uv pip install --python .venv/bin/python -r requirements-dev.txt
.venv/bin/ruff check packages/core/src tests
.venv/bin/mypy packages/core/src
.venv/bin/python -m pytest -q -m 'not native_crypto'
```

Native integration tests are opt-in. Build [rill-crypto](../rill-crypto/README.md)
first, then:

```sh
uv pip install --python .venv/bin/python -e ../rill-crypto/python
RILLSWAP_RUN_NATIVE_CRYPTO=1 \
RILL_CRYPTO_LIBRARY="$PWD/../rill-crypto/tmp/build/librill_crypto.so" \
.venv/bin/python -m pytest -q -m native_crypto
```
