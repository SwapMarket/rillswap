# rill-cli

RillSwap command-line client, optional local watcher, static web server, and
independent recovery executable.

Status: pre-release and not suitable for real funds.

The first implemented commands are **offline recovery only**. `rill recover
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
of active recovery records, and independent unilateral recovery remain release
gates.

`rill recover inspect` decrypts an explicitly selected X25519 or age scrypt
file and prints only redacted offline metadata and what remains unproved.
Passphrase input requires a protected terminal prompt; without echo control it
fails closed, never accepts a passphrase argument, and never reads echoed
standard input. **Passphrase export is not implemented**: pyrage's dynamic
encryption work factor cannot be bounded before performing its scrypt KDF.
Scrypt inspection rejects `logN > 19` before invoking the KDF. A logN of 19
uses roughly 512 MiB plus implementation overhead. These resource limits may
exclude otherwise valid age files. No automatically initiated scans, provider
contact, signing, payment, funding, migration, or broadcasts are implemented.

The package declares dependencies on `rill-core`, `rill-crypto` and
`pyrage==1.4.0`, but release wheels do **not** bundle the native cryptographic
library; a missing or wrong library fails closed. Test-only keys and fixtures
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
