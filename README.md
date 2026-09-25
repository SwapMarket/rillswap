# RillSwap

RillSwap is a pre-release Bitcoin and Lightning swap implementation. Start with
[`BLUEPRINT.md`](BLUEPRINT.md) and [`TEST-MATRIX.md`](TEST-MATRIX.md). No component
is authorized for funded production use or mainnet deployment while the release
gates remain open.

This is one Git repository containing six components:

| Directory | Role |
| --- | --- |
| `rill-docs/` | Protocol specifications and conformance tests |
| `rill-crypto/` | Native and browser cryptographic primitives |
| `rill-core/` | Wire types, contract construction, and settlement primitives |
| `rill-provider/` | Provider experiments and disposable backend diagnostics |
| `rill-cli/` | Offline recovery and experimental regtest actions |
| `rill-web/` | Browser preview and disconnected recovery container export |

Each component retains its own dependency lock, local development setup, and
README. The pinned provider integration lock is a **historical** snapshot, not
conformance evidence for later components. The default tests do not exercise
the opt-in funded regtest channel and held-payment diagnostics or complete
either swap profile. The held-payment fixture also demonstrates that the
read-only provider invoice observer currently refuses ordinary pinned LND
custom-record evidence; it is not a funding-eligibility test.

The root `.github/workflows/` directory defines source-only specification and
component checks. The crypto job downloads checksum-pinned native source and
uses a digest-pinned Emscripten container; it is not an independent audit.
Provider and CLI jobs use version-pinned but **not hash-locked** Python
development dependencies and exclude opt-in backend cases. The web job builds
and runs unit tests but does not run Playwright or exercise recovery durability.
These jobs do not run funded backend trials or establish release provenance;
their hosted execution has not been verified in this workspace.

To replay that historical provider v2 baseline without nested repositories,
use Python 3.14 with the provider's pinned development dependencies, Bun
1.3.11, uv, CMake, and the documented network access:

```sh
rill-provider/.venv/bin/python scripts/replay_provider_v2.py --source-root . --verify-only
rill-provider/.venv/bin/python scripts/replay_provider_v2.py --source-root .
```

The wrapper verifies the unchanged v2 lock and its original runner, then uses
disposable Git views of the pinned component commits. This tests the historical
baseline only, not the current source tree or a production authority. It does
not fetch unavailable history, restore a journal, or trigger any swap action.

Work within a component's directory to run its documented checks. Docker
diagnostics use disposable regtest wallets and must never be pointed at a real
installation. Git history for each former component repository is retained as
ancestors of the monorepo import commits, even though old commits use their
original component-relative paths.
