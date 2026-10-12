# RillSwap

RillSwap is a pre-release Bitcoin and Lightning swap implementation. Start with
[`BLUEPRINT.md`](BLUEPRINT.md) and [`TEST-MATRIX.md`](TEST-MATRIX.md). No component
is authorized for funded production use or mainnet deployment while the release
gates remain open.

This is one Git repository containing seven components:

| Directory | Role |
| --- | --- |
| `rill-docs/` | Protocol specifications and conformance tests |
| `rill-crypto/` | Native and browser cryptographic primitives |
| `rill-core/` | Wire types, contract construction, and settlement primitives |
| `rill-provider/` | Provider experiments and disposable backend diagnostics |
| `rill-cli/` | Offline recovery and experimental regtest actions |
| `rill-web/` | Browser preview and disconnected recovery container export |
| `rill-payments/` | Experimental checkout SDK, merchant ledger and shared policy |

For a complete local regtest environment (Core, LND, relay, makers for both
swap directions, the CLI, the browser swap page and a demo shop) in Docker
Compose, see
[`DEVELOPMENT.md`](DEVELOPMENT.md): `dev/devctl up`.

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
development dependencies; a separate provider job checks opt-in native
cryptographic interoperability, while Docker-backed LND and Core cases remain
out of hosted coverage. The web job builds
and runs unit and default Playwright Chromium tests, but does not run opt-in
native/Go age interoperability or exercise recovery durability. The Playwright
browser download is not an audited release artifact.
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

## License

RillSwap is MIT licensed (`LICENSE`; each component carries the same
license). Third-party files keep their own licenses and are marked where they
live: `rill-contracts/vendor/boltz-core/` (Boltz `ERC20Swap.sol`, MIT; Uniswap
`TransferHelper.sol`, GPL-3.0-or-later, which is compiled into
`rill-contracts/artifacts/erc20-swap-v6.json`), and the dev-stack account
abstraction artifacts `entry-point-v0.7.json` (GPL-3.0),
`execution-install-delegate.json` and `sma7702.json` (GPL-3.0-or-later). The
GPL text is in `rill-contracts/licenses/GPL-3.0.txt`; each of those artifacts
records its upstream source.
