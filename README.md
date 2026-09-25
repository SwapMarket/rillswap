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
the opt-in funded regtest channel diagnostic or complete either swap profile.

Work within a component's directory to run its documented checks. Docker
diagnostics use disposable regtest wallets and must never be pointed at a real
installation. Git history for each former component repository is retained as
ancestors of the monorepo import commits, even though old commits use their
original component-relative paths.
