# rill-contracts

Vendored EVM contract sources and their pinned compiled artifacts, shared by
the provider (`rill-provider`) and the browser client (`rill-web`) for the
RS-010 ERC20 profiles.

- `vendor/boltz-core/`: Boltz `ERC20Swap` v6 and its `TransferHelper`
  dependency, copied unmodified from boltz-core `v5.0.0`; see `NOTICE.md`
  for the commit, hashes, and licenses (`ERC20Swap.sol` is MIT,
  `TransferHelper.sol` is GPL-3.0-or-later).
- `artifacts/erc20-swap-v6.json`: ABI, creation bytecode, runtime bytecode,
  and `maskedRuntimeSha256` (runtime bytecode with the immutable EIP-712
  domain separator ranges zeroed, which is what verifiers compare against
  `eth_getCode`). Compiled with solc 0.8.33, optimizer enabled with
  10,000,000 runs, EVM version `cancun`, no metadata hash.

`bun run generate` rebuilds the artifact; `bun run check` fails when it is
stale (run in CI).

## Account abstraction (gas-sponsored claims)

Receiving stablecoins without a wallet extension needs an ERC-4337 EntryPoint
and an EIP-7702 delegate the browser can pin. These artifacts are canonical
CREATE2 deployments (Arachnid factory `0x4e59...956c`), so the dev chain and
public chains hold the same addresses and bytecode:

- `artifacts/entry-point-v0.7.json`: eth-infinitism EntryPoint v0.7.0 at
  `0x0000000071727De22E5E9d8BAf0edAc6f37da032`, the published npm artifact
  (`@account-abstraction/contracts@0.7.0`, GPL-3.0).
- `artifacts/execution-install-delegate.json` and `artifacts/sma7702.json`:
  Alchemy Modular Account v2 v1.1.0 `ExecutionInstallDelegate`
  (`0x0000000000008e6a39E03C7156e46b238C9E2036`) and `SemiModularAccount7702`
  (`0x77021100bD87b7008E5E1989d0eB38555d0d0000`), built from the pinned
  upstream commit with its `optimized-build` profile (GPL-3.0-or-later).

`./build-account-abstraction.sh` reproduces them (docker, curl, jq, git) and
fails unless the rebuilt `SemiModularAccount7702` initcode hash equals the
one in Alchemy's deployment record. Each artifact records its source,
license, CREATE2 salt, and constructor arguments.
