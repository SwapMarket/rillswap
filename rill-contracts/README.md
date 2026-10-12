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
