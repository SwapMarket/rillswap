# Vendored Boltz contracts

Source: https://github.com/BoltzExchange/boltz-core at tag `v5.0.0`, commit
`7612d67102ad370673c26be000ecc8804a5bec45` (2026-05-22). Files are copied
unmodified so that compiled bytecode can be compared against upstream
deployments.

| file | upstream path | sha256 | license |
| --- | --- | --- | --- |
| `contracts/ERC20Swap.sol` | `contracts/ERC20Swap.sol` | `efa11b0fdea551ece84f485d40035196825ec3c3e751b94f04318be4b2b99689` | MIT (repository `LICENSE`, Copyright 2024 Boltz) |
| `contracts/TransferHelper.sol` | `contracts/TransferHelper.sol` | `0f0e4cd25e1da2f703938ada2ab76c9f05cccfa66f6be8ffea00cf2658d7dcc0` | GPL-3.0-or-later (Copyright 2020 Uniswap team) |

`ERC20Swap.sol` declares contract `VERSION = 6` and imports only
`TransferHelper.sol`. Upstream compiles with solc 0.8.33, optimizer enabled
with 10,000,000 runs (`foundry.toml` release profile).
