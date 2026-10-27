# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/rillswap/rillswap/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include the affected component, version or commit, network (regtest, signet,
testnet4, mainnet) and steps to reproduce. Never attach real secrets: redact private
keys, seeds, MuSig nonces, preimages, recovery backups, LND macaroons, wallet
credentials, invoices, payment hashes, addresses and transaction identifiers
unless they come from a disposable test environment.

## Scope

All components in this repository are in scope:

- `rill-docs`: protocol, contract and transport specifications
- `rill-crypto`: native and WASM cryptographic boundary
- `rill-core`: protocol validation and settlement primitives
- `rill-provider`: liquidity provider
- `rill-cli`: client and independent recovery tool
- `rill-web`: browser client
- `rill-payments`: merchant checkout SDK and services
- `rill-contracts`: pinned EVM contracts and artifacts

The `dev/` Docker environment uses public, disposable test keys by design and
must never be pointed at a real wallet or node.
