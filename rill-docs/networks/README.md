# Network definitions

These identities are generated from Bitcoin Core v30.0 chain parameters. The
`consensus_profile` values are RillSwap identifiers for the pinned Core policy,
not values exported by Bitcoin Core.

The included regtest identity belongs only to the authoritative RillSwap E2E
deployment. Every other regtest lab must select and persist a distinct
deployment namespace. Runtime regtest consensus overrides require a different
consensus profile and fixture.

The active implementation targets are default signet, testnet4, mainnet, and
namespaced regtest. The testnet3 definition remains for inspection of historical
records, not as an enabled live network. Custom signets are outside this rollout.

Offline contract support does not authorize funded operation. Mainnet funding
must remain disabled until explicit security and release acceptance, and public
test networks need end-to-end validation before being advertised as operational.
Backend checks must compare Core's chain and genesis, its `signet_challenge` on
signet, and LND's actual chain identity. The shared testnet3/testnet4 invoice
prefix alone is not sufficient network evidence. Missing or unknown evidence
must refuse new financial actions, not trigger scans or migrations.
Signet Core RPC must expose `signet_challenge` in `getblockchaininfo` (as in
Core v29 and v30); older backends without that evidence cannot fund or provide
trusted online recovery observations. Existing recovery records are unchanged.

Sources:

* <https://github.com/bitcoin/bitcoin/blob/v30.0/src/kernel/chainparams.cpp>
* <https://github.com/bitcoin/bitcoin/releases/tag/v30.0>
