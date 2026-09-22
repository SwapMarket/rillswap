# Network definitions

These identities are generated from Bitcoin Core v30.0 chain parameters. The
`consensus_profile` values are RillSwap identifiers for the pinned Core policy,
not values exported by Bitcoin Core.

The included regtest identity belongs only to the authoritative RillSwap E2E
deployment. Every other regtest lab must select and persist a distinct
deployment namespace. Runtime regtest consensus overrides require a different
consensus profile and fixture.

Sources:

* <https://github.com/bitcoin/bitcoin/blob/v30.0/src/kernel/chainparams.cpp>
* <https://github.com/bitcoin/bitcoin/releases/tag/v30.0>
