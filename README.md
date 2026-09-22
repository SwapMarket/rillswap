# rill-core

Pure Python RillSwap protocol domain plus separately installable adapters.

The core package performs no network, disk, clock, database, or notification
side effects. It validates messages and observations, reduces verified events,
and returns explicit permitted effects.

The settlement package reconstructs RS-002 Taproot contracts and builds,
finalizes, parses, and authorizes unilateral claim/refund transactions. BIP340
signing stays outside core behind explicit key-operation and verifier protocols.
Callers must supply authenticated contract terms, a correct key-operations
implementation, and independently observed live funding outpoint data. Core
authorization is not chain confirmation or current mempool acceptance.

Status: pre-release and not suitable for real funds.
