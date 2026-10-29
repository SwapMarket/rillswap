# References

RillSwap specifications cite external standards by name. The main ones are:

| Area | Standards |
|---|---|
| Bitcoin | BIP 65 (`OP_CHECKLOCKTIMEVERIFY`), BIP 327 (MuSig2), BIP 340 (Schnorr signatures), BIP 341 (Taproot), BIP 342 (Tapscript), BIP 3 (BIP process) |
| Lightning | BOLT 11 (invoices), LND gRPC API (hold invoices, payment tracking) |
| Nostr | NIP-01 (events), NIP-44 v2 (encryption), NIP-59 (gift wrap) |
| Recovery files | age v1 file format |
| EVM | ERC-20, EIP-712, EIP-7702, ERC-4337 (EntryPoint v0.7), Boltz `ERC20Swap` v6 |
| Cryptography library | `bitcoin-core/secp256k1` (Schnorr, extrakeys and MuSig2 modules) |
| Security advisories | [LND advisories](https://security.lightning.engineering/), [Bitcoin Core advisories](https://bitcoincore.org/en/security-advisories/), BOLT 11 single-field clarification ([lightning/bolts#1357](https://github.com/lightning/bolts/pull/1357)); see [`ATTACKS.md`](ATTACKS.md) |
