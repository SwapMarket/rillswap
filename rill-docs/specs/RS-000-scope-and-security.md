# RS-000: Scope and security

Status: draft

Version: `0.1.0-pre.1`

## 1. Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are interpreted as described
by BCP 14 when they appear in uppercase.

An implementation conforms only to a named protocol version, profile, network
identity, and capability set. Passing schema validation alone is insufficient.

## 2. Scope

Version 1 defines two Bitcoin and Lightning swap profiles:

* `btc-to-ln/v1`, confirmed P2TR funding followed by a BOLT11 payment;
* `ln-to-btc/v1`, accepted hold-invoice HTLCs followed by confirmed P2TR
  funding.

Both profiles use the contract in RS-002. Script-path claim and refund are the
required settlement paths. Cooperative key-path claim is an optional privacy
optimization and MUST NOT be required for recovery.

Version 1 excludes P2WSH contracts, BOLT12, AMP, keysend, PTLCs, additional
assets, batching, and early cooperative refunds. A BTC to LN provider MAY
announce zero funding confirmations; it then bears the double-spend risk
alone (RS-003). LN to BTC terms sign at least one funding confirmation; a
client MAY explicitly claim at a lower depth and then bears the double-spend
risk alone (RS-004).
Asset extensions, such as the ERC20 profiles in RS-010, define their own
profiles outside the base protocol.

## 3. Security boundary

The protocol protects principal only under its stated assumptions. It does not
guarantee availability, routing, bounded miner fees, anonymity, timely mining,
or safety while the responsible party is offline. A refund becoming eligible
does not make it confirmed or invalidate the claim path.

No implementation may take a funding, payment, preimage-release, settlement,
or signing action based only on a counterparty status message. Required chain,
Lightning, contract, transaction, signature, amount, network, and deadline
evidence MUST be independently verified through the configured trust mode.

## 4. Required invariants

Implementations MUST enforce every invariant in
[ARCHITECTURE.md](../ARCHITECTURE.md) section 22. In
particular:

1. A contract with an unexpected internal key, leaf, network, amount, payment
   hash, timeout, output script, or destination is invalid.
2. An LN to BTC user MUST have a valid signed unilateral claim and durable
   recovery material before disclosing the preimage.
3. A provider MUST NOT issue an LN to BTC cooperative partial signature before
   it has the valid preimage and a safely settleable accepted payment.
4. MuSig secret nonces MUST remain in one-shot opaque native handles and MUST
   never be serialized, copied, restored, or deterministically reconstructed.
5. Knowledge that a preimage or dangerous signature was disclosed is
   monotonic across restart and reorganization.
6. Recovery MUST remain possible without any RillSwap provider, relay,
   website, registry, or previous browser origin.
