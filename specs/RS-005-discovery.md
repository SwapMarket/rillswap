# RS-005: Provider discovery

Status: pre-release draft

Version: `0.1.0-pre.1`

Discovery returns authenticated advertisements, not trusted liquidity,
solvency, routing, availability, or reputation evidence. Manual import of a
provider identity and endpoint is mandatory.

An advertisement contains the protocol and binding versions, provider
identity key, complete supported network identities, profiles and directions,
coarse amount bands, indicative fee policy, communication suites and
endpoints, epoch inbox keys, creation and expiry times, and a monotonically
increasing revision. The identity key signs the canonical advertisement using
the RS-001 advertisement tag.

The first Nostr adapter uses project-local experimental addressable kind 39417
with a required `rillswap` namespace and experimental binding version. This is
not a globally registered kind. A public stable binding requires coordination
and a new binding version rather than silent reinterpretation.

The `d` tag is the lowercase hex SHA256 of the canonical tuple
`["rillswap", binding_version, network_identity, slot]`. Public tags contain
only the namespace, binding version, coarse network selector, and `d` value.
They MUST NOT contain invoices, payment hashes, transaction IDs, contract or
session IDs, exact per-swap amounts, or client identities.

Consumers validate the Nostr event signature, application signature, identity,
schema, revision, expiry, future-date cap, supported network, and local resource
bounds. A lower or equal revision does not replace a valid cached record for
the same identity and slot. Per-identity memory, verification work, and relay
input are bounded.

Provider display names and descriptions are untrusted plain text. NIP05,
proof-of-work, claimed capacity, relay count, and listing source MUST NOT be
presented as principal protection. Multiple relays and cached advertisements
improve availability but do not establish truth.

Identity rotation uses an old-key-signed continuity statement and a
new-key-signed acceptance statement with activation time. Rotation never
changes identity or keys already bound into accepted swaps.
