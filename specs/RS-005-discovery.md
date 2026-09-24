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

For the **private-regtest Nostr adapter** `nostr-experimental-1` only, an
announcement is a signed NIP-01 addressable kind-39417 event with exactly
`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig` and no duplicate
JSON members. Its tags are **exactly, in order**
`[["rillswap","nostr-experimental-1"],["network","regtest"],["d",D]]`, with
no extra tag members, where `D` is the `d` digest above over the **one complete
network identity** in the signed application advertisement. The `network` tag
is public coarse routing metadata, never authorization for a specific genesis
hash, consensus profile, or deployment namespace. The event's `content` is
the RFC8785 JCS UTF-8 serialization of the existing schema-valid
`{"advertisement":{...},"signature":"..."}` object, with no additional
container. The outer `pubkey` equals the signed
`provider_identity_xonly_key`; verify **both** the NIP-01 ID/BIP340 signature
and the independent RS-001 tagged application signature. The outer
`created_at` equals the signed advertisement `created_at`.
The multi-character `rillswap` and `network` tags are public labels, **not**
portable relay subscription indexes. NIP-01 standardizes single-letter tag
filters only; fetch by kind (or a known address's `d`) and verify locally.

Only this Nostr adapter restricts the application advertisement to exactly
one `network_identities` entry, whose `name` is `regtest`, and to empty
`extensions`. Produce separate signed advertisements for separate complete
network identities; the schema and out-of-band manual application import
remain compatible with multiple networks. The producer MUST strictly
increase both signed revision and outer timestamp for an address (waiting
for the next second when necessary). A relay's replacement ordering by event
timestamp is not application revision ordering. Consumers compare revision
only within `(kind, identity pubkey, d)` after all signatures and complete
network checks; a matching coarse `network` tag alone proves nothing.

This adapter rejects more than 64 KiB of UTF-8 bytes in the **decoded content
string**, more than 128 KiB of **received raw UTF-8 event-object JSON bytes**
(not a compact reserialization), or more than 128 KiB in any complete relay
`EVENT` message carrying it. Enforce raw relay/event byte caps before parsing
either; enforce the decoded content string cap before parsing its JSON. Outer
event JSON and parsed application content independently permit at
most 16 nested object/array levels: the root object/array has depth 1, and
each contained object/array increments depth by 1. It rejects creation more
than 300 seconds ahead of the local Unix-seconds clock, an advertisement with
`expires_at <= now` (Unix seconds), or expiry at/before creation.
These limits are RillSwap profile policy, not general NIP-01 rules. Receive
work, not just each event, MUST be bounded globally as well as per identity;
deployments must set finite pending-verification and cached-address budgets
before accepting untrusted relay traffic. Unavailable capacity must fail
closed without evicting a trusted revision floor to make room for repeated
lower-revision events. No relay adapter or publication is implied by this
wire contract alone.

Consumers validate the Nostr event signature, application signature, identity,
schema, revision, expiry, future-date cap, supported network, and local resource
bounds. A lower or equal revision does not replace a valid cached record for
the same identity, complete network, and slot (equivalently, address `d`).
Per-identity memory, verification work, and relay input are bounded. A
locally absent revision record provides no evidence about whether an earlier
publication exists; an older, partial, or restored record does not prove global
freshness. Upgrading MUST
NOT republish, scan relays, reset a revision floor, or admit a provider solely
because its metadata is missing. Explicit user import remains a historical
offer unless an independent currentness policy is established.

Provider display names and descriptions are untrusted plain text. NIP05,
proof-of-work, claimed capacity, relay count, and listing source MUST NOT be
presented as principal protection. Multiple relays and cached advertisements
improve availability but do not establish truth.

Identity rotation uses an old-key-signed continuity statement and a
new-key-signed acceptance statement with activation time. Rotation never
changes identity or keys already bound into accepted swaps.
