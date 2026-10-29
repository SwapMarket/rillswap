# RS-005: Provider discovery

Status: draft

Version: `0.1.0-pre.1`

## Nostr announcement format

The public discovery event is kind **39417**, signed by the provider's stable
identity key. It follows the event and addressable-kind rules in
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md#kinds)
(formerly [NIP-33](https://github.com/nostr-protocol/nips/blob/master/33.md)).
The kind and application tags are RillSwap's experimental choices, not kinds
assigned by either NIP. An announcement is public and unencrypted; private
client requests use [RS-006 gift wraps](RS-006-nostr-transport.md#protocol-overview),
not announcement events.

Schematic event (placeholders are not valid wire values):

```json
{
  "id": "<NIP-01 event hash>",
  "pubkey": "<stable provider identity x-only public key>",
  "created_at": 1703021488,
  "kind": 39417,
  "tags": [
    ["rillswap", "nostr-experimental-1"],
    ["network", "regtest"],
    ["d", "<SHA256 of the canonical protocol/binding/network/slot tuple>"]
  ],
  "content": "<JCS serialization of the signed advertisement object>",
  "sig": "<NIP-01 signature by the provider identity key>"
}
```

The decoded `content` is exactly `{"advertisement":{...},"signature":"..."}`,
using the [advertisement schema](../schemas/advertisements/advertisement-v1.schema.json).
The inner `advertisement` has these actual wire member names:

```text
protocol, binding_version, provider_identity_xonly_key, network_identities,
profiles, amount_bands, indicative_fee_policy, communication_suites,
transport_endpoints, epoch_inbox_xonly_keys, slot, revision, created_at,
expires_at, extensions
```

The inner `signature` is the RS-001 `RillSwap/advertisement/v1` application
signature, distinct from the outer NIP-01 event `sig`. Both use the provider
identity key and both are verified. `content` is serialized once to a canonical
JSON string, then escaped as a string when serializing the outer event.
The [regtest announcement vector](../vectors/discovery/nostr-announcement-regtest-v1.json)
and its linked application vector give exact bytes, ID and signatures.

Clients fetch announcements with NIP-01 `REQ`, for example
`["REQ","providers",{"kinds":[39417]}]`, and validate them locally as specified
below. The addressable event's `d` distinguishes network/slot advertisements
by the same provider; relay replacement by timestamp does not replace the
application's revision and expiry checks.

## Validation and discovery policy

Discovery returns authenticated advertisements, not trusted liquidity,
solvency, routing, availability, or reputation evidence. Discovery is
permissionless: a client MAY list every valid announcement on its selected
network from any number of relays without an author allowlist, keeping each
identity's highest revision and excluding an identity with conflicting
advertisements at its latest revision. Selecting a provider for a swap remains
an explicit user choice of one identity, and manual import of a provider
identity and endpoint remains supported.

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

For the **Nostr adapter** `nostr-experimental-1` only, an
announcement is a signed NIP-01 addressable kind-39417 event with exactly
`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig` and no duplicate
JSON members. Its tags are **exactly, in order**
`[["rillswap","nostr-experimental-1"],["network",N],["d",D]]`, with
no extra tag members, where `N` is the `name` of the one signed network
identity and one of `mainnet`, `signet`, `testnet4`, or `regtest`, and `D` is the `d` digest above over the **one complete
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
one `network_identities` entry, which must be a supported execution identity
(default mainnet, default signet, testnet4, or namespaced default regtest; not
testnet3 or custom signets) whose `name` equals `N`. Its known `extensions`
keys are RS-010's `rillswap/evm-assets-v1`, RS-006's `rillswap/transport-pow`,
and the funding depth below. A known key with a malformed value refuses the announcement.
Consumers ignore keys they do not know and use the rest of the announcement:
per RS-001 an unknown optional extension cannot change safety behavior, so a
provider that needs clients to act on a new key also requires a handshake
feature for it. Produce separate signed advertisements for separate complete
network identities; the schema and out-of-band manual application import
remain compatible with multiple networks. The producer MUST strictly
increase both signed revision and outer timestamp for an address (waiting
for the next second when necessary). A relay's replacement ordering by event
timestamp is not application revision ordering. Consumers compare revision
only within `(kind, identity pubkey, d)` after all signatures and complete
network checks; a matching coarse `network` tag alone proves nothing.

Every session is epoch-bound (RS-001 section 7.1), so the requirement is
unconditional and no extension advertises it. Clients select one of the
advertised epoch inbox keys before deriving their session ID and MUST
negotiate the RS-001 epoch-bound feature in both initiation and acceptance.
An advertisement is still discovery evidence, not permission to fund or a
proof that its epoch is currently usable.

A provider announces its funding depth as

```json
{"rillswap/funding-confirmations": {"confirmations": 1}}
```

where `confirmations` is an exact JSON integer `N`: the
`funding_confirmations` every quote and terms offer for the listed profiles
carries, in blocks of the funding chain (Bitcoin, or the RS-010 EVM chain).
For BTC to LN and ERC20 to LN it is how long the provider waits on the client's
funding before paying the invoice; for LN to BTC and LN to ERC20 it is how long
the client waits on the provider's lockup before claiming. `N` may be 0 only
when every listed profile is `btc-to-ln/v1` (RS-003). A client refuses an offer
whose `funding_confirmations` exceeds an announced `N` and accepts a lower one.
An announcement without the key (older providers) states nothing: clients
treat the depth as unknown, never as 0 or 1, and may order such providers
after those that announce one. An operator who raises `N` publishes the new
revision before quoting; clients still holding the older revision refuse the
higher offers until they refresh.

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
