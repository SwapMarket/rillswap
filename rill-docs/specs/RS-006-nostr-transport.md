# RS-006: Nostr encrypted transport

Status: draft

Suite: `nostr-nip44v2-nip59/v1`

## Protocol overview

There are three distinct layers: [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
defines events and relay WebSocket frames;
[NIP-44 v2](https://github.com/nostr-protocol/nips/blob/master/44.md#version-2)
and [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md#protocol-description)
encrypt and wrap a private message; [RS-001](RS-001-wire-and-types.md) defines
what that message means to a client and provider. NIP-44 and NIP-59 do not
define swap requests, financial authorization, or acknowledgments.
This overview explains the existing binding; the binding rules below and
RS-001/RS-005 define its exact requirements.

| Kind | Author key | Tags | `content` | Relay visibility |
|---|---|---|---|---|
| `39417` | Stable provider identity | Namespace, network, `d`, exactly as [RS-005](RS-005-discovery.md) specifies | Canonical application-signed advertisement JSON string | Public announcement |
| `21417` | Sender session mailbox, unsigned rumor | `[["rillswap","nostr-experimental-1"]]` | Canonical RS-001 envelope JSON string | Only inside encrypted seal |
| `13` | Same sender session mailbox, signed seal | `[]` | NIP-44 v2 encrypted rumor JSON | Only inside encrypted gift wrap |
| `1059` | Fresh one-time wrapper key | Recipient `p`, plus `nonce` if transport PoW applies | NIP-44 v2 encrypted seal JSON | Published encrypted message |

Only `39417` and `1059` are published. The two RillSwap-specific kinds,
`39417` and `21417`, are experimental, not registered NIP allocations. NIP-01
classifies `39417` as addressable; the address is `(39417, provider pubkey, d)`.
Although `21417` falls in NIP-01's ephemeral range, it is never published, and
does not make the stored outer `1059` ephemeral. NIP-59, not RillSwap, defines
kinds `13` and `1059`. This binding does not use ephemeral outer kind `21059`.

### Event layouts

The following JSON is schematic: angle-bracket strings are placeholders, not
valid keys, signatures, ciphertext, or conformance vectors. Each
`content` is a **string**, not an embedded JSON object. The sender constructs
these layers from the inside out; the recipient validates and decrypts them
from the outside in.

Unsigned rumor (the `sig` member is absent, not null):

```json
{
  "id": "<NIP-01 hash of this rumor>",
  "pubkey": "<sender session x-only public key>",
  "created_at": 1703021488,
  "kind": 21417,
  "tags": [["rillswap", "nostr-experimental-1"]],
  "content": "<JCS serialization of the complete RS-001 envelope>"
}
```

Signed seal, encrypted to the recipient's epoch inbox or session mailbox:

```json
{
  "id": "<NIP-01 hash of this seal>",
  "pubkey": "<same sender session x-only public key>",
  "created_at": 1703010000,
  "kind": 13,
  "tags": [],
  "content": "<NIP-44 v2 encryption of rumor JSON, sender key to recipient key>",
  "sig": "<sender session key signature>"
}
```

Signed gift wrap, encrypted to that same recipient with a fresh wrapper key:

```json
{
  "id": "<NIP-01 hash of this gift wrap>",
  "pubkey": "<fresh one-time wrapper x-only public key>",
  "created_at": 1703000000,
  "kind": 1059,
  "tags": [["p", "<recipient epoch inbox or session mailbox x-only public key>"]],
  "content": "<NIP-44 v2 encryption of seal JSON, wrapper key to recipient key>",
  "sig": "<one-time wrapper key signature>"
}
```

The numbers illustrate separate timestamps, not a required offset. See the
binding rules below for timestamp randomization and transport PoW's optional
outer `nonce` tag. NIP-44 ciphertext is a base64 string containing its version
byte, nonce, ciphertext and MAC, with the padding prescribed by NIP-44.
For each Nostr layer, compute its `id` and any `sig` using
[NIP-01 event serialization](https://github.com/nostr-protocol/nips/blob/master/01.md#events-and-signatures),
not the application's tagged JCS hash.

Decoded rumor `content` has the following application shape, shown before
canonicalization. This example represents an initiation; its null application
`signature` is distinct from the rumor having no `sig` member:

```json
{
  "protocol": "rillswap",
  "wire_version": "1",
  "profile_id": "btc-to-ln/v1",
  "network_identity": "<complete NetworkIdentity object, not a network label>",
  "session_id": "<epoch-bound session ID>",
  "message_id": "<random 32-byte logical message ID, lowercase hex>",
  "sender_session_key": "<client session x-only public key>",
  "sequence": 0,
  "in_reply_to": null,
  "contract_hash": null,
  "message_type": "handshake_init",
  "payload": "<complete HandshakeInitV1 object>",
  "required_features": [],
  "extensions": {},
  "signature": null
}
```

The placeholder `network_identity` and `payload` values stand for objects,
not actual wire strings. The initiation payload includes
`"epoch-bound-session/v1"` in its own `required_features` and the selected
epoch in `extensions["rillswap/epoch-bound-session"]`. Binding version
`nostr-experimental-1`, communication suite `nostr-nip44v2-nip59/v1`, wire
version `"1"`, and profile `btc-to-ln/v1` are different identifiers. The exact
closed objects, signature placement and monetary encodings are defined by
[RS-001](RS-001-wire-and-types.md) and the
[envelope schema](../schemas/wire/envelope-v1.schema.json). See the
[rumor vector](../vectors/wire/nostr-rumor-experimental-1.json) and its linked
authentication vector for reproducible application bytes and event ID.

### Communication and handshake suite identifiers

Implementation note: RS-005's advertisement `communication_suites` contains
`nostr-nip44v2-nip59/v1`. RS-001's handshake fields
`requested_encryption_suites` and `selected_encryption_suite` are separate
negotiation identifiers. The reference provider, CLI, browser client and
[authentication vectors](../vectors/authentication/cases-v1.json) currently
use `noise-xk-secp256k1-chachapoly-sha256/v1` in those handshake fields.
Despite its name, that token does not select a Noise handshake or ratchet in
these implementations: actual wire encryption is NIP-44 v2 inside NIP-59 as
described here. The token adds no confidentiality, authentication or forward
secrecy properties. Do not substitute the communication-suite identifier into
the handshake fields or infer extra cryptographic protection from their name.

### Relay wire exchange

Clients and providers both act as Nostr clients connecting to relay
WebSockets. They do not send these frames directly to one another. These are
the [NIP-01 communication frames](https://github.com/nostr-protocol/nips/blob/master/01.md#communication-between-clients-and-relays),
shown with symbolic `event` values:

```text
Sender to relay:      ["EVENT", event]
Subscriber to relay:  ["REQ", "subscription-id", filter]
Relay to subscriber:  ["EVENT", "subscription-id", event]
Relay to sender:      ["OK", "event-id", true, ""]
Relay to subscriber:  ["EOSE", "subscription-id"]
Subscriber to relay:  ["CLOSE", "subscription-id"]
```

For public discovery, use a filter such as `{"kinds":[39417]}`; a known
provider/address can additionally be selected with `authors` and `#d`.
Validate namespace and complete network locally: `#rillswap` and `#network`
are not portable NIP-01 filters because those tags are not single-letter
indexes. [RS-005](RS-005-discovery.md) specifies advertisement validation.

For private delivery, subscribe with
`{"kinds":[1059],"#p":["<local inbox x-only public key>"]}`.
A provider listens for its epoch inboxes and active session mailboxes; a
client listens for its session mailbox. Do not filter wrappers by the
provider's identity as `authors`: outer authors are fresh one-time keys.
Senders publish the outer kind-1059 event, never the rumor or seal.

`OK` reports relay acceptance or rejection only. `EOSE` ends the stored-event
portion of a subscription, not the live subscription and not a swap exchange.
An application `ack` is an encrypted RS-001 message, not a Nostr relay frame.
Durable-kind delivery does not guarantee relay retention, availability, or
counterparty receipt.

The reference CLI and browser may attempt to publish the same constructed
outer event up to three times before failing. This resubmits the same event
ID; it is distinct from an application retransmission constructed with fresh
encryption and a new wrapper around the unchanged logical message.

### Session and application exchange

Every row below is an RS-001 envelope inside a new NIP-59 gift wrap:

| Step | Application message | Rumor/seal sender | Outer recipient `p` |
|---|---|---|---|
| 1 | Client `handshake_init`, client sequence `0` | Fresh client session key | Selected advertised provider epoch inbox |
| 2 | Provider `handshake_accept`, provider sequence `0`, replying to init | Fresh provider session key | Client session mailbox |
| 3 | Client `handshake_confirm`, client sequence `1`, replying to accept | Client session key | Provider session mailbox from the authenticated accept |
| 4 | Quotes, terms and profile-specific messages; next client sequence `2`, next provider sequence `1` | Sending party's session key | Other party's session mailbox |

The initiation offers profile, full network, challenge, suites, capabilities
and required features, but no invoice or payment hash. The accept payload's
`provider_identity_signature` authenticates the handshake using the provider
identity already obtained from discovery or verified manual import; the
kind-1059 wrapper signature cannot do that. The client verifies the identity,
echoed values, selected suite, epoch binding and fresh mailbox before
confirming. Economic messages are invalid before confirmation.

After confirmation, application message types include `quote_request`,
`quote_offer`, `terms_offer`, `terms_accept`, `funding_binding`, `observation`,
`action_request`, `action_result`, `ack` and `error`. A message type is a field
**inside** the encrypted envelope, not a different Nostr kind. The allowed
ordering and payloads depend on [BTC to LN](RS-003-btc-to-ln.md),
[LN to BTC](RS-004-ln-to-btc.md), or [ERC20](RS-010-erc20-swaps.md) state.
Post-handshake envelopes are signed by the sending session key; terms and
funding objects also have their purpose-specific signatures.

For both Bitcoin profiles, an indicative `quote_request` gets a `quote_offer`
without committing either party. A firm request uses a fresh session and gets
`terms_offer` directly, not an intervening `quote_offer`. For BTC to LN, the
firm request supplies the invoice; the client verifies terms and persists
recovery before `terms_accept`, then funds and sends `funding_binding`. For
LN to BTC, the firm request supplies the payment hash; the provider's terms
include the hold invoice. After acceptance, recovery persistence and Lightning
payment, the provider checks the held payment, funds and sends `funding_binding`.
Lightning payments and on-chain transactions use their respective networks,
not Nostr; the encrypted messages negotiate or report those operations.

Sequence, logical `message_id`, `in_reply_to`, session/network binding and
contract hash belong to RS-001, not NIP-59. Application retransmissions retain
the same application bytes and message ID but get fresh encryption and
wrappers. Receivers deduplicate at the application layer so duplicate delivery
cannot repeat a payment or broadcast. Neither valid encryption nor an
acknowledgment replaces independent chain and Lightning checks.

## Binding and validation rules

This transport encrypts RS-001 application frames with NIP-44 version 2
inside NIP-59 gift wraps. Durable outer events use kind 1059. Inner protocol
rumors use project-local kind 21417. For binding `nostr-experimental-1`, the
rumor is exactly the six NIP-01 members `id`,
`pubkey`, `created_at`, `kind`, `tags`, `content`, with **no** `sig` member
(including no null signature). Its tags are exactly
`[["rillswap","nostr-experimental-1"]]`. Its `content` is the canonical
RS-001 application envelope serialized as one UTF-8 JSON string, without a
new container, prefix, or trailing padding. Recompute the rumor ID using
NIP-01's `[0,pubkey,created_at,kind,tags,content]` serialization, **not**
RS-001's JCS hash. The application envelope independently requires
`protocol="rillswap"` and `wire_version="1"`; these are **not** aliases for
the Nostr binding version. Reject unknown binding tags or versions rather
than trying a weaker interpretation. The inner rumor remains unsigned as
NIP-59 requires; any signed RillSwap application object inside is separately
authenticated and is not deniable. The **project-local rumor kind 21417 and
binding `nostr-experimental-1`** are not registered public identifiers;
registered values would require a new binding version. Seal kind 13 and outer gift-wrap
kind 1059 are already NIP-59 identifiers.

Implementations MUST follow NIP-59 rumor, seal, and gift-wrap construction,
including a signed kind-13 seal with **empty tags**, a one-time wrapper key,
and valid outer signatures. **This binding additionally
requires** a durable kind-1059 outer event (not NIP-59's ephemeral 21059),
exactly one matching recipient `p` routing tag, and randomized outer
timestamps. NIP-59 describes recipient routing tags and timestamp tweaking
as SHOULD recommendations; these are stricter RillSwap requirements.
The signed seal `pubkey` MUST equal the unsigned rumor `pubkey`, which MUST
equal the inner envelope `sender_session_key`. Independently bind that sender
to the expected client/provider session context; a stranger can sign a valid
gift wrap to a public inbox. NIP-44 provides encryption only; sequence,
replay, acknowledgement, and transcript rules remain those of RS-001.

The provider advertises a rotating epoch inbox. Bootstrap authenticates a
fresh provider and client per-session mailbox in the signed handshake. Public
identity, epoch inbox, session mailboxes, contract signing keys, and recovery
authorization keys MUST be distinct.

Before decryption, reject an outer event with bad shape, signature, kind,
recipient tag, encoded size over 128 KiB, or insufficient transport proof of
work (below). Bound concurrent decryptions and
per-peer queues. Decrypt the outer content using the intended local epoch-inbox
or session-mailbox secret, **never** the provider identity or contract key.
Verify the decrypted seal ID/signature, kind and empty tags before its NIP-44
decryption; then check the rumor ID/author/binding and the complete RS-001
transcript. Neither outer nor seal timestamp substitutes for application
ordering, expiry, or financial deadlines. Externally observable handling of
malformed ciphertext and malformed plaintext SHOULD be uniform and redacted.

The decoded application envelope `content` is limited to 16 KiB of UTF-8
bytes. NIP-44's own mandatory plaintext padding still applies at both layers.
This binding defines no **additional** transport-padding container: it MUST
send and receive only the direct, unpadded canonical-envelope content defined
above. An optional authenticated transport-padding format would require a
separately specified binding version and explicit negotiation; do not guess it from
extra JSON fields, whitespace, or ciphertext length. The final encoded outer
event size is checked after construction. Retries use a fresh seal/wrapper
and randomness around the unchanged logical application message.

**Transport proof of work.** A provider MAY require NIP-13 proof of work on
every kind-1059 outer event a client sends to it. It advertises the
requirement as `extensions["rillswap/transport-pow"] = {"bits": N}` with
integer `1 <= N <= 20`, and omits the key when it requires none. Clients
MUST refuse an advertisement with any other value, or with `N` above their
own limit, rather than ignore the key. A client contacting such a provider
MUST declare its target in the initiation as
`extensions["rillswap/transport-pow"] = {"bits": T}` with `N <= T <= 20`,
and MUST mine every outer event it sends in that session, the initiation
and every later session-mailbox message, to `T`. The declaration binds the
session: a later change of `N` neither raises nor lowers the work its
messages carry. It is an optional RS-001 extension that providers not
requiring work ignore; it changes neither the session ID nor any safety rule.

Mining adds exactly one tag `["nonce", <counter>, <target>]` after the `p`
routing tag, where `<target>` is `T` in canonical decimal (no sign or leading
zero) and `<counter>` is a decimal string. The outer `created_at` keeps its
randomized past value; unlike NIP-13's reference miners, a client MUST NOT
advance it while mining. The outer event is signed after mining. The work an
event proves is the number of leading zero bits of its **recomputed** NIP-01
ID, capped at its committed target; zero or several `nonce` tags, a tag
without exactly three members, or a non-canonical target prove zero work,
and a claimed `id` other than the recomputed hash proves nothing.

The provider checks work with one hash before any custody unsealing,
signature verification, or decryption, and before recording the event as
seen. An epoch inbox and any unknown recipient require `N`; a session mailbox
requires the target its initiation declared. The provider refuses an
initiation whose declaration is malformed, or, while `N > 0`, missing or below
`N`. A session admitted without a declaration (before the provider required
work) remains exempt only until its swap reaches a terminal state, so enabling
work never strands a live swap; a missing or unrecognized swap state counts as
unfinished. Provider-to-client events carry no work. Work raises the cost of
floods; at a browser-friendly difficulty it does not stop one determined
sender from filling admission limits, and it is not authentication, rate
limiting, Sybil resistance, or principal protection (RS-005). See
`vectors/wire/nostr-transport-pow-v1.json`.

Relay `OK` is delivery information only. Messages are at least once and may be
missing or reordered. The durable outbox retains a logical message until an
application acknowledgment or state reconciliation makes it unnecessary.

Tor-capable native clients reach relays through a local Tor proxy (SOCKS or
an HTTP CONNECT tunnel such as `HTTPTunnelPort`) with remote name resolution,
and fail closed. No automatic clearnet fallback is permitted. On public
networks a native client or provider without a configured proxy MUST refuse
to connect unless the user explicitly accepts direct relay connections;
regtest may connect directly. The reference implementation uses a loopback
HTTP CONNECT proxy, so proxied relays must use `wss://`, except v3 onion
relays, which Tor encrypts and authenticates end to end and may use plain
`ws://`. Onion relays are opportunistic: a client or provider that cannot
reach onion services skips them without reporting a failure, and a provider
announces only the relays it can reach. Browser applications cannot promise
arbitrary SOCKS and must accurately disclose the chosen browser/network mode.

Relays can observe recipient tags, subscriptions, source addresses, timing,
sizes, retries, and cross-relay correlations. NIP-44 does not provide forward
secrecy. Deletion requests are retention hints. Implementations MUST NOT market
this suite as anonymity against a global observer or as an audited ratchet.
