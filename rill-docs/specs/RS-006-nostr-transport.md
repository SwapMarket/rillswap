# RS-006: Nostr encrypted transport

Status: pre-release draft

Suite: `nostr-nip44v2-nip59/v1`

The first transport encrypts RS-001 application frames with NIP-44 version 2
inside NIP-59 gift wraps. Durable outer events use kind 1059. For local
interoperability tests, inner protocol rumors use project-local experimental
kind 21417. For **private-regtest experimental binding**
`nostr-experimental-1`, the rumor is exactly the six NIP-01 members `id`,
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
coordinate stable values before deployment. Seal kind 13 and outer gift-wrap
kind 1059 are already NIP-59 identifiers.

Implementations MUST follow NIP-59 rumor, seal, and gift-wrap construction,
including a signed kind-13 seal with **empty tags**, a one-time wrapper key,
and valid outer signatures. **RillSwap's private-regtest profile additionally
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
recipient tag, or encoded size over 128 KiB. Bound concurrent decryptions and
per-peer queues. Decrypt the outer content using the intended local epoch-inbox
or session-mailbox secret, **never** the provider identity or contract key.
Verify the decrypted seal ID/signature, kind and empty tags before its NIP-44
decryption; then check the rumor ID/author/binding and the complete RS-001
transcript. Neither outer nor seal timestamp substitutes for application
ordering, expiry, or financial deadlines. Externally observable handling of
malformed ciphertext and malformed plaintext SHOULD be uniform and redacted.

The decoded application envelope `content` is limited to 16 KiB of UTF-8
bytes. NIP-44's own mandatory plaintext padding still applies at both layers.
The previously proposed **additional** 4/8/16 KiB transport-padding container
has no wire encoding yet: this experimental binding MUST send and receive
only the direct, unpadded canonical-envelope content defined above. A future
optional authenticated transport-padding format requires a separately
specified binding version and explicit negotiation; do not guess it from
extra JSON fields, whitespace, or ciphertext length. The final encoded outer
event size is checked after construction. Retries use a fresh seal/wrapper
and randomness around the unchanged logical application message.

Relay `OK` is delivery information only. Messages are at least once and may be
missing or reordered. The durable outbox retains a logical message until an
application acknowledgment or state reconciliation makes it unnecessary.

Tor-capable native clients use SOCKS with remote DNS and fail closed. No
automatic clearnet fallback is permitted. Browser applications cannot promise
arbitrary SOCKS and must accurately disclose the chosen browser/network mode.

Relays can observe recipient tags, subscriptions, source addresses, timing,
sizes, retries, and cross-relay correlations. NIP-44 does not provide forward
secrecy. Deletion requests are retention hints. Implementations MUST NOT market
this suite as anonymity against a global observer or as an audited ratchet.
