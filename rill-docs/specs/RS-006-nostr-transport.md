# RS-006: Nostr encrypted transport

Status: draft

Suite: `nostr-nip44v2-nip59/v1`

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
