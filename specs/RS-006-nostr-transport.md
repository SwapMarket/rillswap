# RS-006: Nostr encrypted transport

Status: pre-release draft

Suite: `nostr-nip44v2-nip59/v1`

The first transport encrypts RS-001 application frames with NIP-44 version 2
inside NIP-59 gift wraps. Durable outer events use kind 1059. For local
interoperability tests, inner protocol rumors use project-local experimental
kind 21417 with a required `rillswap` namespace and binding version. The inner
rumor remains unsigned as NIP-59 requires; any signed RillSwap application
object inside is separately authenticated and is not deniable.

Implementations MUST follow NIP-59 rumor, seal, and gift-wrap construction,
including empty seal tags, seal author checks, recipient checks, randomized
outer timestamps, one-time wrapper keys, and valid outer signatures. NIP-44
provides encryption only; sequence, replay, acknowledgement, and transcript
rules remain those of RS-001.

The provider advertises a rotating epoch inbox. Bootstrap authenticates a
fresh provider and client per-session mailbox in the signed handshake. Public
identity, epoch inbox, session mailboxes, contract signing keys, and recovery
authorization keys MUST be distinct.

Before decryption, reject an outer event with bad shape, signature, kind,
recipient tag, or encoded size over 128 KiB. Bound concurrent decryptions and
per-peer queues. After decryption validate seal author and recipient, then the
complete RS-001 transcript. Externally observable handling of malformed
ciphertext and malformed plaintext SHOULD be uniform and redacted.

The decoded application frame is limited to 16 KiB. Optional authenticated
padding is outside business semantics and pads the plaintext container to the
smallest configured 4, 8, or 16 KiB bucket that fits. The final encoded outer
event size is checked after construction. Retries use a fresh seal/wrapper and
randomness around the unchanged logical application message.

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
