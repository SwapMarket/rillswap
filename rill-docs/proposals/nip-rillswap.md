# NIP draft: RillSwap discovery and encrypted sessions

**NIP number:** unassigned  
**Status:** proposed application binding, not submitted or registered  
**Version:** 0.1.0  
**License:** MIT for this document

## Purpose

Define permissionless discovery and authenticated encrypted communication for a provider-neutral Bitcoin–Lightning swap protocol. Settlement is specified separately; relays do not verify, arbitrate, or guarantee swaps.

This draft uses [NIP-01 events and relay WebSockets](https://github.com/nostr-protocol/nips/blob/master/01.md), [NIP-44 v2 encryption](https://github.com/nostr-protocol/nips/blob/master/44.md#version-2), and [NIP-59 wrapping](https://github.com/nostr-protocol/nips/blob/master/59.md#protocol-description). It is not a replacement for those specifications. [RS-006's protocol overview](../specs/RS-006-nostr-transport.md#protocol-overview) gives schematic event layouts, relay frames and the client/provider handshake; [RS-001](../specs/RS-001-wire-and-types.md) defines the exact application wire objects.

## Kind allocation

RillSwap requires a dedicated addressable provider-announcement kind and an application rumor kind. This draft uses project-local values **39417** and **21417**, respectively. These values are not claimed to be registered or globally unused. Events carry the protocol namespace and binding version; registering stable values is a binding-version change. Never publish the private rumor directly.

| Kind | Role | Author | Published? |
|---|---|---|---|
| `39417` | Public addressable advertisement | Stable provider identity | Yes |
| `21417` | Unsigned rumor carrying an RS-001 envelope | Sender session key | No, encrypted in seal |
| `13` | NIP-59 signed seal with empty tags | Same sender session key | No, encrypted in gift wrap |
| `1059` | NIP-59 encrypted gift wrap with recipient `p` tag | Fresh one-time wrapper key | Yes |

NIP-01 defines the `30000..39999` addressable range and address `(kind, pubkey, d)`; [NIP-33](https://github.com/nostr-protocol/nips/blob/master/33.md) now points to those rules. Kind `21417` lies in the ephemeral range but is only an encrypted rumor, not a relay-published event. Kinds `13` and `1059` come from NIP-59, not a RillSwap allocation. This binding requires stored outer kind `1059`, not ephemeral `21059`, without promising relay retention.

Do not use [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) kind 30078 as a generic public provider directory: its current documented purpose and owner-authenticated relay behavior differ from this use case.

## Provider announcements

An announcement is signed by the stable provider identity. Its addressable `d` tag identifies a protocol/network/advertisement slot. Public tags are restricted to application/network routing and other explicitly specified discovery metadata.
For the Nostr adapter only, RS-005 fixes kind 39417, the ordered namespace/network/`d` tags, canonical application-signed content, and a single complete supported network identity (mainnet, signet, testnet4, or namespaced regtest) per event. The coarse public `network` tag names that identity but cannot authenticate the full network. Manual application-signed import remains a separate path and does not require a Nostr event.

The outer event has the seven NIP-01 fields `id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`. Its `content` is the canonical JSON **string** of `{"advertisement":{...},"signature":"..."}`. Verify both the NIP-01 event signature and the independent RS-001 application signature using the same stable provider key. The schema's actual advertisement member names are:

```text
protocol, binding_version, provider_identity_xonly_key, network_identities,
profiles, amount_bands, indicative_fee_policy, communication_suites,
transport_endpoints, epoch_inbox_xonly_keys, slot, revision, created_at,
expires_at, extensions
```

See [RS-005](../specs/RS-005-discovery.md#nostr-announcement-format) for the event layout, exact tags, `d` calculation, schema and reproducible vector. NIP-01 subscriptions fetch kind `39417` (optionally constrained by author and `#d`); the multi-character `rillswap` and `network` tags are validated locally, not portable relay tag indexes.

Provider identity is the signing public key, not an unauthenticated display name. Provider descriptions are plain text. Exact balances, individual swap IDs, invoices, payment hashes, transaction IDs, client keys, and user-specific requests are forbidden in announcements.

Clients verify signatures, namespace, network, revision, expiry, bounded future dating, and supported profiles. Results remain untrusted offers. Clients may use any relays, cache valid ads, or import a provider directly. No central registry, NIP05 identifier, or official rating is mandatory.

## Session bootstrap

The client generates a fresh session identity unrelated to its social identity and wallet keys. It contacts the advertised epoch inbox using gift wrapping. The initial request carries only negotiation metadata and a random challenge, not the user's invoice or payment hash.

The provider replies with a signed handshake binding its advertised identity, both fresh session keys, both challenges, network, protocol/profile, encryption suite, capabilities, and per-session endpoints. The client checks this before exchanging binding financial terms.

Subsequent messages use per-session mailbox keys. A separate per-swap recovery authorization key permits authenticated resume without exporting past mailbox decryption keys. Unilateral recovery never depends on session resume.

The encrypted application sequence is client `handshake_init` (sequence 0) to the epoch inbox, provider `handshake_accept` (sequence 0) to the client session mailbox, then client `handshake_confirm` (sequence 1) to the authenticated provider session mailbox. The accept payload contains `accept` and `provider_identity_signature`; its signature uses the provider identity learned before the handshake. After confirmation, the next client sequence is 2 and the next provider sequence is 1. Quotes, terms, funding bindings, observations, actions, acknowledgments and errors are RS-001 `message_type` values inside the same wrapping, not new Nostr kinds.

Both parties connect to relays as NIP-01 clients. Subscribe with `["REQ","inbox",{"kinds":[1059],"#p":["<local-mailbox-key>"]}]`, publish `["EVENT",gift_wrap]`, and receive `["EVENT","inbox",gift_wrap]`. The provider listens on advertised epoch inboxes and active session mailboxes; the client listens on its session mailbox. The outer author is a one-time key, not the provider identity. Relay `OK` reports event acceptance and `EOSE` ends stored-event replay, neither is an application response; the subscription stays live until closed or disconnected.

## Message wrapping

The application rumor contains the canonical RillSwap envelope as its content. For binding `nostr-experimental-1`, RS-006 fixes its kind 21417 and tags exactly `[["rillswap","nostr-experimental-1"]]`, matching the separately advertised binding version. The rumor ID uses NIP01 serialization and has **no** `sig` member. Apply NIP59: encrypt the rumor inside an author-signed, empty-tag kind-13 seal, then encrypt that seal inside a one-time-key gift wrap with one matching recipient `p` tag. Use NIP44 v2 at each prescribed encryption step and durable outer kind 1059. Follow NIP59's timestamp, recipient, and signature rules. Do not publish the private rumor directly or treat a valid wrapper as authenticated swap admission.

Verify event signatures/size bounds before decrypting, then validate the seal and expected peer. App-level signed quotes are allowed inside the encrypted payload and remain explicitly transferable evidence; do not claim that such quotes are deniable merely because the enclosing rumor is unsigned.

Encrypted application messages bind protocol version, profile, network, session/message ID, sender, sequence, response correlation, contract hash, type, payload, and mandatory features. Session authentication never replaces independent Bitcoin/LN observations for financial authorization.

The profile caps application envelope content at 16 KiB and received outer events at 128 KiB. NIP44's mandatory plaintext padding remains in use; the binding defines no additional transport-padding container. A separately versioned binding may define one, with final encoded-size checks. This cap is a RillSwap policy, not a claim about NIP44's protocol maximum.

## Delivery and idempotency

Relays can drop, duplicate, reorder, delay, censor, or selectively expose events. Persist application inbox/outbox records and financial action intents. A logical retransmission retains its message ID but receives a fresh encrypted wrapper. Relay acknowledgment is not application acknowledgment; neither is proof of successful chain/payment execution.

True application expiry and deadlines are inside authenticated content. Randomized outer timestamps must not control financial timeouts. A party may move to another allowed relay or direct transport through authenticated endpoint negotiation. Such migration cannot change settlement terms, network, encryption suite, or privacy policy silently.

## Metadata and key-compromise limitations

Relays can observe recipient routing tags, timing, sizes, source addresses, subscriptions, and correlations. Public provider inboxes disclose initial service targeting. Per-session keys and gift wrapping reduce some stable linkage but do not eliminate these observations.

NIP44 is not a forward-secret ratchet. Session-key deletion is only an exposure-reduction measure; recorded traffic can remain vulnerable if relevant keys are later obtained. Expiration/deletion requests do not prove relay erasure.

Clients should avoid stable social/relay-auth identities, use a small explicitly selected relay set, and provide Tor-capable fail-closed transport. Remote DNS is required for Tor proxy mode. A browser uses Tor Browser or a local transport component rather than pretending to set system SOCKS itself. Extra relays increase both availability and observation surface.

Privacy claims must distinguish protection from a curious relay, protection from a colluding provider, and resistance to a global traffic observer. This draft does not claim the last property.

## Extensibility

Discovery and session transport are independent interfaces. A future direct HTTPS/WebSocket or onion endpoint may carry the same authenticated encrypted frames without relays. New encryption mechanisms require distinct suite identifiers, authenticated capability negotiation, and independent review. This binding neither mandates a particular relay operator nor excludes non-Nostr discovery.

## Conformance

Implementations must pass cross-language NIP44/59 fixtures, signature/recipient rejection, discovery expiry/rollback tests, replay/reorder/idempotency tests, transcript downgrade tests, plaintext metadata inspection, and Tor fail-closed tests. Tests must distinguish metadata that is intentionally visible from a leaked private field.

A registered kind does not itself establish settlement safety or community endorsement.
