# NIP draft: RillSwap discovery and encrypted sessions

**NIP number:** unassigned  
**Status:** proposed application binding, not submitted or registered  
**Version:** 0.1.0  
**License:** MIT for this document

## Purpose

Define permissionless discovery and authenticated encrypted communication for a provider-neutral Bitcoin–Lightning swap protocol. Settlement is specified separately; relays do not verify, arbitrate, or guarantee swaps.

This draft uses NIP01 events, NIP44 v2 encryption, and NIP59 wrapping. It is not a replacement for those specifications.

## Kind allocation

RillSwap requires a dedicated addressable provider-announcement kind and an application rumor kind. For private regtest interoperability, this draft uses experimental values **39417** and **21417**, respectively. These values are not claimed to be registered, globally unused, or final. Require protocol namespace and binding version, and coordinate/freeze the public stable values before deployment. Never publish the private rumor directly.

Do not use NIP78 kind 30078 as a generic public provider directory: its current documented purpose and owner-authenticated relay behavior differ from this use case.

## Provider announcements

An announcement is signed by the stable provider identity. Its addressable `d` tag identifies a protocol/network/advertisement slot. Public tags are restricted to application/network routing and other explicitly specified discovery metadata.
For the Nostr adapter only, RS-005 fixes kind 39417, the ordered namespace/network/`d` tags, canonical application-signed content, and a single complete supported network identity (mainnet, signet, testnet4, or namespaced regtest) per event. The coarse public `network` tag names that identity but cannot authenticate the full network. Manual application-signed import remains a separate path and does not require a Nostr event.

Content is a bounded, versioned object containing:

```text
protocol = "rillswap"
binding_version
advertisement_revision
network_identity
supported_settlement_profiles
supported_directions
coarse_amount_limits
indicative_fee_policy
transport_endpoints_and_suites
provider_epoch_inbox_key
application_expiry
```

Provider identity is the signing public key, not an unauthenticated display name. Provider descriptions are plain text. Exact balances, individual swap IDs, invoices, payment hashes, transaction IDs, client keys, and user-specific requests are forbidden in announcements.

Clients verify signatures, namespace, network, revision, expiry, bounded future dating, and supported profiles. Results remain untrusted offers. Clients may use any relays, cache valid ads, or import a provider directly. No central registry, NIP05 identifier, or official rating is mandatory.

## Session bootstrap

The client generates a fresh session identity unrelated to its social identity and wallet keys. It contacts the advertised epoch inbox using gift wrapping. The initial request carries only negotiation metadata and a random challenge, not the user's invoice or payment hash.

The provider replies with a signed handshake binding its advertised identity, both fresh session keys, both challenges, network, protocol/profile, encryption suite, capabilities, and per-session endpoints. The client checks this before exchanging binding financial terms.

Subsequent messages use per-session mailbox keys. A separate per-swap recovery authorization key permits authenticated resume without exporting past mailbox decryption keys. Unilateral recovery never depends on session resume.

## Message wrapping

The application rumor contains the canonical RillSwap envelope as its content. For the private-regtest binding only, RS-006 fixes its kind 21417 and tags exactly `[["rillswap","nostr-experimental-1"]]`, matching the separately advertised binding version. The rumor ID uses NIP01 serialization and has **no** `sig` member. Apply NIP59: encrypt the rumor inside an author-signed, empty-tag kind-13 seal, then encrypt that seal inside a one-time-key gift wrap with one matching recipient `p` tag. Use NIP44 v2 at each prescribed encryption step and durable outer kind 1059. Follow NIP59's timestamp, recipient, and signature rules. Do not publish the private rumor directly or treat a valid wrapper as authenticated swap admission. Public kind/version allocation remains open.

Verify event signatures/size bounds before decrypting, then validate the seal and expected peer. App-level signed quotes are allowed inside the encrypted payload and remain explicitly transferable evidence; do not claim that such quotes are deniable merely because the enclosing rumor is unsigned.

Encrypted application messages bind protocol version, profile, network, session/message ID, sender, sequence, response correlation, contract hash, type, payload, and mandatory features. Session authentication never replaces independent Bitcoin/LN observations for financial authorization.

The profile caps application envelope content at 16 KiB and received outer events at 128 KiB. NIP44's mandatory plaintext padding remains in use; the proposed additional 4/8/16 KiB transport container cannot be sent or accepted in the first private-regtest binding because its exact encoding is not yet specified. A separately versioned future binding may define it, with final encoded-size checks. This cap is a RillSwap policy, not a claim about NIP44's protocol maximum.

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
