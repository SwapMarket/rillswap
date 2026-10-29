```
BIP: ?
Layer: Applications
Title: Taproot Bitcoin-Lightning Atomic Swaps
Authors: m0wer <m0wer@sgn.space>
Status: Draft
Type: Specification
Assigned: ?
License: MIT
Version: 0.1.0
Requires: 65, 327, 340, 341, 342
```

# Draft notice

This is an unassigned draft. It has not been submitted, assigned, or accepted. Byte-level schemas, vectors and a reference implementation are maintained in the RillSwap repository (`rill-docs/schemas/`, `rill-docs/vectors/`). Follow the current BIP 3 process.

## Abstract

This proposal specifies a provider-neutral construction for exchanging Bitcoin on-chain funds and a fixed-amount Lightning payment. A two-leaf Taproot output supplies a preimage-and-signature claim and a timed refund. A two-party aggregate internal key permits a cooperative key-path claim. Directional requirements bind the construction to Lightning payment state, safe preimage disclosure, and independent recovery.

Discovery, message transport, pricing, and wallet implementation are modular. The accompanying RillSwap wire documents define interoperable negotiation and a separate Nostr binding. This proposal introduces no Bitcoin consensus change.

## Copyright

This document is licensed under the MIT license included in the RillSwap repository. Third-party specifications and implementations retain their licenses.

## Motivation

An atomic-swap service can disappear while valid transactions remain recoverable. Users therefore need more than a provider API: they need a locally verifiable contract, defined authorization conditions, and recovery data another implementation can consume. Providers need equivalent protection against clients who attempt to claim on-chain value while preventing Lightning settlement.

A common settlement profile enables different transports and discovery systems without weakening the underlying contract. Cooperative privacy must remain optional at execution time: refusal to cooperate cannot eliminate an already valid unilateral path.

## Terminology and scope

A **user** initiates a swap. A **provider** offers the opposite side. A **claimant** is the party authorized to consume the hashlocked branch. A **funder** is the party authorized to consume the timed refund branch. The roles differ by direction.

The initial profile uses BOLT11, an exact 32-byte SHA256 preimage, a fixed invoice amount restricted to whole satoshis, and confirmed Bitcoin funding. A BTC-to-LN provider may opt in to paying against unconfirmed funding, at its own risk. LN-to-BTC terms always require at least one confirmation, though the user may explicitly claim earlier at its own risk. It does not support AMP, keysend, PTLCs, or alternative assets.

The initial identifiers are `rillswap/taproot-htlc/btc-to-ln/v1` and `rillswap/taproot-htlc/ln-to-btc/v1`. They are proposed identifiers, not claims of compatibility with existing service APIs.

## Specification

### 1. Network binding

Accepted terms MUST identify the Bitcoin network, genesis hash, consensus profile, and signet challenge where applicable. Regtest/test deployments MAY add an application namespace. An implementation MUST NOT infer the complete network identity solely from an address or invoice prefix. Recovery data MUST preserve the same identity.

### 2. Keys and preimage

Each party supplies a fresh valid compressed secp256k1 public key for the swap. The two public keys MUST be distinct and MUST NOT be reused as Nostr identity/mailbox keys. The claim preimage is 32 bytes, with `payment_hash=SHA256(preimage)`.

For BTC→LN, the invoice receiver controls the secret before payment. For LN→BTC, the user generates the secret before the provider creates a hold invoice. Reuse of a payment hash across independently funded swaps is prohibited in this profile.

### 3. Output construction

The aggregate internal key is computed by BIP327 with ordered input list `[user_key, provider_key]`. Apply the BIP341 Taproot tweak committing to exactly two depth-one leaves. Leaf version is `0xc0`; branch hashing and key parity follow BIP341.

Claim leaf:

```text
OP_SIZE <32> OP_EQUALVERIFY
OP_SHA256 <payment_hash> OP_EQUALVERIFY
<claimant_xonly_key> OP_CHECKSIG
```

Refund leaf:

```text
<refund_lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
<funder_xonly_key> OP_CHECKSIG
```

Script integers and data pushes MUST use minimal encoding. The timeout is a block height below the locktime timestamp threshold. No extra script leaves, alternative leaf versions, annex, or additional spending conditions are permitted.

For BTC→LN, claimant=provider and funder=user. For LN→BTC, claimant=user and funder=provider.

Before funding or accepting funding, the verifier MUST reconstruct the aggregate internal key, both scripts, merkle root, tweak, output key, scriptPubKey, and control blocks. Checking a presented refund script alone is insufficient.

### 4. Funding and spending transactions

Funding MUST create the exact contract amount in the exact contract scriptPubKey. V1 funding inputs are native SegWit/Taproot. Each contract is funded once. A replacement MUST preserve the contract output and MUST be tracked as a replacement, not a second independent deposit.

Unilateral spends use transaction version 2 and `SIGHASH_DEFAULT`. The contract input sequence is `0xfffffffd`. A claim has locktime 0; a refund has locktime T, the agreed refund height. The first eligible mined refund block is modeled as R=T+1. Exact boundary behavior MUST be tested against Bitcoin Core.

The initial spend template has one contract input and one preapproved destination output. Fee changes require an explicitly authorized output reduction within the agreed policy. Additional inputs, batching, other sighash modes, and arbitrary outputs require a separate extension/profile. The claimant witness is `[signature, preimage, claim_script, control_block]`; the refund witness is `[signature, refund_script, control_block]`.

### 5. BTC→LN authorization

The user MUST validate and accept the invoice/terms, persist independently usable refund recovery data, and then fund the contract. The provider MUST independently verify the funded amount/script and confirmation policy before initiating Lightning payment.

The provider MUST bound its latest possible outgoing HTLC exposure so that it retains a claim-confirmation margin before R. Payment RPC timeout or cancellation of further attempts MUST NOT be treated as proof that no in-flight payment can settle.

A successful provider obtains the preimage and claims through either path. A user MUST NOT issue a cooperative partial that bypasses the provider's required claim authority. A validated preimage demonstrates existing unilateral claim authority; it does not by itself mean that the UI independently observed a Lightning receipt.

The invoice receiver's secrecy before payment is an assumption of this flow. A third-party receiver that gives the secret to the provider can invalidate the user's expected payment relationship.

### 6. LN→BTC authorization

The user MUST persist the secret and unilateral-claim key before paying. The provider creates a hold invoice for the agreed hash and MUST observe a fully accepted payment with sufficient HTLC expiry margins before funding. The earliest relevant accepted part controls the incoming expiry budget.

Before preimage release, the user MUST verify the contract, funding outpoint/value, confirmation evidence, remaining claim time, and an economically viable, valid unilateral claim. It MUST persist the necessary signing/recovery data.

The provider MUST NOT issue a cooperative partial that enables the user to claim before the provider has the preimage and a safely settleable held payment. Following preimage disclosure, the user MUST ensure timely claim confirmation even if cooperation ceases.

If the provider refunds, it MUST obtain the required refund-resolution evidence before canceling the held invoice. Refund eligibility alone is not sufficient: the claim branch remains independently valid.

### 7. Deadline relationships

Let E_out be the latest actual outgoing HTLC exposure; E_in the earliest relevant incoming expiry; h the validated chain tip; and R the first eligible refund block. Required relationships are:

```text
BTC→LN: E_out + learn-and-claim margin < R
LN→BTC: R + refund-and-LN-resolution margin < E_in
reveal: h + claim-confirmation margin < R
```

Margins MUST account for the implemented backend's behavior, force-close resolution, observation delays, confirmation targets, and fee escalation. Admission MUST additionally budget funding confirmation and client action time. This proposal does not supply universal production constants.

### 8. Cooperative signing

The parties MAY cooperatively create a BIP327 signature for an exact approved key-path claim. Each attempt binds contract, network, prevout data, transaction, role, participants, and a unique attempt identifier before nonce creation. Partial and final signatures MUST be checked.

Secret MuSig nonces MUST NOT be copied, serialized, reused, restored, or reconstructed for a retry. Restart abandons unfinished attempts; transaction replacement requires new nonces. Implementations MAY store public nonces and previously computed public partial signatures for retransmission.

Cooperative failure MUST NOT remove unilateral recovery. The protocol does not promise fairness of exchanging the preimage for a cooperative signature.

### 9. Recovery

Before principal commitment, implementations MUST make independently usable recovery material durable and available for export. It includes the network/profile, contract, relevant key/secret material, destinations, timeout, and information sufficient to discover and spend the funding output. After funding/replacement, records MUST be updated with known outpoints/transactions.

Recovery MUST NOT require an available provider API, discovery system, original website, old browser origin, or live cooperative signer. Secret MuSig nonces and node credentials MUST NOT be exported. RS-007 defines the versioned canonical recovery object and age-encrypted interchange container; exact fixtures are required before stable interoperability.

### 10. Failure semantics

Provider messages are hints until independently verified where funds are at risk. Restart MUST reconcile ambiguous actions using the relevant chain/LN backend. Revealed-secret knowledge cannot be rolled back by a reorg or database replay.

Fees, lockup, and availability are distinct from principal safety. Optional prepayments MUST be separately identified, capped, and disclosed as potentially irrecoverable. No implementation may advertise safety against arbitrary censorship, unbounded fees, arbitrary reorgs, or missed monitoring deadlines on the basis of this profile.

### 11. Discovery and provider/client wire protocol

The Bitcoin construction above does not require Nostr. The accompanying
RillSwap binding uses ordinary [NIP-01 events and relay WebSocket
messages](https://github.com/nostr-protocol/nips/blob/master/01.md),
[NIP-44 v2 encryption](https://github.com/nostr-protocol/nips/blob/master/44.md#version-2),
and [NIP-59 gift wrapping](https://github.com/nostr-protocol/nips/blob/master/59.md#protocol-description).
The current binding is `nostr-experimental-1`, with communication suite
`nostr-nip44v2-nip59/v1` in the advertisement's `communication_suites`:

| Kind | Purpose and format | Published to relays? |
|---|---|---|
| `39417` | Provider-identity-signed addressable announcement. Tags are exactly `[["rillswap","nostr-experimental-1"],["network",N],["d",D]]`; `content` is the canonical JSON string of `{"advertisement":{...},"signature":"..."}`. | Yes, public discovery. |
| `21417` | Unsigned application rumor, with tags exactly `[["rillswap","nostr-experimental-1"]]` and the canonical RS-001 envelope JSON string in `content`. | No, encrypted inside the seal. |
| `13` | Sender-session-key-signed NIP-59 seal, empty tags, NIP-44 v2 encrypted rumor JSON in `content`. | No, encrypted inside the gift wrap. |
| `1059` | NIP-59 gift wrap signed by a fresh one-time key, recipient `p` routing tag, NIP-44 v2 encrypted seal JSON in `content`. | Yes, encrypted session traffic. |

Kinds `39417` and `21417` are project-local experimental choices, not NIP
allocations or collision-free reservations. Kinds `13` and `1059` are defined
by NIP-59. Announcement addressing uses NIP-01's `(kind, pubkey, d)` semantics
(formerly [NIP-33](https://github.com/nostr-protocol/nips/blob/master/33.md)).
Here `N` is the coarse network name and `D` is the SHA256 of the canonical
`["rillswap", binding_version, network_identity, slot]` tuple; clients still
verify the complete signed network identity. See [RS-005](../specs/RS-005-discovery.md)
for the exact advertisement schema, signatures, expiry and revision rules.

The client subscribes to announcements with a NIP-01 `REQ` filter such as
`{"kinds":[39417]}`. Each peer subscribes to its own encrypted inbox using
`{"kinds":[1059],"#p":["<recipient-xonly-key>"]}`. Senders publish
`["EVENT",event]`; relays deliver `["EVENT",subscription_id,event]`.
Neither relay `OK` nor the end-of-stored-events marker `EOSE` means that the
counterparty processed a swap message.

The client sends `handshake_init` from a fresh session key to an advertised
provider epoch inbox, without an invoice or payment hash. The provider sends
`handshake_accept` from its fresh session mailbox to the client's mailbox;
an application signature by the previously advertised provider identity binds
the handshake and both session keys. The client sends `handshake_confirm` to
that provider session mailbox. Only then may they exchange `quote_request`,
`quote_offer`, `terms_offer`, `terms_accept`, and profile-specific funding,
observation and action messages inside kind-1059 gift wraps.

The handshake's `requested_encryption_suites` and `selected_encryption_suite`
are separate from the advertised communication suite. Reference handshakes
currently use `noise-xk-secp256k1-chachapoly-sha256/v1` as their negotiation
token, but do not run a Noise handshake or ratchet. Actual wire encryption is
NIP-44 v2 inside NIP-59; that token does not add security properties.

After decryption, the rumor's `content` is an RS-001 envelope binding protocol
and wire version, profile, complete network, session and logical message IDs,
sender session key, sequence, reply correlation, contract hash, message type,
payload, required features, extensions and application signature. NIP-59's
unsigned rumor does not remove RillSwap's application signatures. Application
retransmissions keep the same logical message and sequence but use fresh
encryption and wrappers; relay delivery never authorizes a financial effect
on its own.

[RS-001](../specs/RS-001-wire-and-types.md) defines the exact application
objects, authentication and replay rules.
[RS-006](../specs/RS-006-nostr-transport.md#protocol-overview) gives the
event layouts, relay frames, mailbox routing and handshake sequence, including
the optional [NIP-13](https://github.com/nostr-protocol/nips/blob/master/13.md)
outer-event proof of work. The accompanying [NIP draft](nip-rillswap.md)
summarizes this application binding; it is not an assigned NIP.

## Security considerations

The security model includes malicious counterparties, relays, chain-data services, compromised UI delivery, and accidental crashes. It excludes compromised signing devices/keys and assumes the stated chain, fee, Lightning, and monitoring conditions.

Particular hazards are internal-key substitution, mismatched hash/preimage length, premature preimage release, provider partial signatures issued before payment authorization, insufficient HTLC margin, refund/claim races, duplicate deposits, stale/replayed economic terms, nonce misuse, unexpected transaction outputs, and privacy leaks through funding clusters or remote observation.

A browser verifying scripts is not itself a fully validating Bitcoin node. Implementations MUST expose the chain-data trust model. Cooperative key-path settlement avoids revealing the script leaves on-chain, but does not hide amounts, timing, provider knowledge, or all funding relationships.

## Rationale and alternatives

Separate profiles make preimage ownership and commitment ordering explicit. The initial construction prioritizes ordinary BOLT11 wallet compatibility and enforceable script fallbacks. HTLC-first forward flows and adaptor/PTLC constructions have different operational requirements and should not be disguised as interchangeable messages.

Using a two-party internal key permits private cooperative claims without allowing either participant an independent key-path spend. The exact tree is normative to make full client reconstruction possible.

## Backward compatibility

No Bitcoin consensus or Lightning wire change is required. Existing swap-provider APIs are not automatically compatible. Adapters must preserve the actual upstream profile; creating a new Taproot-facing contract over a different market requires a separately funded participant and/or a separately analyzed composition.

## Reference implementation and vectors

The reference implementation is <https://github.com/rillswap/rillswap>: `rill-core` (Python protocol library), `rill-crypto` (libsecp256k1 binding), `rill-provider`, `rill-cli` and `rill-web` (independent TypeScript client). Vectors live in `rill-docs/vectors/`.

The vectors cover the Taproot contract, MuSig2 signing, settlement transactions, canonicalization, wire messages, discovery, and recovery files. An optional suite executes the contract spends against a pinned Bitcoin Core version.
