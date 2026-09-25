```
BIP: ?
Layer: Applications
Title: Taproot Bitcoin-Lightning Atomic Swaps
Authors: [maintainer name and email required]
Status: Draft
Type: Specification
Assigned: ?
License: MIT
Version: 0.1.0
Requires: 65, 327, 340, 341, 342
```

# Draft notice

This is an initial, unassigned engineering draft. It has not been submitted, assigned, audited, or accepted. The author placeholder must be replaced before submission. Byte-level schemas/vectors and reference implementations remain implementation deliverables; this document does not assert their existence. Follow the current BIP 3 process. Source references resolve in `SOURCES.md`. [S23]

## Abstract

This proposal specifies a provider-neutral construction for exchanging Bitcoin on-chain funds and a fixed-amount Lightning payment. A two-leaf Taproot output supplies a preimage-and-signature claim and a timed refund. A two-party aggregate internal key permits a cooperative key-path claim. Directional requirements bind the construction to Lightning payment state, safe preimage disclosure, and independent recovery.

Discovery, message transport, pricing, and wallet implementation are modular. The accompanying RillSwap wire documents define interoperable negotiation and a separate Nostr binding. This proposal introduces no Bitcoin consensus change.

## Copyright

This document is licensed under the MIT license included with this handoff. Third-party specifications and implementations retain their licenses.

## Motivation

An atomic-swap service can disappear while valid transactions remain recoverable. Users therefore need more than a provider API: they need a locally verifiable contract, defined authorization conditions, and recovery data another implementation can consume. Providers need equivalent protection against clients who attempt to claim on-chain value while preventing Lightning settlement.

A common settlement profile enables different transports and discovery systems without weakening the underlying contract. Cooperative privacy must remain optional at execution time: refusal to cooperate cannot eliminate an already valid unilateral path.

## Terminology and scope

A **user** initiates a swap. A **provider** offers the opposite side. A **claimant** is the party authorized to consume the hashlocked branch. A **funder** is the party authorized to consume the timed refund branch. The roles differ by direction.

The initial profile uses BOLT11, an exact 32-byte SHA256 preimage, a fixed invoice amount restricted to whole satoshis, and confirmed Bitcoin funding. It does not support zero-confirmation execution, AMP, keysend, PTLCs, or alternative assets. [S06]

The initial identifiers are `rillswap/taproot-htlc/btc-to-ln/v1` and `rillswap/taproot-htlc/ln-to-btc/v1`. They are proposed identifiers, not claims of compatibility with existing service APIs.

## Specification

### 1. Network binding

Accepted terms MUST identify the Bitcoin network, genesis hash, consensus profile, and signet challenge where applicable. Regtest/test deployments MAY add an application namespace. An implementation MUST NOT infer the complete network identity solely from an address or invoice prefix. Recovery data MUST preserve the same identity.

### 2. Keys and preimage

Each party supplies a fresh valid compressed secp256k1 public key for the swap. The two public keys MUST be distinct and MUST NOT be reused as Nostr identity/mailbox keys. The claim preimage is 32 bytes, with `payment_hash=SHA256(preimage)`.

For BTC→LN, the invoice receiver controls the secret before payment. For LN→BTC, the user generates the secret before the provider creates a hold invoice. Reuse of a payment hash across independently funded swaps is prohibited in this profile.

### 3. Output construction

The aggregate internal key is computed by BIP327 with ordered input list `[user_key, provider_key]`. Apply the BIP341 Taproot tweak committing to exactly two depth-one leaves. Leaf version is `0xc0`; branch hashing and key parity follow BIP341. [S01, S02, S04]

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

Unilateral spends use transaction version 2 and `SIGHASH_DEFAULT`. The contract input sequence is `0xfffffffd`. A claim has locktime 0; a refund has locktime T, the agreed refund height. The first eligible mined refund block is modeled as R=T+1. Exact boundary behavior MUST be tested against Bitcoin Core. [S05]

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

Secret MuSig nonces MUST NOT be copied, serialized, reused, restored, or reconstructed for a retry. Restart abandons unfinished attempts; transaction replacement requires new nonces. Implementations MAY store public nonces and previously computed public partial signatures for retransmission. [S08]

Cooperative failure MUST NOT remove unilateral recovery. The protocol does not promise fairness of exchanging the preimage for a cooperative signature.

### 9. Recovery

Before principal commitment, implementations MUST make independently usable recovery material durable and available for export. It includes the network/profile, contract, relevant key/secret material, destinations, timeout, and information sufficient to discover and spend the funding output. After funding/replacement, records MUST be updated with known outpoints/transactions.

Recovery MUST NOT require an available provider API, discovery system, original website, old browser origin, or live cooperative signer. Secret MuSig nonces and node credentials MUST NOT be exported. RS-007 defines the versioned canonical recovery object and age-encrypted interchange container; exact fixtures are required before stable interoperability.

### 10. Failure semantics

Provider messages are hints until independently verified where funds are at risk. Restart MUST reconcile ambiguous actions using the relevant chain/LN backend. Revealed-secret knowledge cannot be rolled back by a reorg or database replay.

Fees, lockup, and availability are distinct from principal safety. Optional prepayments MUST be separately identified, capped, and disclosed as potentially irrecoverable. No implementation may advertise safety against arbitrary censorship, unbounded fees, arbitrary reorgs, or missed monitoring deadlines on the basis of this profile.

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

Planned repositories are `rill-core`, `rill-crypto`, `rill-provider`, `rill-cli`, and `rill-web`. They are architectural proposals in this handoff, not existing published implementations.

Before stable publication, provide exact serialized valid/invalid vectors for keys, aggregation, tree/control blocks, output scripts, transaction/witness construction, signing, canonical terms, network identity, and cross-client recovery. Execute transactions against a pinned Bitcoin Core version and obtain independent review. Do not substitute plausible-looking example hashes for verified vectors.

## Open editorial/release items

Finalize author identities; complete public review; freeze schemas and signature tags; generate verified vectors; select documented backend/version policies and timeout configurations; complete independent security review. None of these is implied by an unassigned draft header.
