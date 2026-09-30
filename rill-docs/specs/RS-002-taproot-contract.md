# RS-002: Taproot contract and transactions

Status: pre-release draft

Version: `0.1.0-pre.1`

## 1. Keys and tree

Each swap uses fresh valid compressed secp256k1 keys `K_user` and
`K_provider`. Duplicate keys are invalid. Aggregate in exact order
`[K_user, K_provider]` with BIP327 `KeyAgg`. Convert the aggregate to its x-only
form and use it as the BIP341 internal key.

Each compressed key is converted to its x-only form only for the role-specific
leaf `OP_CHECKSIG`. Implementations MUST retain the original compressed keys,
aggregate-key cache, x-only internal key parity context, output-key parity, and
tweak context required by BIP327 and BIP341. Invalid points, infinity, an
invalid tweak, or a failed tweak-add make the contract invalid.

There are exactly two tapscript leaves at leaf version `0xc0`. Compute leaf
hashes and lexicographic TapBranch ordering as BIP341 specifies. Apply the
BIP341 TapTweak to the aggregate internal key and exact two-leaf Merkle root.
The resulting output MUST be P2TR. No other leaf, leaf version, annex, or
OP_SUCCESS opcode is allowed.

## 2. Leaves

The claim leaf is:

```text
OP_SIZE <minimally encoded ScriptNum 32> OP_EQUALVERIFY
OP_SHA256 <32-byte payment_hash> OP_EQUALVERIFY
<32-byte claimant x-only public key> OP_CHECKSIG
```

The refund leaf is:

```text
<minimal nonnegative ScriptNum refund_lock_height>
OP_CHECKLOCKTIMEVERIFY OP_DROP
<32-byte refund-party x-only public key> OP_CHECKSIG
```

The payment preimage MUST be exactly 32 bytes. The lock is a block height, not
a timestamp. BTC to LN assigns claimant provider and refund party user. LN to
BTC assigns claimant user and refund party provider.

`refund_lock_height` MUST satisfy `0 < T < 500000000` and all profile admission
margins at acceptance. The script encoding of the number 32 is the two bytes
`0x01 0x20`, a one-byte direct push followed by the minimally encoded ScriptNum.
Payment hash and x-only key pushes use direct 32-byte pushes. The lock height is
the shortest little-endian signed-magnitude ScriptNum with an added zero byte
when needed to avoid a sign bit; heights 1 through 16 use `OP_1` through
`OP_16` as required by minimal-push rules. Zero is not valid for this contract.

Every participant MUST reconstruct and compare the aggregate internal key,
both serialized scripts, TapLeaf hashes, Merkle root, tweaked output key,
scriptPubKey, parity, and both control blocks.

## 3. Funding

The contract output value is exact and MUST NOT be reduced for the funding
fee. Funding inputs MUST be native SegWit or Taproot. Change and destination
outputs in version 1 are restricted to native P2WPKH (`OP_0 <20>`) or P2TR
(`OP_1 <32>`) scripts explicitly present in the signed terms or wallet funding
plan. A wallet MUST NOT add unapproved inputs or outputs. Funding fee is the
sum of validated input values minus all outputs, is nonnegative, and does not
exceed `max_funding_fee_sat`.

One contract has one logical funding attempt. An opt-in RBF replacement MUST
preserve the exact contract output and replacement lineage. A second unrelated
deposit is not a replacement and is reported as an extra exposure. It MUST NOT
be automatically claimed or represented as safely refundable after the common
preimage is revealed.

## 4. Unilateral spends

Initial unilateral claim and refund transactions have:

* transaction version 2;
* exactly one contract input;
* exactly one approved destination output;
* `SIGHASH_DEFAULT` only;
* no annex;
* contract input sequence `0xfffffffd`.

The sole output script is the exact role destination from the signed terms:
provider destination for a BTC to LN claim, user destination for an LN to BTC
claim, user destination for a BTC to LN refund, and provider destination for an
LN to BTC refund. Output value equals contract input value minus transaction
fee, is positive, is not dust under the pinned Bitcoin Core policy, and the fee
does not exceed the corresponding signed maximum. Every signer recomputes the
input, output, role mapping, value equation, fee, version, locktime, sequence,
sighash, witness plan, and all prevout data before signing.

Claim locktime is zero. Its witness is `[signature, preimage, claim_script,
control_block]`.

Refund locktime is `T`, the contract refund height. Its witness is `[signature,
refund_script, control_block]`. Model the first block in which the refund may
be mined as `R = T + 1`; conformance tests MUST execute the exact mempool and
block boundary against the pinned Bitcoin Core version.

Fee changes alter transaction bytes and require a fresh signature. Recovery
MUST retain the key and construction data needed to rebuild a unilateral spend.
An initial spend or fee replacement retains exactly one contract input and one
approved output. It MUST NOT add wallet inputs, change, or arbitrary outputs.
A replacement spends the same contract outpoint, pays the same role destination
script, reduces only the output by an authorized fee increase, remains within
the fee cap and dust rule, and receives a fresh signature.

`funding_confirmations` is the minimum best-chain depth before the provider may
pay in BTC to LN or the user may sign/reveal in LN to BTC.
`settlement_confirmations` is the minimum claim depth before terminal chain
completion. `refund_resolution_confirmations` is the minimum refund depth
before terminal refund completion in either direction and, for LN to BTC,
before the provider may cancel its hold. Every depth is revalidated
against block hashes immediately before the consequential action. A reorg
removes reversible confirmation evidence but not knowledge already disclosed.

## 5. Cooperative claim

The key path uses BIP327 MuSig2 over the exact BIP341-tweaked aggregate key.
Both parties freeze transaction bytes, all prevout scripts and amounts,
contract hash, network, ordered keys, roles, sighash, and a unique cooperation
identifier before nonce generation.

Secret nonces exist only in one-shot opaque native handles. A durable burned
attempt record is written before handle allocation. A crash abandons the
attempt. Public nonces and a resulting public partial signature may be stored.
A changed transaction or fee requires a new identifier and new nonces.
The BTC-to-LN client's burn is the append-once encrypted reservation described
in RS-007 section 3.1. Its already-paid, exact provider claim does not change
`dangerous_signature_issued`; the reservation never proves signature issuance
or permits signing from recovery. The one-attempt-per-swap limit below still
applies to fee changes in the first release.

The cooperative claim uses transaction version 2, locktime zero, input sequence
`0xfffffffd`, and the same one-contract-input, one-role-destination output, fee,
SIGHASH_DEFAULT, and no-annex authorization policy as a unilateral claim. Its
key-path witness is exactly one 64-byte BIP340 signature. It does not authorize
extra inputs, outputs, or a different destination.

Each signer validates the other public nonce and partial signature. The final
signature MUST verify against the exact tweaked output key before use. Profile
documents define directional authorization conditions. Cooperative failure
MUST immediately leave unilateral recovery available.

### 5.1 Negotiated action payloads (implementation pending)

For **new** swaps, `cooperative-claim/v1` is required in both authenticated
handshake halves and signed contract terms. An accepted older swap without it
continues unilaterally. The claimant (provider for BTC to LN, client for LN to
BTC) initiates a bounded cooperative attempt. Both peers use signed RS-001
envelopes with the same session, network, profile, and contract hash. The
receiver independently checks the claimant/cosigner sender role, message
sequence, exact `in_reply_to`, signed feature negotiation, frozen transaction,
funding state, deadline, and one-shot burn. A parsed payload alone grants no
signing authority.

The closed `action_request` proposal carries `action` =
`cooperative_claim_propose`, a 32-byte `cooperation_id`, lowercase hex
`unsigned_transaction` (60 to 1,000 bytes), the 32-byte `payment_preimage`, a
66-byte `public_nonce`, and nonnegative integer `deadline_at` and
`deadline_height`. Its `in_reply_to` is null. The `action_result` reply either
has the same action and ID with `status` = `declined`, or `status` = `signed`
with the cosigner's 66-byte `public_nonce` and 32-byte
`partial_signature`. A second `action_request` carries `action` =
`cooperative_claim_complete`, the same ID, and the claimant's 32-byte
`partial_signature`. This starts the second request/result pair, so its
enclosing `in_reply_to` is null; the local one-shot signing transition must
still require the exact retained, admitted peer-signed proposal result. The
receipt `action_result` has the same action and ID
and `status` = `verified`. Results refer to their request via the enclosing
envelope's `in_reply_to`. The claimant need not wait for the receipt to finish
or broadcast; a missing receipt never authorizes nonce reuse.

The local attempt has at most 30 seconds and ends before the existing
unilateral broadcast/escalation cutoff (both constraints apply). The first
release permits one cooperative attempt per swap; later fee bumps use fresh
unilateral spends. Both parties burn before allocating a nonce, consume before
revealing a partial, and fall back without extending the budget on refusal,
invalid data, restart, or timeout. For LN to BTC the client first durably
saves a signed unilateral claim; proposal preimage disclosure can settle the
hold, so the provider does not return a partial until it positively reconciles
that settlement. No runtime currently enables these payloads for new swaps.
