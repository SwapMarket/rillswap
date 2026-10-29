# RS-001: Wire format and protocol types

Status: draft

Version: `0.1.0-pre.1`

## 1. Encoding

Application objects are UTF-8 JSON. Before signature or hash calculation they
MUST be serialized with RFC 8785 JSON Canonicalization Scheme. Parsers MUST
reject duplicate object keys before constructing a value.

Protocol values MUST NOT contain JSON floating-point numbers. Satoshi and
millisatoshi values are canonical decimal strings matching `0|[1-9][0-9]*`.
Values MUST be no greater than 2,100,000,000,000,000 satoshis or exactly 1,000
times that bound in millisatoshis. Contract and invoice amounts MUST be
positive. Success and service fees are signed: they match `0|-?[1-9][0-9]*`
(never `-0`), have the same magnitude bound, and are negative when the provider
pays a rebate. Every other amount is unsigned. Heights, timestamps, revisions, and sequence
numbers are JSON integers in the range 0 through 9,007,199,254,740,991.

Binary identifiers are lowercase hexadecimal without a prefix. Fixed-size
identifiers MUST have the exact encoded length required by their type. Parsers
MUST reject uppercase or odd-length hexadecimal.

Objects reject unknown members except in `extensions`. An extension key MUST
be a bounded, lowercase, reverse-domain namespace followed by `/` and a name.
Unknown required features make a message invalid. Unknown optional extensions
MUST NOT change base-profile safety behavior.

Implementations MUST enforce these resource limits before expensive work:

* JSON nesting depth: 16;
* object members: 128;
* array members: 256;
* ordinary strings: 16,384 UTF-8 bytes;
* decoded application object: 16 KiB;
* transport outer event: 128 KiB.

## 2. Network identity

`NetworkIdentity` has exactly these members:

```json
{
  "family": "bitcoin",
  "name": "mainnet|signet|regtest|testnet3|testnet4|custom",
  "genesis_hash": "32-byte lowercase hex in display order",
  "signet_challenge": "lowercase script hex or null",
  "consensus_profile": "bounded versioned identifier",
  "deployment_namespace": "bounded identifier or null"
}
```

Mainnet, regtest, testnet3, and testnet4 identities MUST use a null signet
challenge. Signet identities MUST bind the exact challenge. Regtest identities
MUST have a nonempty deployment namespace. Implementations MUST compare the
entire object, not a label or genesis hash alone.

## 3. Application envelope

Every application message has exactly these base members:

```text
protocol             "rillswap"
wire_version         "1"
profile_id           "btc-to-ln/v1" or "ln-to-btc/v1"
network_identity     NetworkIdentity
session_id           32-byte random value
message_id           32-byte random logical-message value
sender_session_key   32-byte x-only BIP340 public key
sequence             nonnegative integer
in_reply_to           previous message_id or null
contract_hash        32-byte value or null
message_type         registered type
payload              type-specific object
required_features    sorted unique feature identifiers
extensions           namespaced extension object
signature            64-byte BIP340 signature when required, otherwise null
```

`session_id`, sender keys, profile, version, and network are fixed by the
authenticated handshake. Sequence numbers start at zero and increase by one
per sender. A receiver MAY buffer a bounded future window but MUST reject a
duplicate logical message whose canonical unsigned contents differ. Replayed
messages produce the previously recorded logical result and MUST NOT repeat a
financial effect.

Retransmission uses the same `message_id` and application bytes but a new
transport wrapper and encryption randomness. Relay acceptance is not an
application acknowledgment. An acknowledgment is not evidence that a
financial effect succeeded.

## 4. Hashes and signatures

`TaggedHash(tag, message)` is SHA256(SHA256(tag) || SHA256(tag) || message).
Tags are exact UTF-8 strings and are protocol-versioned:

* contract hash: `RillSwap/contract/v1`;
* provider terms signature: `RillSwap/provider-terms/v1`;
* client acceptance signature: `RillSwap/client-acceptance/v1`;
* handshake signature: `RillSwap/handshake/v1`;
* authenticated envelope: `RillSwap/envelope/v1`;
* advertisement: `RillSwap/advertisement/v1`;
* funding binding: `RillSwap/funding-binding/v1`;
* recovery authorization: `RillSwap/recovery-authorization/v1`.

The additional exact hash domains are:

* handshake initiation: `RillSwap/handshake-init/v1`;
* invoice representation: ordinary untagged SHA256 as defined in section 5;
* application transcript: `RillSwap/transcript/v1`.

A signature message is the tagged hash of canonical bytes of the exact object
defined for that signature. The `signature` member itself is omitted from the
signed object, not set to null. BIP340 verification uses the stated identity or
session x-only public key.

## 5. Invoice and economic binding

Version 1 accepts only fixed-amount BOLT11 invoices whose millisatoshi amount
is exactly divisible by 1,000. The canonical invoice representation is the
lowercase ASCII BOLT11 string after rejecting mixed-case input. Its
`bolt11_sha256` is ordinary SHA256 of those bytes. Implementations MUST decode
and verify the invoice signature, network, amount, payment hash, payee, creation
time, expiry, and minimum final CLTV delta. The invoice binding contains exactly:

```text
bolt11_sha256, payment_hash, amount_msat, payee_compressed_pubkey,
created_at, expires_at, min_final_cltv_delta
```

The selected invoice itself is delivered only inside the authenticated
session. Its recomputed binding MUST equal the signed terms. An invoice that is
expired or does not leave the negotiated timing budget cannot be accepted.

Economics is a closed discriminated object. For BTC to LN, let `L` be
`lightning_principal_sat`, `S` be `success_fee_sat`, and `V` be
`contract_amount_sat`. The object contains exactly those three fields and MUST
satisfy `V = L + S`, where a negative `S` is a provider rebate and `V` MUST
still be positive; the invoice amount MUST equal `L * 1000` millisatoshis.
Funding and possible refund mining fees are paid separately and MUST NOT reduce
`V`. Mining prepayment is not valid for this direction.

For LN to BTC, let `V` be `contract_amount_sat`, `D` be
`nominal_payout_sat`, `C` be `claim_fee_reserve_sat`, `S` be
`success_fee_sat`, `M` be `mining_prepayment_sat`, and `H` be
`hold_invoice_sat`. The object contains exactly those six fields and MUST
satisfy `V = D + C`, `0 <= M <= max(S, 0)`, and `H = V + S - M`, so a rebate
(`S < 0`) forbids a prepayment. The invoice amount
MUST equal `H * 1000` millisatoshis. The total successful Lightning payment is
`M + H = V + S`, excluding wallet routing fees. `M` MUST be zero unless the
named mining-prepayment extension is explicitly offered and accepted.

All equations are evaluated with arbitrary-precision signed integers and
then checked against the protocol monetary maximum. Overflow, underflow,
fractional satoshis, zero principal, zero contract value, and a zero invoice are
invalid.

## 6. Contract terms and acceptance

The contract terms object is independent of transport and contains exactly:

```text
protocol, contract_version, profile_id, network_identity,
provider_identity_key, client_contract_compressed_key,
provider_contract_compressed_key, claimant, refund_party, invoice_binding,
economics, refund_lock_height, funding_confirmations,
settlement_confirmations, refund_resolution_confirmations,
max_funding_fee_sat, max_claim_fee_sat, max_refund_fee_sat,
client_destination_script, provider_destination_script,
recovery_authorization_xonly_key, terms_expiry, timing_policy,
required_features, extensions
```

The identity, recovery-authorization, and session keys are 32-byte x-only
BIP340 keys. Contract aggregation keys are valid 33-byte compressed SEC keys;
their role-specific x-only forms are derived as RS-002 specifies. Keys assigned
to distinct purposes MUST be distinct.

Keys, roles, amounts, fees, scripts, exact selected invoice digest and decoded
invoice values, timeout,
confirmations, destinations, recovery authorization, profile, and complete
network identity are therefore committed. `timing_policy` records negotiated
block margins, not a claim of universal safety. It is a closed discriminated
object. Every height and block count is a nonnegative exact JSON integer; each
margin named below is at least one block.

For BTC to LN it contains exactly `kind: "btc-to-ln"`,
`max_outgoing_htlc_expiry_height`, `learn_and_claim_blocks`,
`client_response_blocks`, and `claim_confirmation_blocks`. With first refund
block `R = T + 1` and maximum outgoing exposure `E_out`, terms MUST satisfy
`E_out + learn_and_claim_blocks < R`. Admission additionally proves the
funding-confirmation and client-response budget from the observed height.

For LN to BTC it contains exactly `kind: "ln-to-btc"`,
`min_incoming_htlc_expiry_height`, `refund_and_ln_resolution_blocks`,
`client_response_blocks`, and `claim_confirmation_blocks`. With earliest
incoming expiry `E_in`, terms MUST satisfy
`R + refund_and_ln_resolution_blocks < E_in`. Immediately before reveal at
height `h`, the client MUST prove
`h + claim_confirmation_blocks < R`. Actual accepted HTLC expiries MUST be no
earlier than the signed minimum.

`settlement_confirmations` and `refund_resolution_confirmations` are exact
JSON integers of at least one. `funding_confirmations` is an exact JSON
integer of at least one for LN to BTC, where the client reveals the preimage
on that depth, and of at least zero for BTC to LN, where only the paying
provider bears the funding risk (RS-003).

`contract_hash` is `TaggedHash("RillSwap/contract/v1", JCS(contract_terms))`.
`ProviderTermsV1` contains exactly `contract_hash`, `contract_terms`, and
`handshake_hash`. Its `provider_terms_signature` is made by the provider
identity key using `RillSwap/provider-terms/v1`. `ClientAcceptanceV1` contains
exactly `contract_hash`, `handshake_hash`, `session_id`,
`client_session_xonly_key`, and `provider_session_xonly_key`. Its
`client_acceptance_signature` is made by the client session key using
`RillSwap/client-acceptance/v1`. Each signature is a sibling wire member and is
omitted from its signed object. Terms MUST be unexpired at acceptance. Both
closed signed objects are retained for recovery verification.

Funding outpoints are not part of initial terms. `FundingBindingV1` contains
exactly `contract_hash`, `funding_attempt_id`, `binding_revision`, `funder_role`,
`lineage_anchor_txid`, `lineage_anchor_vout`, `funding_txid`, `contract_vout`,
`contract_value_sat`, `contract_script_pubkey`, `replaces_txid`, and
`created_at`. Revision starts at zero and increases by one. The BTC to LN client
or LN to BTC provider, respectively, signs it with its authenticated session
key using `RillSwap/funding-binding/v1`.

Every funding transaction in one attempt MUST spend the same lineage anchor
outpoint, making valid versions mutually exclusive, and contain exactly one
output matching the contract value and script. A replacement MUST identify the
previous transaction, conflict by spending the anchor, and preserve the exact
contract output. The receiver independently retrieves the transaction, checks
all inputs and outputs, validates the conflict and revision chain, and checks
best-chain or mempool status. A stale binding cannot change an already accepted
best-chain outpoint. A transaction not spending the anchor is a separate extra
deposit, never a replacement or automatic additional claim.

## 7. Handshake

`HandshakeInitV1` contains exactly `protocol`, `wire_version`, `profile_id`,
`network_identity`, `session_id`, `client_challenge`,
`client_session_xonly_key`, `expected_provider_identity_xonly_key`,
`requested_encryption_suites`, `requested_capabilities`, `required_features`,
and `extensions`. Every session is epoch-bound (section 7.1): its session ID
is derived from the provider epoch, and the client challenge is an independent
random 32-byte value. `handshake_init_hash` is the handshake-init tagged hash
of this object.

`HandshakeAcceptV1` contains exactly `handshake_init_hash`, `protocol`,
`wire_version`, `profile_id`, `network_identity`, `session_id`,
`client_challenge`, `provider_challenge`, `client_session_xonly_key`,
`provider_session_xonly_key`, `provider_identity_xonly_key`,
`selected_encryption_suite`, `selected_capabilities`, `transport_endpoints`,
`required_features`, and `extensions`. The provider signs this exact object
with its identity key using `RillSwap/handshake/v1`; the signature is a sibling
member and omitted from the signed object.

The client obtains the expected provider identity from a manually verified
fingerprint or a previously validated signed advertisement and MUST compare it
to both handshake objects. A signature by a key first declared inside the same
handshake is not provider authentication.

`handshake_hash` is `TaggedHash("RillSwap/transcript/v1",
JCS({"accept": HandshakeAcceptV1, "init": HandshakeInitV1}))`. The member order
shown is not significant before JCS. `HandshakeConfirmV1` contains exactly
`handshake_hash`, `session_id`, `client_session_xonly_key`, and
`provider_session_xonly_key` and is signed by the client session key using the
envelope tag. No economic message is valid before confirmation.

Negotiation fails on network mismatch, reused challenge, unsupported suite or
profile, downgrade, unknown required feature, bad signature, or expired
advertisement. Session and contract keys MUST be distinct.

### 7.1. Epoch-bound admission

`epoch-bound-session/v1` is a mandatory handshake feature: every session is
admitted through a finite-lifetime provider epoch. It does not change the
closed handshake wire shape. Both initiation and acceptance MUST list the
feature in `required_features`; a handshake half without it is refused, and
there is no unbound admission. The initiation MUST
carry `extensions["rillswap/epoch-bound-session"]` with exactly
`{"epoch_inbox_xonly_key": <recipient epoch x-only key>}`. The client MUST use
a fresh session key and an independent random client challenge.

Its session ID is the lowercase hex encoding of:

```text
TaggedHash("RillSwap/epoch-bound-session/v1", JCS({
  "network_identity": <complete NetworkIdentityV1>,
  "provider_identity_xonly_key": <expected provider identity>,
  "epoch_inbox_xonly_key": <recipient epoch key>,
  "client_session_xonly_key": <fresh client session key>
}))
```

The three keys MUST be distinct, canonical secp256k1 x-only keys. The provider's
selected session key MUST also differ from the retiring epoch key. This static
binding is not evidence that the epoch is active or belongs to the provider.
Before reserving any new challenge, a live provider MUST authenticate the actual
recipient epoch, require it to equal the declared epoch, and establish that it
has not durably retired. Missing provenance never authorizes admission.

Within an admissible epoch, exact initiation replays MUST reuse the recorded
result. A provider MUST NOT discard that replay protection merely because the
session is idle while the epoch remains admissible. Once the epoch is durably
retired, a provider MAY expire idle pre-economic sessions without lifetime
session-ID tombstones. Retired epochs MUST NOT reopen after a clock rollback;
rewrapping the old initiation for another epoch MUST be refused. Expired
pre-economic transcripts are refused, never issued another accept.

This exception does not permit retiring accepted contracts or payment-hash
reservations. An epoch extension without the feature is refused, never
treated as an unbound session.

Every session ID commits to its epoch and a retired epoch never reopens, so a
pruned session ID cannot be admitted again. Per-epoch tombstone limits MAY
refuse new sessions until retirement frees capacity; they MUST NOT delete
replay protection early to make room.

Retirement MUST NOT make a formerly used epoch key eligible for reuse. Providers
retain a public epoch-key history across rotations and upgrades. Unlike
temporary session tombstones, this history grows with provider-controlled key
rotations and is not bounded total storage. Retired epoch secret keys need not
remain available.

Clients select the epoch from the provider's signed advertisement (RS-005).
Offline recovery requires the binding and validates it as historical evidence;
it does not require the epoch to remain active.

## 8. Message authentication, ordering, and effects

`handshake_init` is unsigned. `handshake_accept` uses the provider identity
signature above. `handshake_confirm` uses the client session key. Every later
application envelope, including acknowledgments and errors, MUST carry the
RS-001 envelope signature from the role-labeled sender session key. Terms and
funding payloads additionally carry their purpose-specific signatures. A
message received under the wrong sender role or key is invalid.

Handshake messages use the ordinary envelope shape. The client
`handshake_init` envelope has sequence zero, null `in_reply_to`, and null
envelope signature. Its payload is exactly `HandshakeInitV1`. The provider
`handshake_accept` envelope has sequence zero, replies to the init message, and
has a null envelope signature. Its payload has exactly `accept` containing
`HandshakeAcceptV1` and `provider_identity_signature` containing the signature
over that inner object. The client `handshake_confirm` envelope has sequence
one, replies to the accept message, carries exactly `HandshakeConfirmV1` as its
payload, and signs the entire unsigned envelope with the client session key and
the envelope tag. The signature member is omitted from those unsigned envelope
bytes. The first later client message uses sequence two; the first later
provider message uses sequence one.

Every received accept field MUST equal the corresponding initiation field or a
single selection from what it offered. Selected capabilities MUST be a subset
of requested capabilities, the selected suite MUST be requested, echoed values
MUST match exactly, and all required features MUST be understood.

For each `(session_id, sender_session_key)`, sequence numbers are contiguous.
A receiver may durably buffer a bounded future
window but MUST NOT process a message or authorize an effect across a gap.
`message_id` and sequence are each unique in that sender stream. Reuse of either
with different canonical unsigned envelope bytes is a transcript conflict and
halts new financial risk. An exact replay returns the durable recorded logical
result.

A response `in_reply_to` MUST identify a previously processed request in the
same session and opposite sender stream. `quote_request` and `action_request`
may initiate an exchange with null `in_reply_to`. Profile-registered
observations and funding bindings are unsolicited and also use null. All other
responses identify their initiating message. An `ack` identifies the message
whose durable receipt it acknowledges and is delivery state only; it is not the
terminal financial result. A request has at most one terminal `action_result`
or profile-defined terminal result even if that result is retransmitted.

The receiver durably records the canonical digest, sequence disposition,
state revision, logical result, and any effect intent atomically before an
external effect. Network calls occur afterward. The result or reconciled
observation is then appended. A crash, duplicate, or timeout resumes or
reconciles the existing intent rather than issuing a new effect.

## 9. Registered messages

Version 1 reserves: `handshake_init`, `handshake_accept`, `handshake_confirm`, `quote_request`,
`quote_offer`, `terms_offer`, `terms_accept`, `funding_binding`, `observation`,
`action_request`, `action_result`, `ack`, and `error`. Profile specifications
define allowed state-dependent payloads. `error` messages contain stable codes
and redacted text and never reveal a decryption or parsing oracle.

The schemas directory defines structural validation. This specification and
the profile documents define contextual validation and take precedence when a
schema cannot express an invariant.
