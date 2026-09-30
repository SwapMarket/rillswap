# RS-007: Recovery package

Status: pre-release draft

Format version: `1-pre.1`

## 1. Container

The plaintext recovery object is canonical UTF-8 JSON conforming to the
versioned recovery schema. It is encrypted as an age v1 binary file using
either one user-provided X25519 recipient or the age scrypt passphrase mode.
Scrypt recipients MUST NOT be mixed with other recipient types. Armor is not
part of version 1.

For the pre-release CLI profile, "one recipient" means exactly one X25519
key-wrapping stanza. Zero to four bounded GREASE stanzas (tags ending in
`-grease`) MAY accompany it; they are not additional decrypting recipients.
The scrypt stanza MUST be the only stanza, including no GREASE. The importer
limits the binary header through its MAC line to 8192 bytes, ciphertext to
256 KiB, and canonical plaintext to 128 KiB. A GREASE argument line is at
most 256 bytes and its decoded body at most 1024 bytes. The scrypt work
factor `logN` MUST be no greater than 19 (approximately 512 MiB for the
scrypt allocation, plus process and implementation overhead)
before invoking any KDF. These are conservative RillSwap resource bounds,
not limits imposed by age itself; a rejected file must not authorize an
automatic migration, scan, or funding action. Header preflight does not
authenticate recipients or ciphertext; decryption and static import checks
remain mandatory.
The initial Python CLI can inspect conforming scrypt packages, but passphrase
export remains disabled until its age backend can set a bounded work factor
before encryption. A failed export creates no success state and cannot enable
funding or payment. The X25519 create-only export can emit an explicit successor
snapshot relative to one supplied, fully inspected prior age file, without
replacing that file. It preserves monotonic knowledge only relative to that
chosen snapshot: a valid older/restored file can omit knowledge stored in an
unselected sibling. It does not implement atomic replacement of an active
export, global client-state reconciliation, or authorization to fund, pay,
sign, or broadcast.

Decryptability MUST be independent of browser origin, wallet master key,
provider, discovery, and any hosted RillSwap service. Passphrases are obtained
from a protected prompt or standard input, never a command-line argument.

## 2. Contents

The object binds format/specification versions, creation and update times,
complete network identity, profile, contract terms and signatures, contract
hash, both leaves and control blocks, keys and roles, refund height,
destinations, funding transaction/outpoint and replacement history, chain scan
birthday, fee policy, recovery authorization public key, and the user's
encrypted swap secret material or independently usable derivation data.

It also retains both closed handshake objects, handshake hash, provider
identity signature and expected-identity source, both public session keys,
provider terms object/signature, client acceptance object/signature, and every
accepted funding binding/signature. Communication secret keys are not needed
for verification and are excluded by default.

LN to BTC recovery includes the user preimage from the initial pre-commitment
export. BTC to LN recovery adds a learned preimage when available. The package
MUST NOT include provider credentials, social identity keys, node wallet seeds,
LND macaroons, live communication keys by default, or MuSig secret nonces.

## 3. Lifecycle

The first package is durably exported and verified decryptable before funding
or Lightning payment. It contains enough contract and scan information to find
a later output even though no outpoint exists yet. Each funding transaction or
RBF replacement produces an atomic updated export. Losing an update MUST NOT
erase monotonic knowledge already persisted by the client.

A pre-signed fixed-fee transaction alone is insufficient. Recovery retains the
key and construction data needed to rebuild and sign the correct unilateral
transaction for the actual outpoint and fee environment.

### 3.1 Cooperative claim reservation

Before allocating a BTC-to-LN cosigner nonce, the original live client MUST
publish and verify a create-only encrypted `.cooperating` successor to its
already-funded, already-paid snapshot. Publication failure or uncertainty
abandons cooperation, even if the attempted file exists. Previous recovery
files remain unchanged. The successor adds only the extension
`rillswap/cooperative-claim-reservation`, a closed object containing:

* `version`: the exact integer `1` (not a boolean).
* `proposal`: the complete signed provider RS-001 `cooperative_claim_propose`
  envelope, including all signed fields.
* `signature_hash`: the lowercase 32-byte BIP341 signing digest recomputed from
  the exact authorized claim transaction and selected prevout.

Static inspection authenticates the provider session signature, cooperative
feature/role/context, retained preimage, exact transaction and fee policy, and
exactly one retained funding binding. The wall deadline is positive and the
height deadline is positive and no later than the signed refund height minus
`claim_confirmation_blocks`. Insertion requires the latest recorded binding,
unchanged funding history and monotonic knowledge, prior known preimage, and an
update timestamp strictly before the proposal wall deadline. Every unrelated
extension is immutable. After insertion the reservation is immutable, including
its envelope signature, but valid funding history may still grow. Inspection
then matches the historical binding and succeeds even after expiry or reorg.

The record proves reservation only, not actual nonce allocation or signature
issuance, timely publication, chain validity, or signing authority. The live
handler MUST retain the original readiness deadline and cutoff, consume its
attempt eligibility once, and recheck time and independent funding evidence
after publication. Neither this record nor an absent, older, or restored record
allows signing to resume. Restart abandons cooperation and uses independent
unilateral recovery. No automatic migration or retry is performed.

For the narrowly verified, already-paid BTC-to-LN provider claim,
`dangerous_signature_issued` remains unchanged: its partial enables only the
same dedicated-output spend already authorized by the retained valid preimage.
An existing `true` value MUST remain `true`. This classification does not apply
to other signing flows or waive their authorization and disclosure checks.

### 3.2 Private reverse claim fallback

The extension `rillswap/reverse-claim-fallback` is a closed object containing:

* `version`: the exact integer `1` (not a boolean).
* `funding_binding_hash`: the lowercase 32-byte RS-001 hash of exactly one
  authenticated retained funding binding.
* `transaction`: bounded, nonempty, even-length lowercase hex containing the
  fully signed unilateral reverse client claim, including its preimage witness.

Static inspection requires the LN-to-BTC profile and independently verifies
the transaction against the binding and terms: outpoint, claim ownership,
destination, fee, preimage, script, control block, digest, and native signature.
Insertion selects the latest binding and preserves funding history, monotonic
knowledge, secrets, and unrelated extensions. Private preparation preserves
`dangerous_signature_issued` exactly, including an existing `true`; it is not
signature issuance or preimage disclosure. Once inserted, the artifact is
immutable. Valid funding history may still grow, and an older fallback remains
inspectable without authorizing a replacement output.

The artifact proves only prepared signed bytes. It proves neither payment,
current chain validity, timely or durable encrypted publication, nor permission
to disclose. Independent key-based rebuilding remains available; this fixed-fee
transaction is never the sole recovery path. Missing, partial, older, or restored
records authorize no automatic work, migration, payment retry, or cooperation.
Restart abandons cooperation. The future live flow must separately verify durable
publication and fresh original-session payment/funding authority, then durably
reserve possible preimage disclosure before transmission. This artifact is not
that disclosure reservation and does not enable reverse readiness or cooperation.

### 3.3 Reverse possible-preimage-disclosure reservation

The distinct extension `rillswap/reverse-preimage-disclosure` is a closed object:

* `version`: the exact integer `1` (not a boolean).
* `funding_binding_hash`: the RS-001 hash of exactly one authenticated retained
  binding, matching the private reverse claim fallback.
* `proposal`: the complete client-session-signed `cooperative_claim_propose`
  envelope, including its nonce identifiers, transaction, preimage, and deadlines.

Inspection verifies original reverse roles, session, network, contract, negotiated
features, envelope signature, matching known preimage, and deadline bounds. It
reconstructs and validates the cooperative transaction against the selected binding.
The private fallback must independently pass native verification for that binding.
No stored redundant transaction digest is required. Message IDs remain nonce IDs,
not envelope hashes.

Insertion requires an existing fallback in the predecessor, selects the latest
binding, and leaves funding history, monotonic knowledge, secrets, and unrelated
extensions unchanged. Its timestamp must precede the proposal deadline. Adding a
fallback and disclosure reservation simultaneously is forbidden. Either existing
value of `dangerous_signature_issued` is preserved: an envelope signature and public
nonce are not issuance of a cooperative spend signature. The reservation is immutable
after insertion, including after expiry; valid funding history may subsequently grow
without authorizing a new attempt or changing the historical binding.

This record conservatively means disclosure is possible, even if no transmission
occurred. Signed bytes and recorded timestamps prove neither durable publication nor
its ordering, transmission, receipt, payment, nonce uniqueness, secret nonce custody,
or live signing authority. A live producer MUST acknowledge durable encrypted
publication of the exact successor before any preimage-bearing transmission, then
recheck original-session authority and the original nonrenewing deadline. The format
alone does not implement that live boundary.

Missing markers (including previous-release installations and restored predecessors)
prove nothing and trigger no backfill, payment retry, scanning, cooperation, or other
automatic work. Partial, malformed, and unsupported markers fail inspection rather
than being silently discarded. Valid historical evidence never resumes cooperation
and never disables independently authorized, explicitly selected unilateral recovery.
No format-version bump or migration is required for this named, versioned extension.

## 4. Import and use

The top-level format identifier and specification version are immutable exact
strings. Import performs bounded parsing, schema checks, duplicate-key rejection,
network binding, contract-hash recomputation, full P2TR reconstruction,
signature verification, and consistency checks before any network request.
Import MUST NOT automatically contact a provider, relay, or destination and
MUST NOT reveal a preimage.

Unsupported versions, absent signed context, and partial or older draft records
may be diagnosed offline but MUST NOT authorize signing, broadcast, funding,
payment, settlement, cancellation, or automatic migration.

`inspect` works offline and reports redacted identity, network, profile,
recovery paths, deadlines, and missing observations. A user-selected chain
source can scan from the birthday, validate replacement lineage and outpoints,
construct and sign the appropriate unilateral claim or refund, and broadcast.
Provider authorization is never required.

Static cross-language fixtures cover Python and TypeScript decryption for age
scrypt and X25519 modes, binary boundary content, wrong credentials, tampered
header or payload, malformed recipient data, and forbidden mixed recipient
types.
