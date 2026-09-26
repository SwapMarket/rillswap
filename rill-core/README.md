# rill-core

Pure Python RillSwap protocol domain plus separately installable adapters.

The core package performs no network, disk, clock, database, or notification
side effects. It validates messages and observations, reduces verified events,
and returns explicit permitted effects.

`wire.verify_static_signed_envelope` parses bounded strict JSON bytes and
checks one post-init/accept envelope signature against caller-supplied session,
profile, complete network, sender key, and supported features. It returns only
the canonical unsigned digest. The caller must derive these expectations from
an independently authenticated session and durably enforce RS-001 sender role,
handshake confirmation, message order, replay/conflict handling, response
linkage, and effect intent **before** any external action. In particular, a
valid `handshake_confirm` envelope signature is not proof that its payload was
accepted or delivered, and the digest is never funding or payment authority.
Older or absent session records do not establish an empty history.
`wire.verify_static_handshake_transcript` checks the three typed RS-001
handshake envelopes against independently supplied provider identity, profile,
network, and supported negotiation values. It verifies the identity-signed
inner acceptance and client-session-signed confirmation, returning only the
transcript hash. Init and accept outer wrappers are unsigned, so matching
their linkage does not authenticate their delivery. A previously signed
historical transcript passes this static test again: a host still needs its
own durable pending challenge, locally owned provider key, receipt ordering,
and replay policy before any session is established or any effect is allowed.

The settlement package reconstructs RS-002 Taproot contracts and builds,
finalizes, parses, and authorizes unilateral claim/refund transactions. BIP340
signing stays outside core behind explicit key-operation and verifier protocols.
Callers must supply authenticated contract terms, a correct key-operations
implementation, and independently observed live funding outpoint data. Core
authorization is not chain confirmation or current mempool acceptance.

Funding-plan authorization compares version-two raw transaction bytes to an
exact local wallet plan: declared native witness inputs, one common lineage
anchor, the unchanged contract output, exact approved other outputs, and the
signed funding fee cap. It also accepts canonical unsigned or witness-bearing
serialization. The plan's prevout values and scripts are declarations, not
UTXO evidence; witness presence is not signature validity. A funding-plan
match must never be treated as authorization to pay, reveal a preimage, or
claim another deposit. Replacement lineage and extra-deposit reconciliation
require separately verified, durable observations.

`domain.funding_lineage` records accepted binding revisions separately from
reversible best-chain observations. It only accepts facts already authenticated
and independently checked by a host against live transactions and the current
chain view. A previously accepted revision may win on-chain even after a later
replacement was signed. Reorg invalidation removes the exact chain observation,
not the binding history. `require_funding_confirmations(terms)` checks the
entire signed-term hash and requires the caller-verified current best-chain
view to reach the signed depth in either direction; it returns that exact
observation, not an action token. An older immutable lineage object can still
hold a now-stale view, so the host must serialize chain validation and action
decisions and fence stale instances. No reducer state permits funding, payment, settlement,
or recovery import by itself: storage, export verification, and any restored
state must be validated by separate boundaries. Missing or partial history
must not trigger an automatic rescan or reconstruct chain confirmation.

`settlement.check_funding_binding_transaction` matches bounded transaction
bytes to expected contract terms and a binding's txid, anchor input, exact
contract output, and supported output script types. It does **not** verify the
funder's binding signature, the wallet's approved inputs or other outputs,
input amounts and fees, prior revisions, live chain/mempool/UTXO state, or
funding-export safety. Hosts must verify those facts independently before
adding a binding to a lineage; a byte match is not funding authorization.

`recovery.inspect_recovery_plaintext` accepts canonical UTF-8 RS-007 plaintext
bytes and a required expected network. It verifies static signed context,
preimage/key consistency, Taproot reconstruction, and signed binding order,
then returns only a redacted offline inspection report with explicit missing
evidence. It neither decrypts age nor proves externally trusted provider
identity, handshake confirmation, live funding, export durability, or snapshot
freshness. The 128 KiB document limit and scan birthday at or before refund
height are conservative local inspection constraints; they are not evidence of
irrecoverability for a rejected package. Unsupported features, older/partial
formats, and unknown state never authorize migration, scanning, signing,
funding, payment, or broadcast. Both BTC-to-LN and base-profile LN-to-BTC
recovery fixtures are copied from pinned `rill-docs` commits and exercise native
signature verification when opted in. First canonicalize their decoded objects;
the pretty-printed file bytes are not age plaintext or verified BOLT11 invoices.

`recovery.inspect_recovery_successor` additionally validates two canonical
plaintext snapshots offline. It returns only a redacted report when immutable
fields are identical and the supplied candidate retains the prior binding
prefix, known preimage, issued-signature knowledge, and scan coverage. It
compares **only** the explicitly supplied prior snapshot. A restored file or
unknown sibling can hold more knowledge. Success never proves freshness,
global reconciliation, durability, or permission to fund or pay. It does not
replace authoritative persisted client-state reconciliation or update files.
`recovery.inspect_recovery_selected_funding_binding` requires an exact attempt
ID and revision, validates the complete selected RS-007 plaintext and every
signed history entry first, then returns just the selected immutable public
`FundingBinding`. It never infers the latest record, exports the secret or
preimage, or proves transaction existence, current inclusion, UTXO state, or
freshness. Missing/older/restored histories give no absence or action proof.
`recovery.inspect_recovery_selected_funding_context` additionally projects
only those public signed contract terms needed to reconstruct and check the
selected transaction bytes. It does not return private recovery fields, an
authenticated provider admission, or a chain observation.
Signed public terms may contain arbitrary extension values, and their frozen
model does not deep-freeze those mappings. Treat the result as ordinary input
data, never a validation capability or safe-to-log report.
`recovery.construct_selected_recovery_refund` is a separately and **explicitly**
invoked BTC-to-LN client-refund-only transaction constructor. It validates the
entire canonical RS-007 snapshot and exact selected signed binding, requires a
caller-supplied exact `FundingOutput` and sampled tip height strictly greater
than the refund lock height, enforces the signed fee cap and destination via
RS-002, signs only inside the secret-bearing boundary, and verifies the
resulting transaction. It returns signed bytes only and never broadcasts or
changes state. The caller's chain data is not certified by Core: an earlier
read-only observation is staleable and is not permission to broadcast or to
conclude payment failed. The operation rejects the LN-to-BTC user role; that
profile's independent recovery is a separate **claim** flow involving the
preimage. Python secret bytes are not guaranteed erased from memory.
`recovery.construct_selected_recovery_claim` is a separate, explicitly invoked
LN-to-BTC **client pre-disclosure preparation** function. It checks the full
signed record and selected binding, the caller-supplied exact outpoint,
minimum signed funding confirmations, and the signed timing condition
`sampled_tip_height + claim_confirmation_blocks < refund_lock_height + 1`.
It reuses RS-002's authenticated destination, fee cap, and final BIP340
signature checks. **Its returned signed transaction bytes contain the client
preimage in the claim witness.** Do not print, transmit, publish, or submit
those bytes to Core without a separate independent disclosure decision,
confirmed funding and fee viability, and durable recovery planning. Caller
samples are untrusted; success does not prove chain freshness or payment state.
The function performs no IO, RPC, broadcast, or persisted-state update. Its
pre-disclosure deadline is not a general veto on an urgent claim after the
preimage has already been exposed.

`settlement.verify_static_signed_funding_binding_history` is an explicit
effect-free check of nonempty signed funding declarations. Its caller supplies
an expected provider identity and complete network from an **independent**
trusted source, plus typed handshake/terms context and a crypto adapter whose
Schnorr verifier raises on invalid signatures. It checks transcript and
purpose-key consistency, the three signed context objects, reconstructed
Taproot script, role-selected binding signatures, and contiguous replacement
history. This is static signature consistency, **not** confirmation that the
handshake was delivered or accepted in order, that a funding transaction or
approved anchor exists, that an outpoint is unspent, or that a watch or action
is authorized. Validation-bypassing Pydantic construction is not an accepted
input path: parse untrusted wire data through strict models first. Recovery
inspection reuses only the binding-history invariant; its self-declared
provider key still does not establish independent provider provenance.

### Network capability versus release permission

Offline funding-byte checks and unilateral transaction construction support
default signet, testnet4, mainnet, and explicitly namespaced default regtest.
The execution policy checks the complete pinned identity, including genesis,
consensus profile, and the default signet challenge. Legacy testnet3 and custom
signets remain parseable wire identities but are not enabled for these actions.

This is offline library support, not permission to fund or broadcast on a public
network. Live provider/CLI adapters remain regtest-only pending their own backend
attestation, recovery, privacy, and release gates. In particular, mainnet funding
is not enabled. Existing serialized regtest records and scripts are unchanged;
no migration, scan, or automatic state transition is performed.

Run local tests with `.venv/bin/pytest -q`. For the native crypto contract test,
install the sibling `rill-crypto/python` package in the test environment, build
its pinned native library, and run:

```sh
RILLSWAP_RUN_NATIVE_CRYPTO=1 \
RILL_CRYPTO_LIBRARY="$PWD/../rill-crypto/tmp/build/librill_crypto.so.0.1.0" \
.venv/bin/pytest -q -m native_crypto
```

The native test is skipped by default and fails rather than skipping when
explicitly enabled without the library or Python binding. Its fixture keys
and deterministic signing randomness are public test data, never funds keys.

Status: pre-release and not suitable for real funds.
