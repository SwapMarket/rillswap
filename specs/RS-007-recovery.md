# RS-007: Recovery package

Status: pre-release draft

Format version: `1-pre.1`

## 1. Container

The plaintext recovery object is canonical UTF-8 JSON conforming to the
versioned recovery schema. It is encrypted as an age v1 binary file using
either one user-provided X25519 recipient or the age scrypt passphrase mode.
Scrypt recipients MUST NOT be mixed with other recipient types. Armor is not
part of version 1.

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
