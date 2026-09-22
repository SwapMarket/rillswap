# RS-009: Conformance and release profiles

Status: pre-release draft

Version: `0.1.0-pre.1`

Conformance is claimed against immutable specification, schema, vector,
network-definition, dependency, and implementation revisions recorded in a
manifest. A generated schema or a unit test authored with an implementation
does not override normative text.

## 1. Required levels

`core-v1` requires canonicalization, wire/type, complete contract
reconstruction, transaction, state reducer, invalid-vector, and property tests.

`native-client-v1` additionally requires real Bitcoin Core and pinned LND
adapter tests, both unilateral flows, durable secrets, and provider-independent
recovery.

`provider-v1` additionally requires action-journal, reservation, restart,
reorganization, ambiguous-effect, fee/deadline, privacy selection, and
multi-instance deployment tests.

`nostr-v1` additionally requires discovery and transport vectors, malicious
relay behavior, replay, censorship, privacy leakage documentation, and
fail-closed Tor behavior.

`browser-client-v1` additionally requires an independently maintained
TypeScript implementation, cross-language vectors and recovery, real browser
storage/worker flows, static artifact identity, and chain-trust enforcement.

`cooperative-v1` additionally requires pinned native and WASM MuSig builds,
BIP327 and differential vectors, one-shot nonce misuse tests, exact transaction
authorization, crash abandonment, and unilateral fallback.

## 2. Test requirements

All identifiers in `compatibility/TEST-MATRIX.md` are release requirements.
Money-path integration tests use real pinned Bitcoin Core and LND processes;
fake adapters do not satisfy those cases. Regtest block production is explicit
and deterministic. Tests cover both spend paths, exact timeout boundaries,
restarts at effect boundaries, reordered observations, malformed inputs,
short expiries, unknown payment outcomes, relay faults, recovery without any
RillSwap service, and chain-source trust modes.

The two directional reducers have stateful property tests and a bounded model.
The model does not prove adapter correspondence, so each semantic capability
also has real-backend contract tests.

## 3. Release gates

No funded mainnet release may be described as production-ready before signet
trials, reproducible artifacts, complete licensing/provenance review,
independent recovery drills, external review of contract and LND timing,
documented operational limits, stable public event-kind coordination, and
independent security audits. Supporting a mainnet network definition is not
approval to deploy funds.
