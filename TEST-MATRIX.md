# RillSwap E2E and security acceptance matrix

**Status:** proposed tests, not executed results. All IDs are release requirements unless marked later. Run the money paths against real pinned Bitcoin Core and LND; use real relays and a real browser where relevant. The provider repository owns orchestration; each library also runs its local unit/property/vector tests.

## Contract and transaction verification

| ID | Scenario | Required result |
|---|---|---|
| C01 | Python and TypeScript derive the same two-leaf P2TR contract | Identical scripts, root, internal/output keys, address and control blocks |
| C02 | Provider substitutes internal key but presents an honest-looking refund leaf | Client rejects before principal commitment |
| C03 | Extra leaf, malformed control block, wrong parity, bad key aggregation order | Rejected deterministically by both implementations |
| C04 | Wrong hash, 31/33-byte preimage, duplicate/invalid participant key | Rejected before action; invalid script witnesses fail in Core |
| C05 | Wrong amount, network, destination, sighash, annex, or extra output | Rejected before sign/pay/reveal |
| C06 | Boundary heights T−1, T, T+1 | Exact mempool/block results agree with documented refund semantics |
| C07 | Claim after refund eligibility but before a refund wins | Model recognizes claim remains valid; no premature hold cancellation |
| C08 | Fee-bumped claim/refund | Only approved output/fee changes; fresh cooperative attempt when necessary |
| C09 | RBF funding replacement | Exact output preserved; recovery tracks replacement outpoint |
| C10 | Second independent deposit under same hash | No automatic second payment; explicit hazard, no false refund guarantee |
| C11 | Unknown mandatory profile/feature | Fail closed; optional bounded metadata does not mutate safety rules |
| C12 | Amount overflow, JSON duplicate key, bool-as-int, Unicode/canonicalization edge | Rejected or canonicalized identically according to the exact schema |

## Complete money paths

| ID | Scenario | Required result |
|---|---|---|
| F01 | BTC→LN successful cooperative claim | LN receipt and provider claim; only key-path witness on-chain |
| F02 | BTC→LN cooperation refused | Provider script claim succeeds with valid preimage |
| F03 | BTC→LN invoice cannot be paid | User independently refunds after eligible height |
| F04 | BTC→LN payment pending near exposure cutoff | No attempt violating absolute deadline; existing attempt reconciled |
| F05 | LN→BTC successful cooperative claim | User payout and provider LN settlement; exact fee accounting |
| F06 | LN→BTC provider refuses partial after learning preimage | User unilateral claim confirms within agreed assumptions |
| F07 | LN→BTC user disappears before secret release | Provider refund resolves, then held payment cancellation is safe |
| F08 | LN→BTC provider never funds | User payment is not settled; cancellation/timeout handled without fake completion |
| F09 | LN→BTC provider emits usable partial before preimage | Adapter/signing guard forbids action; malicious-provider fixture demonstrates risk |
| F10 | User receives only provider “confirmed” message | No preimage release without required independent chain evidence |
| F11 | User attempts cancellation after principal commitment | Existing monitoring/recovery continues; no deleting live state |
| F12 | Optional mining prepay, success and provider abort | Disclosed cap and exact total accounting; upfront-loss possibility remains visible |

## Lightning backend semantics

| ID | Scenario | Required result |
|---|---|---|
| L01 | Incoming MPP parts include one insufficient expiry | Provider refuses unsafe funding; uses earliest relevant expiry |
| L02 | Partial accepted value, expired or mismatched hold invoice | No funding until full valid acceptance |
| L03 | RPC times out while outgoing payment later succeeds | Reconcile by hash/attempt; no duplicate payment or false refund-safe status |
| L04 | Payment retries at later block heights | Every submitted route satisfies fixed absolute exposure bound |
| L05 | LND restart after accepting/settling hold | Recovery tracks actual invoice/HTLC state and never reuses secret incorrectly |
| L06 | Force close during incoming/outgoing resolution | Actual backend timing fits modeled margins; unsafe profiles disabled |
| L07 | Backend lacks accepted-HTLC expiries | Corresponding capability/profile cannot be advertised |
| L08 | Macaroon scope and TLS certificate mismatch | Least privilege works; mismatch fails closed, no credential fallback |

## Durability, races, fees and reorgs

| ID | Scenario | Required result |
|---|---|---|
| D01 | Kill process before/after every payment/broadcast/sign intent | Restart reconciles; no lost live contract or duplicated irreversible action |
| D02 | DB result missing after successful chain/LN RPC | Query actual backend state before retrying |
| D03 | Reorg removes confirmation evidence | Verified chain state rolls back; revealed-secret knowledge never does |
| D04 | Deep reorg after preimage reveal | Explicitly exercise assumption violation; do not assert impossible unconditional recovery |
| D05 | Claim/refund race | Exactly one canonical spend; invoice cancellation waits for required refund evidence |
| D06 | Fee spike and fee-policy exhaustion | Escalate within policy or signal urgent risk; never pretend refund guaranteed at any price |
| D07 | Wallet/process restart loses Core-only locks | Durable reservation ledger reconciles and prevents unintended coin reuse |
| D08 | Simultaneous requests choose same UTXO | Transactional reservation admits at most one funding intent |
| D09 | Restored database snapshot misses newer chain activity | Reconcile before new action; retain conservative exposure state |
| D10 | Monotonic clock/wall-clock jumps | Block-based financial policy does not become wall-clock-only |

## MuSig2 and key safety

| ID | Scenario | Required result |
|---|---|---|
| K01 | Official BIP327/BIP340 fixtures and TapTweak cases | Native and WASM results match independently checked vectors |
| K02 | Secret nonce reuse/copy/serialization requests | API makes operation unavailable or rejects it before signing |
| K03 | Crash after public nonce sent | Old attempt abandoned; no reconstruction of old secret nonce |
| K04 | Fee-bumped message with old signing attempt | Rejected; new attempt and nonce required |
| K05 | Invalid peer partial/public nonce or substituted transaction | Rejected; unilateral fallback remains possible |
| K06 | Concurrent tabs/workers access same swap | Exclusive signing lease; one-shot native handle, no cloned active signer |
| K07 | Backup/log/core-dump fixture inspection | No live MuSig secret nonce in any intended persistence/export path |

## Discovery, transport and privacy

| ID | Scenario | Required result |
|---|---|---|
| N01 | Discover two independent providers on different relays | No hardcoded registry dependency; signatures/network checked |
| N02 | No official relays or registry available | Manual provider import/alternative relay still works |
| N03 | Expired/future/rolled-back/malformed advertisement | Rejected or explicitly stale; bounded memory/CPU |
| N04 | Relay drops/reorders/duplicates wrappers | At-least-once protocol remains idempotent; financial state not forged |
| N05 | Relay lies about ACK or invents status message | No principal action without app authentication and independent evidence |
| N06 | Session MITM, replay across networks, suite downgrade | Transcript/identity checks reject |
| N07 | Observer records tags, payloads, logs, subscriptions | No plaintext secret/invoice/payment hash/individual swap ID in public fields |
| N08 | Inspect observed metadata | Test expects visible recipient/time/size; no false anonymity claim |
| N09 | Provider epoch-key rotation and session migration | New sessions authenticate; old contract/recovery unaffected |
| N10 | Multi-relay retry | Fresh wrappers; same app ID; user-approved relay set only |
| N11 | Tor proxy failure or DNS request | Fail closed; no clearnet/DNS escape, including notification egress |
| N12 | Relay demands stable social-key authentication | Default refusal; no silent key reuse |
| N13 | Transport switched to private onion direct endpoint | Same authenticated semantics; no downgrade or settlement change |

## Wallet and notification privacy

| ID | Scenario | Required result |
|---|---|---|
| P01 | One adequate coin versus many unrelated exact-match coins | Single-cluster/single-input choice wins under configured policy |
| P02 | Core attempts additional funding inputs | `add_inputs=false`; result validation rejects changed set |
| P03 | Insufficient funds within one cluster | Explicit failure/approval, not hidden cross-cluster consolidation |
| P04 | Change output / derivation metadata | Fresh correct change; no accidental public xpub/path leakage |
| P05 | Unknown origin UTXOs | Not silently placed into one shared privacy cluster |
| P06 | Apprise unreachable, slow, or malicious sink | Settlement continues; notifications are redacted and bounded |

## Web, CLI recovery and release integrity

| ID | Scenario | Required result |
|---|---|---|
| W01 | Load release ZIP over loopback HTTP | Complete UI, assets and WASM available without CDN/application backend |
| W02 | Same build hosted under repository subpath | Relative paths and Pages deployment work |
| W03 | Browser generates recovery; CLI imports it | Exact contract/secret compatibility; no provider needed |
| W04 | CLI generates recovery; browser imports it | Same compatibility in reverse direction |
| W05 | Delete browser storage and stop all providers/relays | Backup recovers through user-selected chain access alone |
| W06 | Crash/close tab before versus after preimage release | State-specific risk and watcher behavior match specification |
| W07 | IndexedDB blocked/quota failure/private mode | Refuse commitment without required durability/export checks |
| W08 | Third-party chain source lies; strict mode enabled | Unverified confirmation does not authorize reveal |
| W09 | Local agent Host/Origin/CSRF/DNS-rebinding attack | Unauthorized access denied; no generic node RPC exposed |
| W10 | Provider description includes script/HTML payload | Render as inert text; no secret leakage |
| W11 | New release available during active swap | No silent in-session executable upgrade |
| W12 | Release ZIP versus Pages artifact | Identical built bytes/checksums; workflow restricted to authorized releases |
| W13 | Fresh client with only backup, own node, and recovery binary | Unilateral claim/refund completed independently |
| W14 | Default signet versus custom challenge / regtest namespace | Cross-network/replay confusion rejected |

## Merchant checkout extension

These are additional release requirements, not a declaration that funded
checkout or multichain conformance has passed. Offline `rill-payments` and
`rill-web` tests cover selected policy, transaction and browser boundaries.

| ID | Scenario | Required result |
| - | - | - |
| M01 | Buyer changes price, submits provider success or a preimage | Only independently verified merchant destination receipt can emit acceptance |
| M02 | Lost invoice-create response and merchant restart | Reconcile the same durable operation/hash; never issue a replacement payable invoice |
| M03 | Concurrent attempts and repeated receipt allocation | One payable attempt and one receipt allocation/event; replay returns stable identity |
| M04 | Native/wallet failure, tab closure and multiple tabs | Durable dispatch reservation before authorization; resume observation, no automatic second payment |
| M05 | Wallet, recovery, journal or relay retry crosses funding deadline | Reject commitment under merchant, invoice and provider deadlines; retain recovery once a signed transaction was shared |
| M06 | Token debit-wallet theft, wrong nonce/chain/contract or public hash claim | Pre-funding authenticated binding and exact source debit/subindex required |
| M07 | Malformed finality, changed canonical view or late native deposit | No false finality; late receipt reconciles; impairment preserves earlier acceptance/history |
| M08 | Merchant conversion/payout timeout and signer restart | Immutable nonce/terms before signing; exact signed-transaction replay and bounded fees; paid checkout unchanged |
| M09 | LayerZero clear/nilify/skip, missing token event or failed receive | Separate commitment, delivery and actual token credit; no generic refund or Lightning-success inference |
| M10 | Direct OFT retry without Scan | Exact packet/peer/endpoint, zero application value, fresh bounded nonce/config simulation and gas approval |
| M11 | Bridge/hub/second swap quote expires after first commitment | Preserve intermediate owner/recovery, stop next spend, reconcile funded operations without replacing the invoice |
| M12 | Operational stablecoin-to-merchant-Lightning path | Pinned deployments and exact fees, independently observed receipt, loss/refund asset accounting, provider disappearance and browser/daemon restart |
| M13 | Disposable native RPC conformance | Explicit sandbox profile, real synthetic-token receipt, local confirmation boundary, ledger restart/late/reorg handling; never claim production finality or fulfillment |
| M14 | Sandbox native API authority and event evidence | Distinct read/payment capabilities, durable verified prebinding, authenticated real RPC receipt, closed signed historical contract/key/terms binding, late and impaired evidence; never production fulfillment |
| M15 | Sandbox SDK funding/recovery | Shared atomic attempt reservation before wallet authorization, immutable private operation, guarded signing/broadcast, contradictory response rejection, same-hash observation after ambiguity/expiry; unknown metadata never auto-dispatches |
| M16 | Disposable Bun merchant LND conformance | Actual TLS/macaroons issuance and funded receipt, same-operation recovery across merchant-process restart, one atomic acceptance, stable signed delivery retry/history and secret projection; not browser-wallet, daemon-restart or production conformance |
| M17 | Scoped Bun merchant credentials | Documented permissions suffice for funded recovery flow; read-only write refusal with absent probe hash, independent TLS/signature failure causes and SendPaymentV2 denial; not formal minimality or full spending isolation |
| M18 | Disposable BTC-to-LN merchant swap checkout | Actual executeMerchantSwap, settled merchant invoice, confirmed cooperative provider claim, absolute payment/claim-witness checks, three CLI-inspectable encrypted recoveries and independently bound stable signed merchant acceptance; not browser-wallet, restart/crash or production conformance |
| M19 | Merchant restart before funded swap checkout | Explicit graceful merchant-only restart after issuing the original invoice, open-only reuse of original keys/config/store, unchanged authenticated checkout/logical SQLite state before payer dispatch, one original attempt/receipt and provider dispatch/funding reference; not postsettlement receipt loss, browser/LND restart or machine-crash evidence |
| M20 | Settled merchant observation lost before swap checkout acceptance | Explicit marker fsync and owned-child exit before observation returns to the ledger; persistence failures cannot accept, missing/conflicting evidence cannot reopen; ordinary same-state recovery independently observes/accepts the original settlement with one payer dispatch and original invoice/funding references; not transport-response loss, parent restart or power-loss evidence |

## Test evidence and accounting

Each funded test records initial/final on-chain wallet balances, contract outputs, LN paid/received amounts, mining fees, routing fees, quoted fees, prepayment exposure, and locked-but-not-spent amounts. Do not compare only UI status labels. Record block hashes/heights and privacy mode without retaining fixture secrets in public CI artifacts.

Run smoke/vectors/type checks on every PR; deterministic full-regtest/browser tests on integration changes; chaos, fuzzing and private-Tor tests in scheduled/full release jobs. Public signet observations are supplementary. Pin cross-repository versions and container digests in the integration manifest. Flaky retries cannot convert a failed safety assertion into a passing release.

Coverage percentage is supporting evidence. Every safety guard, irreversible effect boundary, timeout inequality, and independent recovery path requires an explicit test. Independent security review and audit findings are additional gates, not replaceable by green CI.
