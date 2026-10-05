# rill-cli

RillSwap command-line client, optional local watcher, static web server, and
independent recovery executable.

Status: pre-release and not suitable for real funds.

## Provider directory: `rill providers list`

Anyone can run a provider: publishing a signed kind-39417 announcement is the
only requirement, and no allowlist or registry exists. This read-only command
queries every `--relay` concurrently with no author filter and prints JSON with
each provider whose announcement verifies (event and application signatures,
the complete `--network` identity, the `btc-to-ln/v1` profile, an unexpired
window). It keeps each provider's highest revision across relays, reports
`relays_seen`, and marks a provider `equivocating` (with no terms) when two
different advertisements share its latest revision. It fails only if no relay
answers.

```sh
rill providers list --network signet.json --relay-proxy http://127.0.0.1:9080 \
  --crypto-library /absolute/path/to/librill_crypto.so \
  --relay wss://relay-one.example --relay wss://relay-two.example
```

A listing is discovery evidence only. It proves neither liquidity, solvency,
availability, nor honesty, and relays can withhold events or be flooded (each
relay's query stops after 4096 events, so use several independent relays).
Choosing a provider stays an explicit `--provider` argument to `swap`.

### Relay privacy

On signet, testnet4, and mainnet, `providers list` and `swap` refuse to
connect to relays unless `--relay-proxy http://127.0.0.1:9080` names a local
Tor `HTTPTunnelPort` (proxied relays must be `wss://`, and names resolve inside
Tor) or `--allow-direct-relay` explicitly accepts revealing your IP address.
There is no fallback from the proxy to a direct connection. Regtest connects
directly.

## Live swap: `rill swap btc-to-ln`

Supported networks: regtest, signet, and testnet4. Mainnet wallet funding is
refused in code until release acceptance.

This command pays a Lightning invoice from your Bitcoin Core wallet through
one provider, reached over a Nostr relay. It runs these steps in order:
1. Verify the provider's signed announcement.
2. Complete the handshake on a fresh session key.
3. Request firm terms for the invoice. The invoice is decoded by your own LND
   (`DecodePayReq`, loopback only). The terms are checked against your
   limits, and the provider's identity signature is verified.
4. Write the encrypted recovery file (`--recovery-output`), then accept.
5. Fund from `--wallet`. Before binding, the exact transaction is authorized
   against the signed terms. The funded snapshot (`<output>.funded`, with the
   signed binding) is written, and only then is the transaction bound and
   broadcast.
6. Wait for the provider's `payment_settled` observation and check that the
   preimage hashes to the invoice's payment hash. Publish a verified encrypted
   `<output>.paid` successor retaining that preimage before reporting success.
   All three files are create-only; keep the newest verified snapshot. A paid
   snapshot collision or write failure does not mean the invoice is unpaid.
   Publication failure may leave a valid `.paid` file. Preserve all snapshots,
   inspect any `.paid` file, and do not retry payment.

The post-funding provider stream is consumed in authenticated sequence order.
`--settle-timeout` is one finite, positive lifetime starting at the successful
funding broadcast; nonterminal observations do not renew it. Expiry means
settlement was not observed, not that the invoice is unpaid. Check the invoice
and retain recovery files before taking further action. After a verified
payment the provider's claim is cosigned as a MuSig2 key-path spend; if that
does not finish within its short window, the CLI says why and the provider
claims through the script path instead.

```sh
rill swap btc-to-ln \
  --network trusted-regtest-network.json \
  --crypto-library /absolute/path/to/librill_crypto.so \
  --relay ws://127.0.0.1:7777 --provider PROVIDER_XONLY_HEX \
  --invoice lnbcrt... --max-success-fee-sat 1000 \
  --core-port 18443 --core-cookie ~/.bitcoin/regtest/.cookie --wallet swap \
  --lnd-port 10009 --lnd-tls-cert tls.cert --lnd-macaroon invoice.macaroon \
  --recipient age1... --identity /protected/age-identity \
  --recovery-output swap-recovery.age
```

If the provider never pays, the funds stay in the contract. After the
printed refund lock height, run `rill recover watch-refund` on the `.funded`
snapshot (or the manual `sign-refund` and `broadcast-refund`).

Exit codes:
- `5`: the swap stopped with a stated reason.
- `2`: any other failure. Check whether a `.funded` file exists before
  assuming nothing was committed.

## Live swap: `rill swap ln-to-btc`

Receives on-chain BTC by paying a provider's hold invoice from your own LND
(RS-004). Same networks and mainnet gate as above. It runs these steps in order:
1. Verify the announcement (it must offer `ln-to-btc/v1`) and handshake.
2. Generate the preimage locally and request firm terms for `--payout-sat`,
   with your claim destination (a fresh `--wallet` address) and limits: the
   provider may refund no earlier than `--min-refund-delay-blocks` from now,
   and your Lightning funds may stay held at most
   `--max-incoming-htlc-delay-blocks`.
3. Decode the hold invoice with your LND and verify the terms, the invoice
   binding, and the provider's signature.
4. Write the encrypted recovery file, including the preimage, then accept.
5. Pay the hold invoice (`--lnd-macaroon` needs offchain read and write) on a
   route whose final hop expires no earlier than the terms'
   `min_incoming_htlc_expiry_height`, within `--max-routing-fee-sat`.
6. Consume the original provider stream in FIFO order while waiting for its
   session-signed `funding_binding`, check it and the
   exact funding transaction against the terms, and write the funded snapshot
   (`<output>.funded`).
7. Once Core shows the contract output at the signed depth, sign the claim
   (fee from `--fee-rate`) and broadcast it. Each new block without a
   confirmation replaces it by RBF at a fee rising linearly to the signed
   maximum by `refund_lock_height - claim_confirmation_blocks`; after that
   nothing new is signed. The command returns when the claim confirms. The
   provider settles the hold from the preimage in the claim witness.

The reverse funding wait owns one settlement consumer and one absolute wait
deadline. Earlier action requests, foreign contexts, unexpected replies, or
malformed observations cannot be skipped to a later binding. Nonterminal
observations never renew the wait, and buffered funding at expiry is not
processed. Timeout means funding was not observed, not proof that the provider
never funded. Check `lncli listpayments` and do not retry payment automatically.
Nonfinite or nonpositive settlement timeout values are refused before discovery
or payment. One absolute settlement deadline starts immediately before queuing
the exact hold payment. Queueing, preparation, uncertain submission, funding,
depth, and claim watching consume that same budget; no stage renews it.

The hold payer accepts optional absolute monotonic submission authority for
the shared reverse lifetime. It caps existing planning/submission
budgets, checks after planning and inside queued submission work, and passes
the fixed deadline and permission predicate through to the actual LND RPC
boundary. An already-started send may continue after return. Late positive
tracking remains payment knowledge; unknown outcomes require inspection and
never authorize retry. `run_reverse_swap` supplies the original deadline and
thread-safe submission predicate, including to queued payer work.

The claim watcher likewise accepts an original absolute monotonic deadline
and nonconsuming, thread-safe effect predicate. A relative timeout can shorten,
never renew, that deadline. Checks surround chain and confirmation observations,
signing, and submission, and sleeps cannot extend the budget. Revoked or expired
authority prevents new effects; an already-running callback can still finish.
Signed attempts remain prepared evidence even if a late callback times out or
submission reports failure. Neither outcome proves that the preimage stayed
private. The existing block-height signing and rebroadcast rules are unchanged.
Clock and permission collaborators must be trusted, prompt local observations;
arbitrary callbacks cannot provide atomic time-and-revocation guarantees.
Operational reporting can follow an expired submission to preserve evidence.
The reverse dispatcher supplies this authority to sizing signatures, claim
signing, and watching. Startup recovery publication and settlement workers are
shielded and owned until their actual completion. Cancellation stops new work;
repeated cancellation cannot release the SDK's crypto context before workers
finish. Cleanup lies outside the settlement budget and can remain unbounded
if a started callback hangs. An in-flight LND send can outlive the payer, but its
permission predicate uses only local lifetime state, not the crypto context.
Executor work is held as private Futures with cancellation-isolated waits;
drainage uses a shielded gather Future, not a child Task. Loop-wide Task
cancellation cannot falsely mark a running thread as completed. Late worker
exceptions are consumed without canceled-shield exception logging.

The own-Core wallet broadcaster accepts the same optional lifetime inputs.
Guarded calls keep one absolute deadline through network/genesis attestation,
cookie access, authentication, and request setup. A final HTTPX request hook
checks permission and refreshes phase timeouts before transport handoff. The
destination, root broadcast route, authentication, disabled redirects/proxies,
and exact transaction bytes remain unchanged; the default path is unchanged.
Handoff is potentially irreversible disclosure. Connection establishment still
follows the hook, so the first witness transmission can begin after expiry.
Phase timeouts are not a total duration bound. Late successful results remain
knowledge; timeout, transport error, cancellation, or missing chain observation
does not prove privacy or authorize retry. The reverse dispatcher supplies this
guard to every claim submission; activation and release gates remain closed.

For newly negotiated featured reverse terms, the dispatcher privately prepares
an independently valid signed claim and publishes a create-only `.fallback`
successor to the exact funded snapshot. The new gate requires the trusted
storage adapter to return those exact canonical bytes after durable encrypted
publication and readback. `None`, mismatches, exceptions, timeout, and late
acknowledgments grant no subsequent authority, even if a valid file was created.
Matching bytes detect accidental no-ops; they are not independent proof against
a lying adapter. Older unilateral and forward callback behavior is unchanged.

The private, nonactivated disclosure-publication helper extends those exact
acknowledged fallback bytes without rebuilding their recovery context. Its
create-only `.disclosing` snapshot preserves funding, knowledge, and fallback,
adds the authenticated proposal, and records current `updated_at`. It checks
nonregressing wall time strictly before the captured proposal deadline both
before writing and after exact acknowledgment. Cancellation, uncertain or late
writes, mismatched acknowledgment, and destination collisions grant no success;
a valid file may still remain. The helper sends no proposal and broadcasts no
claim. Publication is not proof of live nonce custody, chain-height eligibility,
or signing authority. A future live caller must retain its actual in-memory
acknowledgment, not substitute a restored historical predecessor.

Upgrading installations perform no automatic disclosure work. Absent and older
markers prove nothing; partial or existing disclosure markers refuse this live
helper. Historical artifacts remain inspectable for independent recovery, never
automatic cooperation resumption or transmission.

With featured terms the client then tries one private key-path claim. It
publishes the exact disclosure snapshot first, sends one signed
`cooperative_claim_propose` (preimage, MuSig2 public nonce, unsigned key-path
claim, a 20 second deadline, and the claim-confirmation height), and waits at
most 25 seconds for the provider's signed reply. It verifies the provider's
partial signature, adds its own (the native nonce is used once and closed on
every path), checks the aggregate BIP340 signature, and broadcasts a claim whose
only witness is that 64-byte signature. The key-path claim pays the same
absolute fee as the first script-path claim, so the watcher's bump schedule is
unchanged; it rebroadcasts the key-path claim until a due bump replaces it with
the already durable script-path claim. A tip at or past the claim-confirmation
height, a relay failure, timeout, decline, or invalid partial costs only
privacy: the client claims with the preimage as before. The client skips the
attempt when less than 85 seconds of `--settle-timeout` remain (the 25 second
wait plus a 60 second reserve for the unilateral claim).

Cooperative MuSig2 claims are mandatory for new swaps in both directions. Every
`handshake_init` requests `cooperative-claim/v1`; the client refuses a
handshake accept that does not echo it and a terms offer that does not commit
to it, before any funding or payment.

```sh
rill swap ln-to-btc \
  --network trusted-regtest-network.json \
  --crypto-library /absolute/path/to/librill_crypto.so \
  --relay ws://127.0.0.1:7777 --provider PROVIDER_XONLY_HEX \
  --payout-sat 50000 --max-success-fee-sat 1000 \
  --core-port 18443 --core-cookie ~/.bitcoin/regtest/.cookie --wallet receive \
  --lnd-port 10009 --lnd-tls-cert tls.cert --lnd-macaroon payment.macaroon \
  --recipient age1... --identity /protected/age-identity \
  --recovery-output swap-recovery.age
```

Payment errors and unknown status do not prove that nothing was submitted.
Preserve recovery files, inspect `lncli listpayments`, and do not retry payment.
A provider abort or expired observation budget does not prove nonfunding or
preimage privacy. If the command stops after funding, claim from
the `.funded` snapshot with `rill recover watch-claim` (same schedule, from
`--initial-fee-sat` to `--max-fee-sat`, capped by the signed terms) before
the refund lock height. Do not assume a late claim was broadcast or confirmed;
check Core and LND. Refund or hold cancellation must be observed, not inferred
from a timeout. Core needs `txindex=1` to report the
funding depth.

```sh
rill recover watch-claim --network signet.json --crypto-library /path/librill_crypto.so \
  --funding-attempt-id ATTEMPT --binding-revision 0 --identity /protected/age-identity \
  --rpc-cookie ~/.bitcoin/signet/.cookie --rpc-port 38332 \
  --initial-fee-sat 300 --max-fee-sat 3000 swap-recovery.age.funded
```

The client currently reuses `rill-provider`'s Nostr transport modules.
Discovery observes a bounded query window and selects the highest valid
announcement revision it receives, rather than trusting arrival order. Equal
revision conflicts and event floods are refused. A relay can still withhold
newer announcements; persistent rollback protection remains required before
public deployment. Use `rill providers list` across several relays to compare.

The live wallet verifies Core's actual chain and genesis before every wallet
effect, including signing and broadcast, and refuses incomplete or initial-sync
responses. Selecting a regtest network file does not authorize a different
wallet backend. The check is not cached across calls. Existing installations
need no state migration; a mismatched endpoint now fails before wallet effects.

Cooperative preflight joins the shared Core reader's mempool-aware
outpoint and strict fee-policy samples only when both name the same configured
network and tip. It never uses a wallet RPC route. It does not authorize signing
or bound acquisition time on its own. The original-session handler enforces
the original deadlines, one-second evidence lifetime, exact transaction
policy, and durable create-only `.cooperating` reservation before nonce
allocation. Recovery inspection never resumes cooperation.

The `_CooperativeClaimAttempt` owns the original FIFO through readiness,
proposal, one-shot partial signing, and verified completion. It preserves valid
preimage knowledge even when readiness is unusable, publishes `.paid` before
echoing, and requires confirmed `.cooperating` publication plus new own-node
evidence before allocating a client nonce. Its nonrenewing budget intersects
the original funding lifetime and advertised deadline. Completion at or after
the cutoff is not processed, even if queued. Abandonment does not cancel a
provider's already-selected key-path winner or permit payment/signing retry.
Transport may retransmit the identical wrapped event without signing again.

Forward `run_swap` constructs this owner only for authenticated cooperative
terms, using the exact original funded bytes and fixed funding lifetime. It
never reconstructs or republishes paid recovery afterward. `SwapOutcome`
distinguishes `verified` completion from `abandoned` cooperation, neither of
which implies chain confirmation or cancellation of a provider winner.
Unconfirmed paid publication retains the existing known-payment error and
do-not-retry guidance. Acknowledged paid storage remains usable even if a later
reservation publication is uncertain; preserve all recovery files.

`--claim-fee-floor-sat` sets the forward user's positive absolute cooperative
claim fee floor (default 1 sat), not the funding sat/vB rate or a signed ceiling.
Fresh own-node market policy may require a higher fee. Invalid floors, including
a floor above `--max-claim-fee-sat`, fail before relay or native setup. No
implicit regtest estimate exemption is enabled.

Cancellation or timeout does not stop an RPC or recovery writer thread.
Forward settlement cleanup retains one shielded worker-drain Future even under
repeated cancellation, then propagates cancellation before the CLI closes its
crypto context. Late publication may leave a
valid recovery file; the retained pending successor is unconfirmed, not a
durability promise. Late worker success never reactivates the attempt.
This cleanup is outside the settlement budget and can remain blocked by a
worker that does not terminate; physical worker termination is still a gate.
Live readiness echoes and client cooperative signing remain disabled until
authenticated feature negotiation, both-direction cooperation, and adversarial
Core/LND acceptance tests are complete. The conditional forward branch is
tested with real funding, encrypted publication, and native MuSig2, but its
discovery/handshake fixtures are stubbed, not negotiated interoperability.
Synchronous
native work and filesystem synchronization can overrun their last clock check;
strict end-to-end deadline guarantees are not established by these unit tests.

Funding uses one confirmed, safe P2WPKH or P2TR coin. Core receives that exact
input with `add_inputs=false`, and its proposed input set is checked before
signing. If no single coin covers the amount and a conservative 165-vbyte fee
reserve, the command fails rather than combining coins of unrelated origin.
Multi-input cluster-aware selection and durable concurrent-wallet reservations
are not implemented. This policy prevents new cross-input consolidation; it
does not establish anonymity or erase a coin's existing transaction history.

`rill recover observe-funding` is a **read-only, explicitly requested regtest
diagnostic**, not a refund transaction or an automatic watcher. It requires a
complete independently trusted network JSON file, protected age X25519
identity or passphrase prompt, pinned native crypto library, exact signed
`--funding-attempt-id` and `--binding-revision`, a local Core cookie and RPC
port, and an explicit encrypted recovery snapshot path. Example (test-only):

```sh
rill recover observe-funding \
  --network trusted-regtest-network.json \
  --crypto-library /absolute/path/to/pinned/librill_crypto.so \
  --identity /protected/age-identity \
  --funding-attempt-id EXACT_64_LOWERCASE_HEX \
  --binding-revision 0 \
  --rpc-cookie /protected/regtest/.cookie \
  --rpc-port 18443 \
  /path/to/selected-recovery.age
```

The selected file is decrypted and **all** recorded signed funding history is
checked before any Core RPC. Only a numeric loopback address (default
`127.0.0.1`) is accepted. The RPC client checks Core's regtest label and
genesis, the chain-only UTXO sample (`gettxout` with mempool excluded), exact
value and script, block-qualified transaction bytes against Core's funding
transaction matcher, and sampled tip/lookup-block consistency. No `txindex`,
wallet RPC, automatic scan, broadcast, or state update is required. Missing,
spent, unconfirmed, stale, partial, older, or restored evidence cannot prove
absence or latest funding, and a mempool spend can coexist with a chain-only
sample. The JSON result labels the transaction lookup block separately from
the sampled inclusion height and explicitly reports **no authority**. A
rapidly changing chain and a later tip can stale a successful observation;
the RPC listener is trusted by the operator, not cryptographically
authenticated by loopback Basic auth. Read timeouts are inactivity limits,
not a transaction deadline. Do not use this output to sign, fund, pay, or
claim refund eligibility. Real regtest byte-matching for both swap profiles
is opt-in with `RILLSWAP_RUN_BITCOIN_CORE=1 .venv/bin/pytest -q -m bitcoin_core`
and requires the locally built sibling native library plus pinned Docker
images. Neither test uses funds outside disposable regtest.

`rill recover observe-claim` accepts the same exact selection, trusted regtest
network, age identity, native library, and read-only Core cookie as
`observe-funding`, but only for an LN-to-BTC **client claimant**. It validates
the complete signed recovery snapshot before Core RPC, checks the selected
transaction and output bytes without txindex, requires the signed minimum
funding confirmations and the strict pre-disclosure timing window
`tip_height + claim_confirmation_blocks < refund_lock_height + 1`, and samples
`gettxout` both chain-only and including known mempool spends. An unknown or
mempool-spent outpoint fails closed. Validation necessarily parses the encrypted
snapshot, including its preimage; the command never signs a claim, prints or
sends the preimage, calls a mutating Core RPC, writes an artifact, or authorizes
preimage disclosure. The observation is staleable; it does not establish fee
viability, a durable claim plan, absence of earlier disclosure or competing
funding history, complete LN state, or permission to pay or broadcast. A
valid restored recovery file may lack later signed bindings. The disposable
pinned Core test verifies refusal before required confirmations and after an
independently created synthetic claim enters the mempool.

`rill recover prepare-claim` adds `--fee-sat` and a new `--output` path to the
`observe-claim` arguments. It requires a **matching protected age X25519
identity** (passphrase output is unsupported). After the read-only claim
sample, it signs and locally verifies an LN-to-BTC client claim, then writes
only a private age-encrypted, create-only `rillswap-opaque-claim-plan/v1` file
in an operator-trusted, fsync-capable directory. The canonical plaintext
contains the complete network identity, contract hash, SHA-256 of the exact
selected recovery plaintext, attempt/revision, and the signed transaction
hex (bounded to 6 KiB). The witness **contains the preimage**. The file is
X25519 encrypted and decrypted again for exact plaintext and independent
signature/outpoint verification before and after disk readback. The CLI prints
only public txid/fee/selection and says `broadcast: false`, with **no
preimage-release authority**. Do not send the ciphertext to an untrusted
decryptor or the decrypted bytes to Core, a provider, a network service, a
log, or a plaintext file. Python cannot promise key erasure from memory.
Age encryption gives confidentiality and integrity, **not provenance**:
anyone with the public recipient can encrypt a replacement. Static recovery
signatures and the claim transaction are revalidated on readback. A stored or
restored plan may contain an out-of-date binding, fee, or witness; it does not
prove current unspent funding, fee viability, complete lineage, LN state, or
safe first disclosure. Production disclosure still requires independently
reconciling those facts and durable, rollback-safe exposure knowledge.
Missing, partial, older-version, corrupt, or restored plan files never trigger
automatic construction, migration, retry, or sending. Interrupted publication
is uncertain (exit 3) and requires manual inspection rather than retry.

`rill recover broadcast-claim` is an **EXPERIMENTAL, disposable-regtest-only
preimage disclosure attempt**, not the production disclosure operation above.
Supply the same trusted network, native library, age identity, exact selected
attempt/revision, Core cookie/port, and encrypted recovery file as
`observe-claim`, plus `--plan /trusted/private/prepared-claim.age`,
`--intent /trusted/private/new-disclosure-intent.age`, and the required explicit
`--acknowledge-regtest-preimage-disclosure` flag. **Never use a preimage also
used with a real Lightning invoice, a funded swap, or another network.** The
test fixture contains only a public synthetic preimage and disposable regtest
coins. This command checks the signed plan against the selected recovery
snapshot, samples Core, durably publishes and revalidates a private X25519
encrypted create-only exact-byte intent marked `disclosure_may_occur`, then
resamples the selected outpoint before one `testmempoolaccept` and at most one
`sendrawtransaction`. **Even preflight can disclose the preimage to Core.** A
definitive preflight rejection still reports exposure/submission **unknown**
(exit 4), with no automatic retry. Intent durability uncertainty is exit 3;
refusal before any witness-bearing RPC is exit 2; matching node acceptance is
exit 0, **not confirmation or LN settlement**. Repeated invocations at the
same intent path cannot send again, but another path, a deleted marker, or an
older/restored snapshot can bypass that local check. Missing, partial, wrong-
version, or restored intent is never an automatic migration or a fresh-secret
proof. The operator must reconcile exposure and payment outside this tool.
Neither the stdout receipt nor the encrypted intent is safe first-disclosure
authority. No live LND hold/HTLC status, current complete funding lineage,
fee-market viability, crash-safe global disclosure journal, recovery watcher,
or rollback-safe replay fence is implemented.

`rill recover sign-refund` constructs a **BTC-to-LN client refund only** for
one explicitly selected signed funding binding, on disposable regtest. It
accepts the same network, identity, native library, exact attempt/revision,
cookie, RPC port, and encrypted file arguments as `observe-funding`, plus
`--fee-sat` (an exact integer constrained by signed refund terms) and
`--output` (a new file in a **trusted local directory**). For example:

```sh
rill recover sign-refund \
  --network trusted-regtest-network.json \
  --crypto-library /absolute/path/to/pinned/librill_crypto.so \
  --identity /protected/age-identity \
  --funding-attempt-id EXACT_64_LOWERCASE_HEX \
  --binding-revision 0 \
  --rpc-cookie /protected/regtest/.cookie \
  --rpc-port 18443 --fee-sat 500 \
  --output /trusted/private/new-refund.raw \
  /path/to/selected-recovery.age
```

The complete selected encrypted record is validated before Core RPC, then
revalidated inside the secret-confined signer. The selected output is sampled
both chain-only and with mempool spends included, matched against the funding
transaction bytes, and checked at a sampled tip strictly after the signed
refund lock height. The signed refund is verified from the private, fsynced
temporary file before create-only publication, with no overwrite, wallet RPC,
network broadcast, or state update. **The output is not proof of complete or
current funding, payment failure, absence of competing bindings, safe
broadcast, or ongoing spendability.** A rapid reorganization, unobserved
mempool activity, restored/older snapshots, and later spending can invalidate
the sampled evidence. Recheck independently and reconcile every relevant
outpoint before contemplating manual broadcast. An LN-to-BTC user does not own
the refund key and must use the separate, experimental-only claim flow. The local
directory must not be writable by untrusted actors; this tool is not a
hostile-directory or ancestor-symlink defense. An interrupted publication may
leave an artifact without a success report (exit 3 if detected), which requires
manual inspection and **no automatic retry**. Python does not guarantee
erasure of private key material from memory. The opt-in pinned Core test mines
to height T+1, checks `testmempoolaccept` without broadcasting, and never
uses funds outside disposable regtest.

`rill recover broadcast-refund` is a **separate, explicit, regtest-only
submission** of a BTC-to-LN client refund, not a retry of `sign-refund` and
not a production recovery workflow. Supply the same independent trusted
network, protected age identity, native library, exact attempt and revision,
Core cookie/loopback port, encrypted snapshot, and `--fee-sat` as
`sign-refund`, plus a **new** `--intent /trusted/private/new-intent.json`
instead of `--output`. The command revalidates the full signed snapshot and
exact outpoint, signs and validates only that refund, then durably creates and
reads back a private, canonical intent containing the exact transaction bytes,
txid, byte hash, network, selection, fee, and sampled tip. The intent is
marked `submission_may_occur` **before** the first send attempt. Publication
uncertainty (exit 3) prevents sending. It samples Core again, requires exact
`testmempoolaccept` on those bytes, and calls `sendrawtransaction` at most once
per invocation. A valid returned txid is reported as `node_accepted`, never
as confirmed, final, paid, or swap-recovered. A lost/malformed response after
the send begins returns **unknown** (exit 4) without an automatic retry.
Ctrl+C **caught during submission checks or RPC execution** before the send
boundary is a no-send preflight refusal (exit 2); after the boundary it is
conservatively unknown (exit 4), including interruption during client cleanup.
This does not guarantee classification for interruptions during earlier intent
preparation/publication or after the helper returns. Other process-control
exceptions are not translated. Neither signal classification nor a returned
txid proves chain inclusion or makes a second attempt safe.

`rill recover watch-refund` is the automatic form for a swap the provider
never paid. With `--lnd-port`, `--lnd-tls-cert`, and
`--lnd-invoice-macaroon` it checks the invoice in your own LND before every
attempt, which fits paying your own node's invoice. For someone else's invoice
pass `--chain-only` instead: it then refunds only past the refund lock height
while the funding output is still unspent, without knowing whether the invoice
was paid, and its JSON reports `"invoice_check":"skipped-chain-only"`. It
polls until the refund confirms or the invoice settles. Before every attempt
it asks your own LND (`--lnd-port`, `--lnd-tls-cert`,
`--lnd-invoice-macaroon`, an
`invoices:read` macaroon) for the invoice state and **refuses to refund a
SETTLED invoice** (the provider paid you; refunding would take their funds).
Missing LND or Core evidence only waits. Core `gettxout` returning null means
the selected output is absent, not that a foreign spender was identified;
the watcher keeps polling and checks whether a previously recorded refund
confirmed. A non-null output must match the selected signed funding value,
script, confirmations, and chain tip before it can authorize a new attempt.
After the refund lock height, it signs the refund at `--initial-fee-sat`,
rising linearly to `--max-fee-sat`
(capped by the signed `max_refund_fee_sat` and the dust floor of the
refund output) over `--escalate-blocks`
blocks, replacing the unconfirmed attempt by opt-in RBF when a new block has
passed and the fee beats the previous one by 1 sat/vB. Every signed attempt
is written to a create-only `refund-NN-<txid>.json` in `--intent-dir` before
it is sent; those files are the state, so a restart reloads and verifies
them and never signs a lower fee. The final JSON names every attempt and the
outcome (`refund_confirmed` with its depth or `invoice_settled`; the watcher
also understands an explicitly supplied `outpoint_spent_elsewhere` view, but
the live Core adapter does not infer a foreign spend from UTXO absence).

```sh
rill recover watch-refund --network signet.json --crypto-library /path/librill_crypto.so \
  --funding-attempt-id ATTEMPT --binding-revision 0 --identity /protected/age-identity \
  --rpc-cookie ~/.bitcoin/signet/.cookie --rpc-port 38332 \
  --lnd-port 10009 --lnd-tls-cert tls.cert --lnd-invoice-macaroon invoices.macaroon \
  --intent-dir /trusted/private/refund-attempts --initial-fee-sat 300 --max-fee-sat 3000 \
  swap-recovery.age.funded
```
Existing intent paths are never overwritten or automatically resumed; the
operator must reconcile exact txid, mempool, selected chain, conflicts, and
LN state before any separate manual action. Even a `node_accepted` response
can become stale or compete with a claim; `testmempoolaccept` is not a chain
reservation. The intent directory must be operator-trusted, fsync-capable
local storage. Partial or restored recovery files prove neither nonpayment
nor complete funding lineage. **This is pre-release: do not rely on it as a
production-ready refund broadcaster for real funds.** The
opt-in pinned Core test submits once, verifies mempool entry, mines the refund,
and checks exact block-qualified transaction bytes on disposable regtest.

The export, export-update, and inspect commands are **offline only**. `rill recover
export` explicitly creates a new binary age v1 X25519 file from canonical
RS-007 plaintext supplied on standard input. It requires one public age
recipient, a matching private age identity file, a separately trusted complete
Bitcoin network JSON file, and an explicitly selected native `rill-crypto`
library. The recipient secret is needed because export decrypts the stored
ciphertext and checks the exact plaintext and signed contract before reporting
success. The secret file must be regular, not a symlink, and accessible only to
its owner (`0600`). Export never overwrites an existing file (including a
symlink), makes no plaintext temporary file, and never sets a funding-ready
marker. It does not overwrite an existing recovery export after funding or RBF.

`rill recover export-update --previous OLD.age --output NEW.age` is an
explicit, **create-only successor snapshot**, not replacement-in-place.
It accepts new canonical RS-007 plaintext on standard input, decrypts and
validates the explicitly supplied prior X25519 age file using the same
protected identity, asks `rill-core` to check pairwise monotonic knowledge,
then publishes a separate verified age file under the existing no-clobber
durability protocol. It refuses absent, corrupt, partial, unsupported-format,
or symlinked prior files; an existing output path, including the prior path,
is never overwritten. No auto-discovery, migration, scan, or funding action
occurs. A valid older/restored prior snapshot remains eligible; an unselected
sibling may hold knowledge missing from the created successor. **Success proves
only a relationship between the two selected snapshots, not freshness,
authoritative client reconciliation,
or a safe RBF workflow.** Interrupted publication is still uncertain (exit 3)
and requires manual reconciliation. Client-state durability, atomic update
of active recovery records, and production-safe independent unilateral
recovery remain release gates.

`rill recover inspect` decrypts an explicitly selected X25519 or age scrypt
file and prints only redacted offline metadata and what remains unproved.
Passphrase input requires a protected terminal prompt; without echo control it
fails closed, never accepts a passphrase argument, and never reads echoed
standard input. **Passphrase export is not implemented**: pyrage's dynamic
encryption work factor cannot be bounded before performing its scrypt KDF.
Scrypt inspection rejects `logN > 19` before invoking the KDF. A logN of 19
uses roughly 512 MiB plus implementation overhead. These resource limits may
exclude otherwise valid age files. No automatically initiated scans, provider
contact, payment, funding, migration, or broadcasts are implemented by these
offline commands. The separate `sign-refund` command signs only after its
explicitly requested regtest checks.

## Merchant inventory journal (internal, not an executable conversion service)

`rill_cli.conversion_journal` provides an operator-only allocation boundary for
merchant-held Lightning to an owned Taproot BTC treasury destination. It does
not verify merchant proofs, query a wallet, run a swap, or expose a CLI command.
Those runtime integrations and funded conversion evidence remain required.

Explicit provisioning requires a dedicated source epoch, exclusive control of
all source-wallet spending and known refund/reserve commitments. One retained
source-owner fence must live outside the journal directory at the operator's
authoritative location for that wallet. Ordinary opening never creates state;
missing, partial, incompatible or lost state requires reconciliation, not empty
reprovisioning. A signature, historical invoice settlement or replenished wallet
balance cannot authorize spending or recreate consumed source credit.

Conversion allocations and refund holds share an atomic private SQLite ledger.
The worker must call `begin_capacity_query()` **before** its authenticated wallet
RPC and bind the response to that challenge. Durable generations reject queries
begun before dispatch or completed hold release, even if they return afterward.
Timestamp freshness alone is insufficient. Pending holds and a fixed wallet
reserve remain unavailable; completed actual debits remain consumed.

Only a fresh reservation owner can consume an invocation right. Replays and
reopened jobs are observation-only. Verified firm terms must fit total source,
routing, fee and output limits, with create-only encrypted recovery verified
from disk before a one-shot dispatch marker. Ambiguous state retains allocations
and never authorizes a replacement swap or payment. Completion requires actual
source debit/fees and an independently verified owned BTC output/depth, not a
nominal swap payout. This module never changes customer paid status or receipts.
Existing installations receive no automatic provisioning, migration or conversion.
Production conversion remains disabled and unproved.

### Merchant credit correspondence (internal, provenance only)

`rill_cli.merchant_credit.verify_merchant_credit` verifies the existing merchant
PureEd25519 acceptance format against an independently pinned key, matching paid
view, decoded invoice, and configured LND/Core source identity. It returns only
the agreed quantity, payment hash and invoice digest. Historical acceptance and
expired-but-settled invoices remain eligible **provenance**, not spendable credit.
Pinned alias origins can yield the same canonical credit; preventing repeated
consumption remains the journal's responsibility.

The trusted runtime must authenticate the pinned HTTPS server, reject redirects
and caches, and obtain the source projection **only after successful
`observe_bound_settled_invoice(expected)`**. `from_bound()` checks the projected
state, not whether that RPC or its sufficiently-paid checks actually ran. Typed
wrappers do not prove transport authentication. Record full start/completion
intervals for view, LND and Core reads, enforce monotonic elapsed-time bounds,
and import only into the journal whose source authority was supplied. Complete
network pins include declared namespace/profile; separate LND/Core reads do not
constitute atomic chain attestation.

The frozen public test fixture checks actual TypeScript signing and Python
verification, including canonical-origin edge cases. Invoice decoding, HTTP/RPC
acquisition and backend observations in these tests are mocked. Actual ordinary
invoice interoperability, safe outgoing capacity/economic projections, encrypted
swap recovery, runner wiring and funded receipt-to-treasury conversion remain
required. This verifier performs no import, migration, provisioning or payment.

### Leaf-pinned merchant acquisition (internal diagnostic)

`rill_cli.merchant_https.MerchantHttpsReader` reads the current view and events
from M24's explicit numeric-loopback regtest HTTPS profile. Configure a validated
`MerchantSourcePin`, an independently retained SHA-256 digest of the leaf's DER
certificate, and a protected operator CA file. The constructor is inert; missing
trust configuration refuses acquisition, never learns trust from the server.

Each exact GET uses a fresh connection with normal TLS trust/hostname verification
and compares its leaf **before sending the status capability**. Implicit reconnect,
redirects, retries and environment proxy settings are not used. Credentials are
passed per call, not stored in the reader. Keep trust files and their ancestors
under operator control; private-file checks do not isolate same-UID code.

Both documents must be HTTP 200 JSON with `no-store`, no Age or content encoding,
and an explicit positive ASCII-decimal Content-Length of at most 16 KiB. Duplicate
framing headers, contradictory cache directives and every Transfer-Encoding
response refuse. This intentionally rejects chunked responses because stdlib's
chunk parser does not enforce complete final framing. Actual Bun current-view
and events endpoints pass this stricter profile.

One monotonic acceptance budget (at most ten seconds) includes trust-file work,
TLS, both reads and cleanup. Both returned acquisition intervals conservatively
cover the full batch. This is **not a hard execution deadline**: filesystem work
and protocol parsing can block longer, but late evidence is discarded. Do not use
this synchronous diagnostic on a shared server event loop or claim production-grade
availability. A batch does not establish atomic view/events or underlying state
freshness. Returned statements remain unsigned/unverified; they are not credits,
spending authority, independent LND/Core correspondence or paid-order acceptance.

Actual-TLS tests cover pre-capability refusal, trusted certificate rotation,
framing/truncation, deadlines and private failures. The cross-runtime Bun test
uses a real waiting intent with synthetic LND identity and issues no invoices or
payments. Run it from `rill-payments` with
`RILLSWAP_MERCHANT_READER_PYTHON="$PWD/../rill-cli/.venv/bin/python" bun test tests/regtestMerchantHttpsDiagnostic.test.ts`.
CI runs this against the CLI's pinned Python environment. Existing installations
receive no automatic acquisition, provisioning, import or persisted-format change.

### Composed merchant/source provenance acquisition (internal diagnostic)

`rill_cli.merchant_source.MerchantCreditCollector` owns the concrete read sequence:
leaf-pinned merchant HTTPS, strict structural paid-view/single-event extraction,
LND invoice decoding, successful `observe_bound_settled_invoice`, independent
Core source-height observation, and unchanged final Ed25519/correspondence
verification. Its constructor validates the affirmative `SourceAuthority` and
`MerchantSourcePin` relationship without reading credentials or contacting nodes.
`MerchantSourceConfig` supplies protected merchant CA/leaf, one source LND
port/TLS-root/macaroon, and Core port/cookie. Use only the three exact LND URI
permissions for GetInfo, LookupInvoiceV2 and DecodePayReq. The two LND clients
share that explicitly configured endpoint and network; no broad invoice-write
permission or automatic credential provisioning is introduced.

`acquire(intent_id, status_token)` returns only canonical `SourceCredit` provenance
(agreed quantity, payment hash and literal-invoice digest). It does **not** import
into a journal, reserve inventory, guarantee liquidity, fund a swap or establish
refund payability. Earlier spending and custody remain separate responsibilities.
Typed observation substitution is not the runtime API, but concrete construction
does not isolate malicious same-process Python code or a replaced loopback Core
listener. Source namespace/profile/custody remain operator assertions.

One ten-second maximum acceptance budget covers the whole sequence and final
verification. All returned proof intervals conservatively cover the operation;
earlier/future HTTPS observations and a final clock rollback behind either batch
completion refuse rather than refresh timestamps. Late results never release
computed credit. This is not a hard execution or no-late-dispatch deadline: existing
decoder credential/setup work can delay an RPC before applying its relative
timeout. The synchronous diagnostic is unsuitable for a shared server event loop.

Structural extraction does not authenticate signatures. It requires one current
acceptance, duplicate-safe bounded JSON and a lowercase ASCII invoice within the
decoder's initial 2,048-character profile; final verification remains mandatory.
Unit tests use genuine separately signed loopback statements with synthetic RPCs.
The separate opt-in `test_merchant_source_pinned.py` scenario also acquires actual
paid Bun HTTPS statements, ordinary-invoice LND settlement and independent Core
correspondence after one owned 1,000-sat payment. It verifies unchanged merchant
history and protected inputs, one invoice and one payment attempt. This is funded
provenance conformance, not inventory conversion or production clearance.
No previous installation acquires,
imports, provisions, migrates or spends anything automatically.

The package declares dependencies on `rill-core`, `rill-crypto`,
`pyrage==1.4.0`, `httpx==0.28.1`, `pydantic==2.13.5`, and `pycryptodomex==3.23.0`,
but release wheels do **not** bundle the
native cryptographic library; a missing or wrong library fails closed. Test-only keys and fixtures
in `tests/fixtures` are public. To develop alongside the sibling repositories:

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
mkdir -p tmp
.venv/bin/pytest -q --basetemp=tmp/pytest
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

Set `RILL_CRYPTO_LIBRARY` to the pinned local `librill_crypto.so` to enable
native inspection tests. Optionally set `AGE_BINARY` to the Go `age` v1.3.1
binary for two-direction independent X25519 interoperability tests. The CLI
itself requires `--crypto-library` explicitly. Its `export`, `export-update`, and `inspect`
subcommands require `--network`; run `rill recover --help` for their exact
arguments. The pretty-printed JSON fixtures are decoded objects, **not**
canonical age plaintext. If export exits with code 3, the destination may
already exist but its directory durability could not be confirmed: inspect
and reconcile it manually, never retry or fund automatically. An absent path,
absent metadata, or restored older file proves nothing about previous exports.
The library-only `age_container.inspect_container_selected_funding_binding`
can explicitly decrypt and statically validate a recovery file, then project
one public funding binding by exact attempt ID and revision. This is not yet
a CLI command, selected-chain observation, wallet import, or signing path.
An older/restored file may omit later revisions; no latest or unspent binding
is inferred. Invalid and absent records return redacted errors.
The parallel `inspect_container_selected_funding_context` returns only public
validated terms alongside that exact candidate for future independent
transaction-byte checking; it does not grant authority or expose designated
recovery secrets. Signed public terms can include arbitrary extension values,
so do not log the returned object.

For a **fail-closed local backup interoperability gate** on Linux amd64,
download the official Go age v1.3.1 archive from
`https://github.com/FiloSottile/age/releases/download/v1.3.1/age-v1.3.1-linux-amd64.tar.gz`
into this repository's `tmp/` directory. The committed gate verifies its
SHA-256 `bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377`
before extracting or executing `age/age`. Separately build the pinned sibling
`rill-crypto` library and independently record its SHA-256. With the local
Python 3.14 `.venv` and both sibling checkouts installed:

```sh
.venv/bin/python scripts/check_age_interop.py \
  --age-archive "$PWD/tmp/age-v1.3.1-linux-amd64.tar.gz" \
  --native-library "$PWD/../rill-crypto/tmp/build/librill_crypto.so" \
  --native-sha256 YOUR_INDEPENDENTLY_RECORDED_LIBRARY_SHA256
```

The gate refuses a wrong archive digest/version, missing sibling source,
library digest mismatch, a skipped test, or fewer than three passing checks.
It uses a fresh private test directory rather than deleting an existing
scratch path, and requires a structured report with exactly the three intended
cases. Inherited pytest plugins, assertion mode, and Python optimization
settings cannot silently turn this check into a skipped or assertion-free run.
It exercises Python-to-Go and Go-to-Python age X25519 in both profiles plus
the separately generated Go scrypt fixture with native inspection. It records
each component source revision and whether its worktree is dirty; a caller-
supplied native hash identifies tested bytes but does not attest binary origin.
This is **local verification only**. There are no repository remotes or hosted
CI workflows configured yet, so required CI enforcement and independent
reproducible artifact provenance remain open release gates. None of these
checks permits refund signing, broadcast, funding, or payment.
