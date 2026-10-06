# rill-provider

RillSwap provider policy, treasury management, persistence, reconciliation,
watching, and the authoritative cross-repository integration harness.

Status: pre-release and not suitable for real funds. Regtest, signet, and
testnet4 serve both swap directions; mainnet serving stays refused until a
release accepts it.

## Operator quickstart (signet)

The rest of this README is design and upgrade notes. This section is the
supported path to a running signet provider.

**You need:** Bitcoin Core (synced signet, RPC on loopback), LND on the same
host (synced, with outbound liquidity and one channel for BTC to LN, or
inbound liquidity and an on-chain wallet in Core for LN to BTC), Tor with an
`HTTPTunnelPort` (add `HTTPTunnelPort 127.0.0.1:9080` to `torrc` and restart
Tor; relay traffic must not reveal your IP), Python 3.13 or later,
`uv`, `cmake` with a C compiler, and `age-keygen`.

1. Check out `rill-core`, `rill-crypto`, `rill-provider`, and `rill-cli` side by side
   (this monorepo already does), then install from `rill-provider/`:

   ```sh
   uv venv --python 3.14 .venv
   uv pip install --python .venv/bin/python -r requirements-dev.txt
   source .venv/bin/activate          # puts `rill-provider` on PATH
   cmake -S ../rill-crypto -B tmp/native -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
   cmake --build tmp/native           # builds tmp/native/librill_crypto.so
   uv pip install --python .venv/bin/python -e ../rill-cli   # `rill`, for step 6
   ```

2. Make a working directory (for example `/srv/rill`) and an age custody key.
   It decrypts the provider identity and store secrets; back it up offline.

   Run this as the account that will run the provider; if it cannot write
   `/srv`, first `sudo install -d -o "$USER" -m 700 /srv/rill`, or use another
   directory and substitute its path below.

   ```sh
   mkdir -p -m 700 /srv/rill/macaroons
   age-keygen -o /srv/rill/custody.key && chmod 600 /srv/rill/custody.key
   ```

3. Create the provider identity, encrypted to that key's public recipient. The
   command prints the identity's x-only public key: that is
   `provider_identity_xonly`, and what clients paste as "Provider identity".

   ```sh
   rill-provider provision-identity --out /srv/rill/provider-identity.age \
       --recipient "$(age-keygen -y /srv/rill/custody.key)" \
       --native-crypto-library "$PWD/tmp/native/librill_crypto.so"
   ```

4. Bake narrow LND macaroons (never use `admin.macaroon` in production):

   ```sh
   lncli bakemacaroon offchain:read info:read --save_to /srv/rill/macaroons/read.macaroon
   lncli bakemacaroon offchain:read offchain:write info:read \
       --save_to /srv/rill/macaroons/payment.macaroon
   # LN to BTC only:
   lncli bakemacaroon invoices:read invoices:write info:read \
       --save_to /srv/rill/macaroons/invoices.macaroon
   ```

5. Copy [`examples/provider.signet.json`](examples/provider.signet.json) to
   `/srv/rill/provider.json` and replace these example values:
   - `provider_identity_xonly`: the key printed in step 3.
   - `custody_recipient`: the output of `age-keygen -y /srv/rill/custody.key`.
   - `native_crypto_library`: the absolute path of `tmp/native/librill_crypto.so`.
   - `bitcoin_core`: Core's signet RPC port (38332 by default) and its `.cookie`.
   - `lnd`: LND's gRPC port and `tls.cert`; the macaroon paths from step 4.
   - `provider_destination_script`: the scriptPubKey hex of a fresh P2WPKH or
     P2TR address of your own (`bitcoin-cli -signet getaddressinfo <address>`);
     claimed swap funds go there.
   - `relay_urls`: Nostr relay WebSocket URLs (`wss://...`) that accept your
     announcements; clients must use one of them. None is supplied here.
   - `relay_proxy`: your Tor `HTTPTunnelPort` URL.
   - `terms`: your amount band (sat), base fee, proportional fee (millionths),
     and any short `slot` label.
   - `authority`: your attestation that the store's volume (any label) is
     outside every backup or snapshot that could be restored, and that only
     this host uses it. Both must be `true`; the store refuses otherwise.

   Leave `network`, `handshake`, and the remaining fields as they are. Relative
   paths resolve from the config file. Core and LND are reached on `127.0.0.1`.
   `tests/test_cli.py` proves the example passes every startup check. For LN to
   BTC, set `handshake.profile` and `terms.profiles` to `ln-to-btc/v1`, add
   `lnd.invoices_macaroon`, and set `bitcoin_core.wallet` to the Core wallet
   that funds swaps.

6. Create the store once, then serve:

   ```sh
   rill-provider provision-store --config /srv/rill/provider.json
   rill-provider serve --config /srv/rill/provider.json   # stop with SIGINT/SIGTERM
   ```

   `serve` warns only if no relay accepts its signed announcement. To confirm
   discovery, in a second terminal with the same environment active and
   `rill-provider/` as the working directory, list verified announcements:

   ```sh
   rill providers list --network ../rill-docs/networks/signet.json        --crypto-library "$PWD/tmp/native/librill_crypto.so"        --relay wss://your.relay --relay-proxy http://127.0.0.1:9080
   ```

   Your identity key should appear with your terms.

**Cooperative claims.** Every new swap negotiates `cooperative-claim/v1`; you
cannot turn it off. After the swap settles, the provider and client cosign a
MuSig2 key-path spend that looks like any single-key Taproot payment. The
cooperative fee equals the unilateral claim fee. If the peer is unreachable or
anything does not match within a short nonrenewing window (at most 30 s), each
side simply uses its own script-path claim or refund, so cooperation never
blocks recovery. Nothing needs configuring.

**Operating.** Back up the custody key and the identity file offline; never
restore an old copy of the store (a restored snapshot is refused rather than
trusted). Keep exactly one `serve` per store. Use `inspect-swaps` to list
retained swaps offline and `reconcile-payment` for a stuck `PAYING` swap. On
upgrade, stop the service, install the new version, and start it again: stores
v8 to v13 upgrade on open; v5 to v7 need `migrate-store` first (below).

The provider's first implementation is an append-only SQLite reservation
ledger. Its explicit `create` operation refuses existing files and remains
unreconciled; `open_existing` never creates or migrates a database. A recorded
reservation atomically covers one complete, immutable, single-cluster input
set. SQLite WAL, synchronous FULL, and a network-bound schema protect local
bookkeeping across ordinary process restarts, subject to SQLite, filesystem,
storage hardware, and backup handling. A missing row or restored snapshot does
not prove a coin is available. The ledger has no coin-selection permission,
release, Core RPC, or funding-ready flag. Funding must remain disabled until a
future wallet/chain and outstanding-intent reconciliation procedure exists.
Deployments sharing treasury coins need coordinated ownership, not just
separate ledgers or application-level network namespaces.

For development alongside the sibling `rill-core` checkout (Python 3.13 or
later, matching its current supported version):

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
mkdir -p tmp
.venv/bin/pytest -q --basetemp=tmp/pytest
.venv/bin/mypy src
.venv/bin/ruff check src tests
```


The explicit `handshake_diagnostic.verify_handshake_diagnostic` uses the pinned
`rill-crypto` Python adapter and a caller-selected **absolute** native library
path to check the three RS-001 handshake envelopes using Core's strict static
verifier. Its caller supplies a trusted provider identity, complete network,
profile, and allowed feature/suite/capability sets independently of the peer's
documents. There is no library discovery fallback, startup loading, key
custody, transport, journal, or side effect. It returns only a transcript
digest. A recorded historical handshake passes again and **cannot** establish
a live session, local provider secret custody, freshness, received order,
payment authority, or permission to fund. Explicit operator installation of
the separately pinned native library is required, a native ABI load failure
is unavailable diagnostic evidence, and input errors are redacted. From a
sibling `rill-crypto` build and this virtual environment, run the opt-in
native interoperability check with:

```sh
RILLSWAP_RUN_NATIVE_CRYPTO=1 \
RILL_CRYPTO_LIBRARY=/absolute/path/to/pinned/librill_crypto.so \
  .venv/bin/pytest -q -m native_crypto --basetemp=tmp/pytest
```

Existing reservation and payment journals are neither opened nor migrated
by this diagnostic. Missing, partial, old, or restored session records prove
no historical safety and must not trigger reconstruction or an action.

`handshake_signing.session_reservation_for_init` constructs a public,
independently constrained binding from bounded inner initiation bytes. The
purpose-scoped `sign_handshake_accept` requires a separately held, currently
available session-key reference and configured provider identity, validates
offered/selected negotiation and signer identity, verifies the returned BIP340
signature, and returns only the identity signature on the **inner** acceptance.
It never admits a session, persists a pending record, sends an accept, or
authorizes funding/payment. The only implementation of the live
`HandshakeCustody` signing interface is an **explicitly test-only in-memory
fixture**: it cannot resume on restart and must never be deployed. Production
signing integration, pending intent/replay store, transport, ordering, and
effect fencing are still missing. Without an independently authoritative,
durably committed response, no acceptance may be sent. Upgrading from the
previous provider release does not create, migrate, or scan any session state;
absent, partial, old, or restored state grants no key allocation or action
authority.

`live_session_store.LiveSessionStore` is the **authoritative** handshake
session store (SQLite `RLS1` v14; v5-v7 require explicit migration and unreleased v1-v4 files are refused unchanged), and the only provider store whose rows may
permit exposing an accept or admitting a confirm. It must be created
explicitly with `LiveSessionStore.provision(...)` and an
`AuthorityDeclaration`, in which the operator attests that the volume is
outside the application's backup and restore domain and is used by a single
host. The store cannot verify that attestation. Behavior:

- `acquire` takes a lifetime exclusive `flock` on the provisioned
  `<db>.owner-lock` inode, with no lease expiry or takeover. It bumps a
  generation counter, and every write checks that generation. A closed or
  superseded handle raises `StaleOwnerError`, and so does a handle inherited
  across `fork` (reacquire in the child instead). If a `COMMIT` fails, the
   outcome is uncertain, so the handle immediately loses usable ownership.
   Normally the physical lock is released immediately and a new owner re-reads
   the stored state. An explicit `retain_owner()` block can defer physical lock
   release until outstanding external RPC execution finishes, including caller
   cancellation drainage. SQLite and native handles still close immediately.
   This owning-thread primitive is not a concurrency gate or new financial
   authority; callers must never use it to keep native/store workers alive.
   Missing recovery or settlement metadata triggers no work on upgrade.
   `reverse_operations.operation()` provides one shared execution gate and a
   fresh task-bound token. Its external workers and cancellation drainage retain
   physical exclusion until actual completion; token cancellation does not
   permanently disable subsequent fresh unilateral recovery. Authoritative
   state must be reloaded after acquiring the gate, and `check()` must precede
    synchronous economic effects. A timeout around a non-worker await must escape
   the operation context, or its handler must explicitly call `abandon()` before
   continuing. Timeout scopes can restore cancellation counts, so checkpoints
    cannot infer those caught timeouts.
    The captured token's `submission_allowed()` provides a worker-safe Boolean
    transport checkpoint using only local owner openness, stop state, and exact
    active-gate membership. Observed cancellation or drainage stops it; an old,
    foreign, or bare token never regains submission permission. It grants no
    financial or signing authority and cannot atomically revoke a started RPC.
    Reverse advancement uses this boundary, reloads its row after acquiring it,
    and retains every Core/LND worker through
   actual completion before releasing physical exclusion. Queued snapshots
   cannot authorize a second cancellation after terminal commitment or skip a
   newly recorded settlement debt. Reverse hold-invoice creation, decoding,
   committed disposition, and unused-invoice cancellation share this gate.
   Quote time is refreshed after acquisition and asynchronous preparation;
   relay delivery stays outside the gate. Cleanup requires a positively created
   invoice matching the original request and an exact matching canonical,
   committed pending ERROR response. Replay, missing or delivered evidence,
   malformed bytes, cancellation, and admission exceptions authorize no new
   cancellation. In particular, an uncertain commit can leave payable terms
   durable, so its invoice remains intact. Payment eligibility expires normally;
   LND may retain historical invoice records. No absent metadata triggers cleanup
   on upgrade. Future cooperative proposal admission is not yet integrated;
   complete cooperative reverse settlement remains an unfinished acceptance gate.
   A preparatory private provenance record binds a freshly committed cooperative
   reverse handshake accept and terms acceptance to this acquired owner. It is
   populated only after successful commits, never from replay or retained rows,
   and is cleared on logical close even while physical exclusion remains pinned.
   Ownership, blocked state, and exact retained context are checked when consumed.
   This is not deadline, payment, nonce, chain, or signing authority. Handshakes
   contain no signed session expiry; mutable activity timestamps are not one.
   Restored or previous-release sessions receive no provenance backfill and keep
   independent unilateral recovery and settlement-debt repayment. The existing
   production rejection of featured reverse acceptance remains unchanged until
   independently verified reverse admission and signing safeguards are complete.
   The preparatory `ReverseCooperationWindow` freezes a maximum 30-second
   monotonic deadline intersecting the signed proposal deadline. Time expiry is
   exclusive, height equality at the signed refund margin is allowed, and any
    observed expiry, abandonment, or monotonic-clock regression is terminal.
    Wall-clock rollback cannot extend its frozen monotonic bound. The window
    also checks a complete evidence-acquisition interval against its own original
    monotonic clock, with an exclusive one-second freshness bound. Invalid,
    incomplete, stale, or expired intervals abandon it permanently. These are
    timing checks only, not financial admission. Internal reverse proposal reservation now
   authenticates the exact client proposal and retained negotiation signatures,
   associates the provider-signed funding message with the exact transaction,
   and freezes a one-shot attempt under the active owner gate. The atomic
   transaction records inbox evidence and a distinct version-2 BURNED binding,
   without a reply, provider sequence advance, preimage debt, or native nonce.
   Existing version-1 signing consumers reject this reservation variant.
   Post-anchor failures remain terminal in owner memory even after rollback;
   another message or cooperation ID cannot renew the window. Exact authenticated
   replay returns only a receipt, including after restart, without restoring
   authority. Funding signatures and bytes do not prove publication or current
   chain confirmation. Financial evidence, settlement-before-signing, actual RPC
   transport fencing, and runtime routing still need integration before reverse
    cooperation can be enabled. No missing record triggers upgrade work or retry.
    Private reverse preimage evidence is stored separately from settlement debt.
    The first canonical signed client proposal is retained immutably, even if its
    deadline expired or its native claim plan is invalid. The writer authenticates
    the accepted context, proposal, terms envelopes, identity-signed provider terms,
    and client acceptance; it does not independently reverify the handshake's
    identity signature. Its receipt and audit-only timestamp prove neither payment
    nor timely disclosure, and grant no signing or settlement authority. Retention
    commits independently of later admission, without advancing sequences,
    blocking refunds, allocating a nonce, or writing financial debt. Reads
    reauthenticate retained evidence. Malformed evidence remains for operator
    review, but existing debt repayment and unilateral recovery never query it.
- Absent, partial, foreign, or newer files are refused before any pragma can
  modify them. Malformed provisioning metadata (UUID or attestation) is also
  refused. The inode numbers of the database and the lock file are recorded
  when the store is provisioned. This catches a copy, or a restore that
  creates a new file. It cannot catch an in-place restore, a lost `-wal` file,
  or inode reuse. Treat the database, its WAL, the lock, and custody state as
  a single deployment boundary that is excluded from restores. Filesystems with
  unstable inode numbers cause the store to refuse (a false refusal, never
  exposure).
- `reserve(init)` reserves one fresh provider challenge per session and
  generates a fresh random provider session key in the same transaction. The
  secret goes into the reservation row as an age ciphertext, encrypted to the
  `custody_recipient` chosen at provisioning. The ciphertext binds the store
  UUID, network, provider identity, session, init digest, and challenge, and
  is verified by decryption before commit. `acquire` requires the matching
  age identity (`custody_identity`) plus a public-key deriver (the native
  `Context`). Keep that identity outside this volume's images; otherwise the
  encryption adds nothing. If custody is missing, corrupt, or substituted,
  the store refuses and never regenerates a key. Keys are retained, because
  there is no closure policy yet, and SQLite deletion would not guarantee
  erasure anyway.
  `commit_accept(accept)` verifies the identity-signed accept against the
  stored init, the reserved challenge, and the reserved custody session key. It then commits the exact bytes to
  the outbox, and only after it returns may those bytes be published. A
  second, different accept for the same session is refused.
- `admit_confirm(confirm)` verifies the full static transcript over the
  committed bytes and admits it atomically. Admission also acknowledges the
  accept in the outbox. An exact replay returns the recorded admission.
  Unverifiable confirms leave no record. Following RS-001, conflicts are
  judged on unsigned canonical bytes, so a different valid signature over the
  same confirm counts as a replay.
- Conflicting unsigned init bytes, or a second validly signed but different
  confirm, are kept as bounded evidence (one row per session and kind) and
  block the session. For init, a stranger can trigger this, and the cost is
  loss of availability, not exposure.

The store does not detect an in-place rollback of the authoritative volume or
a clone on another host. Admission grants no funding, payment, or claim
authority. Upgrading does not create this store. The diagnostic
`PreparedHandshakeStore` and `IssuanceReservationStore` are never read,
migrated, or promoted, and there is still no relay listener or publisher
wired to the store. Two transport operations keep the session secret inside
the store:

- `wrap_pending(message_id, transport=Context)` returns a fresh RS-006 NIP-59
  gift wrap of a committed, still-PENDING outbox message. The wrap is sealed
  by the custody session key and addressed to the client session mailbox from
  the committed transcript. Each call uses a new seal, a new one-time wrapper
  key, and randomized past timestamps.
- `open_mailbox_frame(event, transport=Context)` routes by the single `p` tag
  to one of our session mailboxes and decodes with that session's custody
  secret. It returns the exact canonical envelope bytes, but only if the seal
  author and envelope sender are that session's client key. This is not
  admission: pass the bytes to `admit_confirm`. Every refusal is uniform and
  redacted.

The internal `_nip59_send` wrapper and NIP-44 v2 encryption are the exact
inverse of the receive decoder. They are checked against the official NIP-44
vector and by native round trips. `rotate_epochs(now=, period=, retention=, advertise_for=)` keeps a current RS-006 epoch inbox
key and returns the keys to advertise, newest first. At most 4 are returned,
the RS-005 maximum. A new epoch starts once the newest key is `period` seconds
old. Each key keeps decoding until `created_at + period + retention`, so set
`retention` to at least the announcement lifetime. If the clock moves behind
the newest epoch, rotation is refused. Epoch secrets are age-sealed in the
store and bound to its UUID. `open_epoch_frame(event, now=, transport=)`
decodes a gift-wrapped `handshake_init` sent to an unretired epoch key. It
returns an `EpochInitiation` containing the exact init bytes and authenticated
recipient epoch only if the envelope sender is the seal author. That sender is
still a stranger; pass this object intact to `reserve` for admission checks.
The epoch-inbox schedule is a local availability policy, because RS-005 and
RS-006 do not specify one.

Only keys that stay decodable for `advertise_for` more seconds are
advertised, so a valid announcement never names a key that is about to
retire.

Three limits apply to new sessions only. Replays of known sessions are
never limited.
- `acquire(..., max_sessions=1000)` caps live pre-acceptance sessions
  (`RESERVED`, `ACCEPT_COMMITTED`, `CONFIRMED`). Accepted sessions are retained
  forever but no longer count here; they hold economic reservations instead.
- `max_tombstones=1_000_000` caps permanent legacy expired-session IDs, or
  temporary epoch-bound tombstones independently when that mode is enabled.
- `new_sessions_per_minute=60` is a global, in-memory token bucket.

Capacity is counted from the durable rows, so a restart does not reset it.
A refused session raises `SessionCapacityError`. When the tombstones are
full, new sessions stay refused until the operator acts. Strangers can still
fill capacity, but only at the configured rate.

Economic capacity is separate. Every firm offer atomically creates an
`economic_reservations` row next to its permanent payment-hash reservation,
before the offer is signed. `max_active_reservations` (default 4) caps rows that
are not `RELEASED`, which bounds concurrent financial exposure. When full, a
firm request gets `capacity_unavailable`, and the store refuses the offer even
if a responder ignores that. States:

- `UNSENT`: an open offer, or an accepted swap whose payment was never
  dispatched. Acceptance requires an `UNSENT` or `UNKNOWN` reservation.
- `DISPATCHED`: set in the same transaction that consumes the one-shot
  dispatch grant. A missing or released reservation aborts the grant.
- `UNKNOWN`: migrated history without affirmative provenance. It counts
  against capacity until later evidenced closure.
- `RELEASED`: only with canonical versioned `release_evidence`.

A session holds at most one firm offer (RS-003), and the store refuses a second
one as a backstop. Releases, each atomic with the fact that justifies it:

- `expired-offer`: idle expiry of an open offer, before its session is deleted.
  A migrated `UNKNOWN` row of such a session (no swap ever existed) is
  released the same way: nothing was ever dispatched for it.
- `exposure-expired`: a terminal swap (`FAILED`, `CLAIMED`, `LOST`) whose
  reservation is still held, once Core's tip is past both the signed
  `max_outgoing_htlc_expiry_height` (no Lightning HTLC can still be pending)
  and `refund_lock_height` (the client could refund), plus
  `refund_resolution_confirmations`. Time is affirmative evidence here:
  nothing can change what the swap cost any more. This is what eventually
  frees migrated `UNKNOWN` rows of `FAILED` swaps and failures no payer
  attested. Non-terminal swaps are never released by time alone.
- `failed-before-dispatch`: a transition to terminal `FAILED` while the
  reservation is still `UNSENT`. Every dispatch marks its reservation in the
  same transaction, so `UNSENT` proves no payment was sent, and `FAILED` has no
  outgoing transition.
- `failed-after-dispatch`: a transition to `FAILED` while the reservation is
  `DISPATCHED`, only when the terminal failure was attested by the dispatch
  record's own bound payer (the LND node that sent the sole authorized
  attempt reports the payment `FAILED`, with no HTLC in flight). The dispatch
  grant stays consumed and the payment hash stays reserved forever. A failure
  without attributable payer, or one reported by another node, keeps the
  capacity, and a mismatched attribution is refused.
- `claim-lost`: `CLAIMING` to `LOST`, after the contract output has been
  spent on the confirmed chain by something other than a recorded attempt for
  `refund_resolution_confirmations` blocks (see lost claims below).
- `claim-confirmed`: `CLAIMING` to `CLAIMED`, entered only at the signed
  `settlement_confirmations`. Historical `CLAIMED` rows (for example migrated
  `UNKNOWN`) release only after the engine freshly observes the retained claim
  txid at that depth. The sweep checks one page of 16 per tick and wraps, so
  claims that never confirm cannot starve later ones. This accepts Bitcoin's depth-based reorganization risk.

The engine also fails an accepted swap with no admitted funding binding (the
client may still have broadcast; `ACCEPTED` does not prove "never funded
on-chain") once the invoice
has expired or the fresh tip leaves no room for the final CLTV delta (the same
guard used before paying a funded swap). The transition is terminal and signs a
`payment_failed` observation, and a later funding binding is refused. Without a
fresh tip only invoice expiry closes it. Blocked sessions are closed too; their
conflict evidence is kept. Both deadline guards trust the host clock: a forward
clock jump can irreversibly close valid accepted swaps, so run NTP-synchronized
hosts and alert on clock steps.

Capacity stays held by unresolved `PAYING` swaps (a tracker that never
reaches a terminal outcome keeps the swap open, and the swap is never closed
without evidence) and by terminal swaps until their exposure windows close.
The claim path depends on the retained claim txid; storage integrity is
assumed. Raise
`max_active_reservations` to accept more exposure. Doing so does not resolve
uncertainty, and freeing a slot does not replenish Lightning liquidity.

`expire_idle(now=, idle_timeout=)` expires sessions that sit idle before any
economic step: reserved, accepted, or confirmed with nothing after the
confirm. It deletes their key, messages, and conflict evidence (with SQLite
`secure_delete`) and keeps only a permanent tombstone of the session ID. Any
later init or confirm for that ID gets `SessionExpiredError`, never a second
accept, as RS-001's stable replay rule requires. A late confirm frame cannot
even be decoded any more, so it gets no reply. The service subscribes to
every still-decodable epoch (`receiving_epochs`), not only to the advertised
ones. Ownership loss (`StaleOwnerError`) always stops the service.

The optional `epoch-bound-session/v1` handshake policy changes **new** admission,
not existing contracts. Enabling it requires explicit `migrate-store` with that
feature in the configured handshake policy; the stored policy cannot later
remove it. Known legacy sessions still replay, but new legacy IDs are refused.
Session IDs in this mode bind the full network, provider identity, recipient
epoch, and fresh client key. An optional extension without the required feature
does not opt in. Missing ingress provenance never authorizes admission.

Idle epoch-bound sessions retain temporary tombstones until their recipient
epoch durably retires. The retirement watermark, deletion of expired epoch
secrets, and tombstone pruning share the ownership transaction. Clock rollback
cannot reopen retired epochs. A public epoch-key ledger prevents reuse of a
formerly retired key. It grows with operator-controlled rotations, not inbound
session traffic. Temporary tombstone capacity recovers after retirement, even
if the legacy tombstone quota is full. Total retained storage is **not bounded**:
accepted contracts, legacy replay IDs, payment-hash history, and the public key
ledger remain authoritative. The accepted-session quota is unchanged pending
separate economic admission policy. The service advertises this requirement in
the signed `rillswap/handshake-required-features` extension only when its durable
store policy requires it. The CLI negotiates it without changing legacy
advertisements; offline recovery accepts this known handshake feature but still
rejects unknown contract features. Configure `handshake.features` as
`["epoch-bound-session/v1"]` and run `migrate-store` explicitly before serving
an existing installation. Omitted features keep the existing legacy policy;
there is no silent configuration upgrade. The browser's disconnected Nostr
verifier recognizes the same signed requirement, not live swap authority.

Cooperative MuSig2 claims (`cooperative-claim/v1`) are intrinsic, not a
configuration option: the store policy always includes the feature, every new
session must request it, every new accept echoes it, and every new firm offer
requires it. An installation provisioned before this requirement upgrades its
stored policy by exactly that one feature when it next starts (any other policy
difference still refuses). Existing records keep their signed meaning:
unfeatured sessions replay exactly and their accepted swaps settle and refund
unilaterally as before, but an unfeatured reservation gets no new accept and an
unfeatured session gets no new offer; such clients must negotiate again. The
announcement's required-feature extension is unchanged (clients always request
cooperation).

`record_announcement(created_at)` makes sure
announcement revisions strictly increase across restarts. It runs before
publication, and a clock rollback is refused instead of publishing a lower
revision.

`create_accept(session_id, identity=ProviderIdentity, transport_endpoints=...)`
builds the accept inside the store. It selects the client's most-preferred
supported suite and the supported requested capabilities, in client order.
It binds the reserved challenge and custody session key, gets the signature
from `provider_identity.ProviderIdentity`, and then goes through
`commit_accept`. Calling it again returns the committed accept.

`provider_identity.ProviderIdentity` holds the long-lived identity scalar in
one age-encrypted file. The file is created explicitly with `provision` and
is never replaced. `load` checks the file against the configured identity
key. The identity signs only digests that it derives itself: a typed accept
that names this identity, or a single-network RS-005 announcement
(`build_announcement`, kind 39417). There is no raw-digest signing. The
announcement `revision` equals `created_at`. The real web verifier accepts
these announcements (opt-in interop test). Back up the identity file
separately. It is small, long-lived, and not in the live store's volume.

`relay_client.RelayConnection` is a minimal NIP-01 WebSocket client (aiohttp).
It returns True from `publish` only on an explicit relay `OK`, keeps one
replaceable subscription, and yields raw, unverified event JSON. Publication
means one relay stored the event, never that the peer received it.

`handshake_service.HandshakeService` connects relays to the live store. On
each tick it:
- rotates epoch keys;
- republishes the RS-005 announcement when the keys change or the refresh
  interval elapses;
- resubscribes to the epoch keys and to the open session mailboxes
  (`session_mailboxes`), and reissues the same NIP-01 filter when a live relay
  connection reports dropped ingress events. This asks the relay to replay
  retained history; the provider cannot recover an event the relay discarded or
  that predates the bounded subscription lookback;
- retries the pending outbox.

Each admitted inbound event is one of four things:
- an init on an epoch inbox (`reserve`, then `create_accept`, then wrap and
  publish);
- a confirm on a session mailbox (`admit_confirm`);
- a later signed client request (`answer_request`);
- an authenticated cooperative result (`_admit_cooperative_result`, no reply
  or signing permission by itself).

Dispositions are content-free. The service adds scheduling and retries, never
authority.

`answer_request(document, responder=, signer=)` handles one signed client
`quote_request` (RS-003 quotes) in a single transaction. It checks the client
session-key signature and the contiguous sequence, calls a pure responder,
signs the answer with the session key, and records both the request and the
answer before anything is sent. An exact replay, even with a fresh
signature, returns the recorded answer, which the service re-sends. A
different validly signed message with the same message ID or sequence blocks
the session, whatever its `message_type` (a mailbox message that is not a
valid confirm is classified the same way). Unverifiable, out-of-order, or
over-budget requests (more than 16 per session) get no record and no reply.
The same applies to a validly signed message at the next sequence that is not
a `quote_request`. Nothing is admitted, so the client stream stays at that
sequence.

`quote_policy.answer_quote` is that responder. It prices indicative quotes as
`base + ceil(L * ppm / 1e6)` within the announced bands. It takes the
reference height from Bitcoin Core (`tip_height`, from the optional
`bitcoin_core` config). The service reads it once per tick, never per request,
and answers `capacity_unavailable` when no tip is available or when an offer
would not be representable on the wire. **Firm requests** get identity-signed `ProviderTermsV1`
(`terms_offer`), but only as the first request of a session and only when the
service has both an invoice decoder (optional `lnd` config, via LND
`DecodePayReq`) and a `provider_destination_script`. Otherwise they get
`unsupported_request`. Before decoding, the service runs `classify_request`,
a read-only preflight, so replays and unadmissible messages never reach LND.

The policy refuses an invoice (`invoice_unacceptable`) in these cases:
- the amount is not exactly L;
- it expires within `minimum_invoice_remaining_seconds`;
- it was created in the future;
- its final CLTV does not fit the outgoing budget;
- its payment hash was ever offered before.

The refund lock is `min(tip + max_refund_delay_blocks - 1,
max_refund_lock_height)`. The outgoing HTLC expiry is `tip +
outgoing_cltv_budget_blocks`, which must leave `learn_and_claim_blocks`
before the refund. The policy refuses fees or timing outside the client's
limits (`limits_unsatisfiable`).

Each session's first request creates one provider contract key, sealed to
the custody recipient like the session key (`contract_keys`). The payment
hash is written to `payment_hashes` in the same transaction as the offer.
That table is never deleted, not even when the session expires. A terms
offer grants no funding or payment action by itself.

**Acceptance and settlement.** A signed `terms_accept` that replies to the
recorded offer, before `terms_expiry`, moves the session to `ACCEPTED`
atomically (a `swaps` row). Idle expiry never deletes accepted sessions. The
client's first signed `funding_binding` (revision 0 only) is checked
statically against the terms and recorded as `FUNDING_SEEN`. Both are
answered with `ack`.

With `lnd.payment_macaroon` (offchain read and write) and `bitcoin_core`
configured, the service runs `SettlementEngine` once per tick. Every step is
recorded before its external effect.

**Readiness admission.** With settlement configured, a firm offer is signed
only after LND shows, at that moment, a route for the invoice within the
exact fee limit and absolute expiry height the payment would later use
(`QueryRoutes` through the payment macaroon; LND checks first-hop local
balance, synchronization, and network). No route, no liquidity, or an
unsynced node answers `capacity_unavailable`; nothing is recorded or
dispatched, and the route is discarded. The whole preflight (including
retries while LND reports itself briefly unsynced after a block) shares one
10 second budget that LND enforces, and it is skipped when economic
capacity is already full, so a flood of firm requests delays a settlement
tick by at most one budget. Successful versus refused firm offers expose
whether a route existed at that moment, not the node's liquidity. This is
point-in-time evidence, not a liquidity reservation: size `max_active_reservations` so that many
concurrent swaps at the top amount band fit your outbound capacity. On
signet, testnet4, and mainnet, `serve` refuses to start with firm offers
enabled (`provider_destination_script`) unless `lnd.payment_macaroon` and
`bitcoin_core` configure settlement.

Settlement steps:
- **Funding.** The exact bound output needs `funding_confirmations` on our
  own node (`txindex=1`). The signed `max_outgoing_htlc_expiry_height` must
  still leave the invoice's final CLTV. The swap is then recorded as `PAYING`,
  or as `FAILED` with a `payment_failed` observation.
- **Payment.** LND `TrackPaymentV2` runs first, so a restart never sends
  twice. Read-only `DecodePayReq` and `QueryRoutes` prepare a single route only
  when LND has no payment for the hash and a durable `UNSENT` dispatch grant
  exists. The decoded invoice must equal its signed binding. The route's
  absolute `total_time_lock` must not exceed `E_out`; a relative query limit
  is only a search hint, never authorization. Amount, destination, hop expiries,
  and routing fees are checked, with fees capped by the success fee.
  Before a new send, the engine rechecks the bound output and its confirmations,
  invoice expiry, and session conflict state. A persisted `PAYING` intent alone
  never proves that funding remains valid. Missing or insufficient funding
  defers a new payment, while existing LND attempts continue to be reconciled.
  The dispatch grant is consumed and its exact `SendToRouteV2` request recorded
  before submission. The sender checks current LND sync/network/height and
  invoice expiry again, then sends those bytes once without automatic route
  retries. Blocks arriving between Core/LND samples cannot increase the saved
  route's absolute expiry. RPC failure is ambiguous, not payment failure.
  Conflict blocking and dispatch authorization are ordered in the same store
  transaction. A lost response never restores a grant: missing or `SUBMITTED`
  state permits reconciliation only, not another send. This can leave an
  interrupted swap stalled if the request never reached LND; it does not prove
  payment failure or immediate refund safety.
  Supported invoices are fixed whole-satoshi, nonblinded BOLT11 invoices with
  a payment secret and TLV onion support. Private route hints are preserved;
  the final hop carries the payment-secret MPP record for the full amount.
  Required MPP, AMP, metadata features, unknown features, and legacy invoices
  without payment secrets are rejected during quote decoding, before fundable
  terms. Optional route-blinding capability is allowed on ordinary invoices,
  but actual blinded paths are not. This deliberately favors refusal over
  accepting funds for invoices this single-path sender cannot safely fulfill.
- **Claim.** A verified preimage records `PAID` and sends a `payment_settled`
  observation. The engine then builds the unilateral claim-leaf spend, signed
  inside the store by the sealed contract key. Its fee is Core's conservative
  `estimatesmartfee` for a 6 block target applied to the claim's vsize,
  never below the configured `claim_fee_sat` (also the fallback when Core has
  no estimate, as on a fresh regtest) and never above the escalation maximum.
  Its exact bytes are recorded as `CLAIMING` with a `claim_broadcast`
  observation and as claim attempt 0 (fee and tip height), then broadcast.
- **Claim fee escalation.** The client can refund after `refund_lock_height`,
  so an unconfirmed claim is replaced (opt-in RBF, fresh signature) on a
  schedule rising linearly from the first fee at its first-seen height to the
  maximum six blocks before that height, and held at the maximum from then
  on. The maximum is the signed `max_claim_fee_sat` or, if lower, the largest
  fee that keeps the claim output above the dust floor. A replacement needs a
  new block and must beat the latest fee by 1 sat/vB (BIP125); a target that
  would leave less than one increment below the maximum jumps to the maximum
  so the final replacement is always reachable. Every attempt is recorded before its
  broadcast and kept forever, because any of them may confirm; the attempt
  that reaches `settlement_confirmations` is recorded as `CLAIMED`. A mined
  attempt is never replaced. At most 32 attempts exist, and the last is
  reserved for the maximum fee. Core transport errors never trigger a bump,
  and a "transaction not found" answer counts as absence (bump allowed) only
  while Core reports `txindex` synced (`getindexinfo`);
  a recorded claim that fails validation isolates only that swap with an
  error log. A mined attempt that a reorganization returns to the mempool is
  simply unconfirmed again and keeps escalating; a reorganization deeper than
  `settlement_confirmations` after `CLAIMED` is accepted risk.
- **Lost claims.** When no recorded attempt is mined and the contract output
  is gone from the confirmed chain (`gettxout` without mempool), something
  else may have spent it: the client's refund. A missing output alone proves
  nothing (the funding itself may have been reorganized out), so the engine
  first requires the funding transaction at the signed `funding_confirmations`
  on the active chain and the tip past `refund_lock_height`. It then logs an
  error, anchors the first sighting to the tip height and block hash
  (`outpoint_spent_height`, `outpoint_spent_block`), stops bumping, and moves
  the swap to the terminal `LOST` state once `refund_resolution_confirmations`
  blocks have built on an anchor that is still on the active chain. The
  anchor block leaving the chain, the output reappearing, the funding losing
  depth, or one of our attempts showing depth clears the sighting and the
  wait restarts. `LOST` releases the economic reservation as `claim-lost`:
  the Lightning payment is gone and nothing further can happen to the swap.

**LN to BTC (RS-004).** A service whose `handshake.profile` is
`ln-to-btc/v1` serves that profile only. Firm offers need
`lnd.invoices_macaroon` (`invoices:read` and `invoices:write`, for
`AddHoldInvoice`, `LookupInvoiceV2`, `SettleInvoice`, and `CancelInvoice`) and
`bitcoin_core` with an optional `wallet` that funds contracts; `serve` refuses
to start otherwise. For each new firm request the service opens a hold invoice
for `H` (lifetime `quote.hold_invoice_lifetime`, default 3600 s, which must
cover `minimum_invoice_remaining_seconds + terms_lifetime`) and cancels it
again unless the answer is exactly that terms offer. `ReverseSettlement` then
advances each swap one step per tick:
- `ACCEPTED` to `LN_HELD` once the hold is `ACCEPTED` for exactly `H` with
  every part expiring after `refund_lock_height + 1 +
  refund_and_ln_resolution_blocks`, and while the funding window is open;
  otherwise the hold is canceled and the swap is `ABORTED` (also when the
  invoice expires unpaid).
- `LN_HELD` to `FUNDING_SENT`: the hold is checked again, Core's wallet
  builds and signs (never broadcasts) a payment of exactly `V` to the
  contract at index 0 with locked inputs, refusing a fee above
  `max_funding_fee_sat`. The signed bytes, the reservation marked
  `DISPATCHED`, and a session-signed `funding_binding` for the client are
  committed in one transaction; only then is the transaction broadcast, and
  every later tick rebroadcasts it.
- `FUNDED` at `funding_confirmations`. The engine looks for a spend of the
  contract output (`gettxspendingprevout` for the mempool, then at most 12
  blocks per tick with `getblock` verbosity 2 from a durable scan cursor). A
  spend whose witness holds the preimage of the payment hash first records a
  durable settlement obligation, then settles the hold. Only successful LND
  settlement or an own-LND `SETTLED` lookup permits terminal `SETTLED` and
  reservation release. Any other spender is logged and never settled on.
- Past `refund_lock_height` with no claim, the refund leaf is signed with the
  contract key, recorded (`REFUNDING`), and broadcast. The engine keeps
  looking for a late claim (which still settles). The hold is canceled
  only once the refund has `refund_resolution_confirmations` (`REFUNDED`).

The client normally claims with a cooperative key-path spend that the provider
cosigns (described below); its own script-path claim stays the fallback.

`LndHoldInvoices.settle` accepts optional transport guards: an absolute
monotonic `deadline` and a repeatable, nonconsuming `submission_allowed`
predicate returning exactly `True`. Guarded calls charge setup against a fixed
ten-second budget capped by that deadline, then check again before RPC dispatch.
These guards confer no financial or signing authority, do not atomically exclude
concurrent revocation, and cannot stop an RPC already started. Late RPC results
retain their meaning without retrying. Historical unguarded debt repayment keeps
its post-connect budget. Featured repayment supplies its operation's local
submission predicate through the bound settlement API below.

`LndHoldInvoices.observe_bound_invoice` checks an original, previously
signature-validated invoice binding supplied from authenticated terms. One
credential snapshot and channel perform GetInfo, LookupInvoiceV2, then GetInfo
again within a fixed pre-connect budget. Both node identities and Bitcoin network
labels must match the original payee and configured network; the returned invoice
hash, exact ASCII BOLT11 digest, amount, and timing must match the binding.
The configured invoices credential additionally needs `info:read` for this new
method, with no fallback or startup change. Ordinary lookup remains unchanged;
featured owed repayment uses the bound settlement method below.

The immutable result contains non-atomic Own-LND assertions and the last reported
tip, not current state, an original process identity, exclusive invoice custody,
genesis, or a signet challenge. Observed tip rollback and same-height
reorganization refuse the batch; tip advance proves no ancestry. The caller must
measure the complete observation interval and independently establish freshness,
Own-Core chain evidence, economic eligibility, and authority before any effect.
A late final response can preserve knowledge but never renew authority. No live
financial or signing consumer uses this API yet.

The separate `settle_bound_invoice` transport requires an authenticated,
previously signature-validated original binding and already admitted durable
debt supplied by the trusted caller. It validates the canonical preimage/hash
before credentials, then checks original node/invoice correspondence on the
settlement channel within one fixed budget. ACCEPTED must hold exactly the
original amount; OPEN/CANCELED or inconsistent amounts refuse secret dispatch.
An already SETTLED invoice succeeds without another RPC only when its reported
paid amount covers the original amount. Otherwise it sends SettleInvoice once,
using the original deadline and predicate at actual unary setup.

No credential fallback, retry, post-settlement authentication call, or negative
reclassification of late success occurs. A failure after dispatch can be
ambiguous. Success means only RPC success or sufficiently paid original-invoice
knowledge, not signing eligibility. A gRPC channel can reconnect and does not
prove one physical connection, original process, or exclusive backend custody.
The reverse settlement worker routes authenticated cooperative debt through
this method, capturing its active operation's worker-safe submission predicate.
It persists debt before classification or RPC and never falls back to ordinary
lookup or settlement after a bound failure. Errors retain the obligation and
economic reservation; a later tick can reconcile through this same bound API.
Historical settlement retains its original unbound error-reconciliation path.
An expired cooperation window supplies no new deadline or signing authority.
Positive bound SETTLED reconciliation remains required before future cooperative
partial signing; transport success alone never permits a partial signature.

`observe_bound_settled_invoice` is the separate positive reconciliation query:
the original-bound, identity-bracketed three-read batch must report SETTLED with
paid amount at least the original invoice amount. Exact payment and overpayment
qualify; other states and insufficient payment refuse. It performs no financial
dispatch, retry, or fallback. Like ordinary bound observation, it requires
authenticated original terms and synchronized original LND. At pinned LND
v0.21.0-beta, `GetInfo` maps to `info:read`, but `LookupInvoiceV2` maps to
`invoices:write`, not `invoices:read`. A dedicated observation credential should
grant only the exact URI permissions `/lnrpc.Lightning/GetInfo` and
`/invoicesrpc.Invoices/LookupInvoiceV2`, with external permissions disabled,
instead of broad invoice-write authority. These are method permissions, not
invoice ownership or single-use restrictions. Settlement credentials retain
their separate mutation authority; no automatic credential rotation is added.
Late final knowledge retains its meaning, not freshness or signing authority.
The returned general observation type alone does not prove this stronger query
ran; trusted runtime must collect the actual invocation and independently check
its original window, full evidence interval, chain, fees, and custody. No signing
consumer uses this query yet. Upgrading installations perform no new startup
work, and absent or older stored state supplies no payment evidence.

The pinned ordinary-invoice scenario decodes its existing 1,000-sat REST invoice
and successfully invokes this strict method through the two URI-only permissions.
It refuses OPEN state, characterizes entity-read-only V2 lookup denial, checks
each omitted URI, and requires exact authorization denial for settlement,
cancellation and hold-invoice creation probes. Duplicate/terminal-state errors
are not accepted as permission proof. These probes reuse existing terminal
invoice inputs within owned disposable fixtures, adding no invoice or payment.
This establishes ordinary-invoice correspondence, not merchant proof acquisition,
independent Core correspondence, inventory spending authority or conversion.

The store-owned `_reverse_repayment_binding` getter classifies
archived context, not whether settlement debt exists. Explicit empty contract
features, matching empty or `epoch-bound-session/v1` inner handshake features,
and empty outer handshake/terms-offer features identify historical repayment.
That branch does not parse or reauthenticate opaque historical client acceptance.
Other contexts require authenticated cooperative terms, their original invoice
binding, and matching session, profile, network, transcript, and signatures.
Missing, mixed, unsupported, or invalid archives refuse rather than downgrade.
The getter performs no backend calls, creates no debt or signing authority, and
requires no live proposal or cooperation window. On upgrade, exact supported
historical archives keep legacy repayment. Authenticated cooperative debt
requires original-node access, `info:read`, and synchronized LND. Absent,
partial, mixed, unsupported, or invalid archives retain debt and reservations
without dispatch or refund; operator repair may be needed. Missing debt never
triggers repayment, backfill, or a startup scan.

The private reverse public-key snapshot is preparatory for Core evidence
acquisition. The owner computes native curve results before queuing a worker;
the immutable snapshot holds only public keys, tweak, results, and parities.
Changed ordered compressed keys or tweak refuse. This is exact-input
memoization, not independent cryptographic verification or proof of authority.
The normal funding matcher still checks complete economic/contract commitments.
The internal acquisition entry enforces the owner task and gate before capture;
no production negotiation path calls that entry yet. Startup and stored formats
are unchanged.

The internal `_commit_reverse_proposal_debt` boundary requires an explicit
original-owner acquisition. It
requires fresh original-owner negotiation memory, the exact native-valid
version-2 BURNED reservation and authenticated inbox proposal, a live original
window, `FUNDED`, and no potentially issued refund. Independently acquired
Own-Core and bound Own-LND facts must agree on the named tip, original funding,
invoice, required depth, and safely held exact amount. The complete acquisition
interval must remain younger than one second on the original window's clock.
Those typed facts are not provenance or authorization by themselves: the trusted
runtime must collect them under the same operation and clock dependency.

Its transaction writes only settlement debt and audit time, before any later
settlement RPC. Failed pre-COMMIT checks, including after the tentative SQL
update, roll back debt and abandon cooperation without erasing separately
committed knowledge. An uncertain COMMIT may retain debt while closing ownership;
failure to return is not proof that debt was absent. Independent repayment resumes
any valid retained obligation without reconstructing cooperation.
Historical/restarted, expired, invalid-plan, or refund-issued proposals receive
no new debt through this path. Existing debt uses its classified independent
repayment path; its expiry or restart never renews signing. No production
negotiation caller or native nonce allocation uses this boundary yet. Featured
repayment uses the original-backend bound path described above, not the
acquisition observations as authorization for another connection.

`ReverseSettlement._acquire_proposal_debt` is an internal, nonactivated consumer
of that writer. Inside one store-owned operation it retains authenticated private
knowledge, reserves the exact proposal, and preflights the original live context.
Replays, including after restart, return receipts without backend work, new
windows, or debt. Fresh acquisition captures public curve results on the owner,
then collects Core and original-invoice LND observations in physically drained
workers. It samples the original window's monotonic clock around the entire
batch, including executor queue delay; the window also checks its original wall
clock. Debt still requires a complete interval strictly younger than one second
at commit, plus all existing financial prerequisites.

LND receives the captured operation/window submission predicate, not an absolute
deadline copied from a different clock domain. Its real-monotonic transport
budget remains separate. Expiry, backend failure, cancellation, or owner loss
abandons cooperation without clearing knowledge or any already committed debt.
No settlement RPC, nonce, partial signature, reply, or production negotiation is
enabled by this entry. Evidence eligibility is bounded, not physical execution:
a started read may outlive expiry, and a trickling Core endpoint can retain the
gate indefinitely while drainage preserves exclusion. Upgrading installations
gain no startup action; absent original memory and partial or older reservations
never trigger acquisition or reconstruct authority.

The private live-proposal context getter requires an explicit purpose.
Acquisition still requires FUNDED without debt. The preparatory paid-signing
purpose requires local SETTLED with the exact authenticated proposal preimage,
the original process-local window and negotiation, and the unchanged owned
native-valid version-2 BURNED cooperation reservation without refund artifacts.
Released economic exposure after repayment does not erase that distinct
cooperation reservation. No paid-signing consumer exists yet. Local SETTLED does
not prove repayment provenance or current original-node payment; future signing
still requires fresh actual bound positive SETTLED, Core, fee, custody, and
original-clock evidence. The getter changes no durable lifecycle state, but a
failed live-context check abandons its in-memory window terminally. Reconcile
repayment before requesting paid context, never probe and retry. Unknown or
omitted purposes cannot select a default policy. Restarted paid state remains
history and triggers no new work or reconstructed signing permission.

The internal `_preflight_paid_proposal` collects fresh Core confirmed-unspent
and strict fee-policy evidence plus an actual `observe_bound_settled_invoice`
call under that same original window and operation. It requires an explicit
positive configured absolute fee floor. Public networks require a positive
conservative estimate within the signed horizon, and every network enforces
relay/mempool floors. Only an explicit boolean regtest exemption permits an
unavailable estimate. All named tips must match; the exact native proposal plan
must cover the resulting floor at its final key-path vsize. Final owner/native
context revalidation counts toward the complete interval strictly younger than
one second. The signed reverse height bound remains inclusive.

This preflight performs no nonce allocation, signature, reply, settlement RPC,
or durable lifecycle update. It has no production caller. A diagnostic success
is not transferable permission; future signing must establish fresh evidence
and uninterrupted original ownership through the effect. Matching named tips
does not make separate Core/LND reads atomic. An isolated pinned regtest case
now exercises native original-session context, actual wallet funding and two
confirmations, proposal-debt acquisition, one bound settlement dispatch, and
paid preflight under the unchanged real-clock window. The measured complete
acquisition and preflight intervals remain strictly below one second. It creates
no provider MuSig nonce and explicitly bypasses the still-disabled reverse
acceptance guard only in the fixture; it is not relay, client nonce-custody, or
production-signing acceptance. An actual blocked executor queue is also checked
to consume that complete interval. Broader adversarial/public-network acceptance
and authority-bearing integration remain separate requirements. Neither these
checks nor their absence trigger startup or migration work.

Paid observation batches are private records bound to the exact collecting
operation, not just the surviving original window. They are neither serialized
authority nor proof that the stronger query or original clock was used. Trusted
runtime collects actual backend observations without holding a SQL transaction;
the store revalidates authenticated context, native plan, facts, fees, and age
inside the caller's explicit owner transaction. A different operation cannot
consume an otherwise fresh batch. The connection-taking context guard avoids
nested transaction acquisition. Diagnostic success still rechecks freshness
after COMMIT, so transaction-exit latency cannot escape the one-second limit.
This separation adds no native signing or startup action. Future native effects
must collect and authorize through consumption and commit in one uninterrupted
original operation/window, never await a diagnostic and then assume permission.

The internal store-owned `_commit_reverse_signed_reply` is a separate,
nonactivated native effect. It requires that exact operation's actually
collected paid evidence, revalidates the original reservation and full interval
around private contract-key decryption and native work, and permanently
tombstones allocation before native begin. It consumes the provider attempt
once, closes custody, independently verifies its partial, and atomically archives
one session-signed, proposal-correlated reply containing provider nonce and
partial. Both attempt response IDs reference that same real envelope.

No scalar, native handle, nonce, or partial is returned before the transaction
commits. COMPLETE means the exact provider contribution and response were
archived, not client broadcast or claim confirmation. An ABANDONED attempt may
already have consumed its native nonce with the result lost. Neither state clears
debt, changes capacity, or permits a refund. Failure, rollback, cancellation, or
uncertain COMMIT never permits regeneration; uncertain COMMIT fences ownership
and may leave the exact completed archive. Fresh ownership abandons unfinished
attempts and never reconstructs signing permission.

Authorization is checked immediately before COMMIT, not guaranteed at return
time. A slow successful COMMIT preserves its archived contribution without
renewing its original deadline; future delivery must establish its own allowed
handoff and cannot reinterpret the bytes as fresh signing authority. This
primitive has no production caller. Archived reply routing, live client custody,
and public/adversarial activation acceptance remain separate work. Schema 14,
stored formats, and startup behavior are unchanged.

The internal `_reverse_signed_reply_replay` read returns the exact archived
reply bytes for a repeated proposal (a fresh client signature over identical
unsigned content is accepted). It authenticates the historical agreement and
proposal, requires the exact admitted inbox record, a strict canonical v2
reservation binding with matching proposal fields, complete nonce/partial
artifacts with paired response IDs, and exactly one correlated outbox reply
whose provider session signature and payload match the attempt. It does not
re-derive the funding plan, re-verify the partial, consult Core or LND, or need
contract-key custody or funding archives; the original committing writer
established those invariants. It still depends on the configured profile,
network, and supported features. An absent row or an unfinished state
(BURNED, NONCE_READY, SIGNING, ABANDONED) returns no artifact and never authorizes
repair, regeneration, or a new nonce. A malformed, partial, or ambiguous COMPLETE
archive is refused without writes. Retrieval works for blocked sessions and
acknowledged replies; it is historical knowledge, not delivery or signing
authority. Upgrading installations need no migration: no prior release wrote
reverse COMPLETE rows.

At runtime, an `ln-to-btc/v1` service routes each inbound
`cooperative_claim_propose` request to `ReverseSettlement.cosign_cooperative_proposal`.
Under the proposal's original window it admits the debt from fresh Core and LND
facts, repays by settling the bound hold invoice, collects fresh paid evidence,
and commits the one-shot signed reply, which the outbox then delivers. A
relayed duplicate gets only the exact archived reply. Any refusal (unpaid
invoice, fee below the fresh floor, expired window, closed readiness) sends no
reply and never signs; the client keeps its unilateral claim. The fee floor is
the engine setting `cooperative_fee_floor_sat` (default 1 sat) on top of the
fresh Core estimate; `allow_regtest_fixed_fee` exists only for regtest.

The dedicated `provider-lnd` CI job builds native crypto and runs opt-in backend
tests against fresh digest-pinned Core/LND/Python containers. Its sidecars use
read-only sources and certificates, private tmpfs wallets/custody, and verified
owned-container cleanup, never public-network funding. The native scenario
alone enables a fresh Core transaction index and actual cookie authentication
alongside test-only named `rpcauth`; the private cookie is streamed directly to
an exclusive mode-0600 file without logging credentials. Existing settlement and
cancellation scenarios retain their original defaults.

A retained matching preimage in `FUNDED` or `REFUNDING` means settlement is
owed, not that LND settlement succeeded. Restart retries that obligation
without needing Core or rediscovering a disappeared witness. Under serialized
owner ticks, refund progression and invoice cancellation cannot supersede it.
The store fences refund transitions, not concurrent external LND cancellation;
future concurrent intent admission must preserve that execution boundary.
The checked writer preserves
the original preimage and does not release capacity, publish a success
observation, or start cooperation. It relies on the existing authorized funding
and trusted own-Core witness observation, not peer-deserialized evidence.

This uses the existing preimage column without a schema migration. An upgrading
installation with no nonterminal preimage retains existing processing; absence
does not prove an unpaid invoice or create a recovery action. Older terminal
`SETTLED` rows remain terminal. Malformed or inconsistent intent fails closed.
A preimage already lost by a previous-release crash cannot be reconstructed by
this fix and remains an unresolved recovery case.

### Cooperative repayment sync refusals

Original cooperative debt repayment may observe LND briefly unsynchronized after
a block. The bound adapter distinguishes only a sync refusal inside its read-only
GetInfo/LookupInvoice/GetInfo checks before the sole SettleInvoice dispatch. This
trusted local signal proves no dispatch by that invocation, not the absence of an
earlier submission, payment, custody, or renewed permission.

Only the already-admitted original bound debt can be resampled, with four attempts
total and the existing 0.5-second cadence. Each remaining attempt reacquires the
owner gate and authenticates the same original proposal, funding binding, exact
preimage, burned reservation and nonrenewing window. It cannot take another
funding, refund or legacy-settlement branch. Missing work is not proof of payment;
an affirmative original SETTLED join and fresh financial observations remain
required before one scope-bound nonce and archived reply. Generic sync errors,
setup failures and ambiguous post-dispatch errors do not authorize resampling.

Expiry, refusal and cancellation after context acquisition abandon the original
window. Cancellation while awaiting the initial gate cannot recover that context;
it leaves the reservation burned and replay empty, never a fresh signing right.
Late known repayment success remains recorded even when signing has expired.
Existing independently owed debt repayment is unchanged. No schema, startup,
backfill or reconstruction changes are added on upgrade; absent or partial live
state confers no cooperation rights. This bounded fix does not establish general
cooperative stability, rollback safety or production readiness.

### Operator entrypoint

```sh
rill-provider provision-identity --out id.age --recipient age1... \
    --native-crypto-library /path/librill_crypto.so   # prints the identity key
rill-provider provision-store --config provider.json
rill-provider serve --config provider.json           # until SIGINT/SIGTERM
```

A v8, v9, v10, v11, v12, or v13 store upgrades to v14 automatically when `serve` (or any
command) opens it. v9 adds the `claim_attempts` table, and each `CLAIMING` swap's
retained claim becomes attempt 0 with an unknown fee and height, which the
engine validates and observes before any bump. v10 rebuilds `swaps` with the
terminal `LOST` state and NULL `outpoint_spent_height`/`outpoint_spent_block`
on every existing row, so no swap changes state and lost-claim observation starts from scratch.
v11 rebuilds `swaps` with the LN to BTC states (`LN_HELD`, `FUNDING_SENT`,
`FUNDED`, `SETTLED`, `REFUNDING`, `REFUNDED`, `ABORTED`) and NULL
`funding_txid`, `funding_vout`, `funding_tx`, `refund_txid`, `refund_tx`,
and `spend_scan_height` on every existing row; v10 stores upgrade on open.
v12 adds an empty cooperation-attempt ledger without modifying existing swaps
or granting signing permission. Old accepted swaps remain unilateral. A missing
attempt row never authorizes allocating a nonce, and an interrupted migration
rolls back its schema and both version markers. Every unfinished cooperation
burn is abandoned on the next store acquisition; its ID is never reissued, and
no native nonce handle is reconstructed from persistent state. Older binaries
refuse a v9, v10, v11, or v12 store. v13 adds an **empty** claim-arbitration
table; it does not backfill admission, delay a previously accepted swap's
unilateral claim, sign, broadcast, or infer work from a missing row. Any
unfinished future arbitration window is closed on reacquisition without
restarting its deadline; retained fallback and completed bytes are preserved.
v14 adds an **empty** reverse-preimage-evidence table after authoritative
namespace, custody, and ownership validation. An installation upgrading from v13
preserves its accepted swaps, existing settlement debt, and completed cooperation
evidence. Established acquisition behavior still abandons unfinished nonce
attempts and closes unfinished arbitration windows. Missing evidence remains
unknown: there is no backfill, scan, RPC, payment retry, debt conversion, or new
signing permission. Partial schemas refuse without repair; interrupted DDL rolls
back the table and both version markers. A binary rollback from v14 is not
supported. Mainnet serving, in either direction, stays refused until a release
accepts it.

On the current version, a *new* BTC-to-LN acceptance can record an `ADMITTED`
arbitration row only when both retained authenticated handshake halves and the
identity-signed offer require `cooperative-claim/v1`, the client's nested
acceptance is independently signature-verified, and the signed acknowledgment
is bound to that contract in the same transaction. Mixed feature commitments
are refused instead of silently downgraded. Old or fully unfeatured accepted
swaps get no row. `ADMITTED` alone starts no cooperation window and does not
delay the normal unilateral claim. Every new live quote requires this feature.

Upgrading an authoritative v5, v6, or v7 installation is an explicit offline operation:

```sh
rill-provider migrate-store --config provider.json
```

Stop the old service first. This takes the existing exclusive owner lock,
verifies the exact predecessor schema, namespace, custody recipient, and original
file inodes, then adds v7 epoch custody (and dispatch custody for v5) in one
transaction. Existing epoch rows seed the public-key history; old sessions never
gain epoch admission metadata. The initial retirement watermark is zero; later
pruning requires an affirmative expired epoch record. A missing v7 watermark or
table is corruption, not permission to reconstruct it.
The v8 step backfills one economic reservation per retained payment hash:
`UNSENT` for an offer whose session is still before acceptance, `RELEASED` with
`{"reason":"expired-offer","source":"migration"}` evidence when the session was
tombstoned and has no session or swap row, and `UNKNOWN` for everything else,
including every accepted swap and any hash without a tombstone (absence proves
nothing). A swap without a payment-hash reservation is inconsistent custody and
refuses the whole upgrade. The check uses the exact hash bound by the
retained accepted offer, not any hash of that session. Upgraded providers with many retained swaps can
therefore start at or above `max_active_reservations`.
It does not start relays, scan a chain, send payments, publish messages, or delete
history. Interrupted upgrades roll back; `serve` never migrates a v5 to v7 store.
Missing, partial, copied, foreign, and unsupported older stores remain refused.
An already-current store is safe to pass to this command again.

No old swap is backfilled as `UNSENT`. Existing `PAYING` swaps reconcile with
LND but cannot start another payment merely because tracking returns not found.
An existing `FUNDING_SEEN` swap can obtain a new grant only through its normal
checked transition to `PAYING`. Keys, preimages, contracts, and payment-hash
reservations are retained. This migration is not restored-snapshot reconciliation.
Existing v6 dispatch grants remain unchanged during migration. Consumed grants
remain consumed, including older relative-send records. New dispatch records
are version 1: they identify `SendToRouteV2`, retain the exact protobuf bytes as
hex, and bind the payer (the LND `identity_pubkey` attested by `GetInfo` during
preparation, plus the configured network identity). No saved request, old or
new, is automatically replayed.
Previously accepted but unsent invoices outside the newly supported routing
subset fail before dispatch if tracking establishes no existing payment and
the store has an explicit unsent grant. Unknown or consumed grants still permit
reconciliation only. Neither case shortens the client's on-chain refund delay.

For bounded offline inspection, stop the service and run:

```sh
rill-provider inspect-swaps --config provider.json --limit 100
rill-provider inspect-swaps --config provider.json --session-id <session-id>
rill-provider inspect-swaps --config provider.json --after <next_after>
```

This takes the same authoritative owner lock and validates namespace, custody,
schema, and file identity. Acquisition advances only the owner generation; the
command does not run settlement, load the provider signing identity, connect to
Core/LND/relays, migrate a store, or change swap and dispatch records. An old,
partial, copied, or currently owned store is refused, not repaired.

Output is `rillswap/provider-swap-inspection/v1` JSON with
`action_authority: "none"`, a bounded `swaps` page, and an exclusive `next_after`
cursor (null at the end). Limits are 1 to 1000, default 100. Pagination uses the
session-ID index; separate invocations are not a shared snapshot. An empty page
does not prove that no external payment exists. Missing session rows are shown,
not silently omitted. Ownership verification still includes the existing whole
database integrity check; the page limit bounds output, not total startup cost.

The summary includes stored state, conflict blocking, dispatch state, public
contract/claim identifiers, and presence flags for recovery material. It never
prints invoices, payment hashes, preimages, secret keys, route details, or exact
dispatch bytes. Presence flags do not validate that material. `UNKNOWN` dispatch
state is not evidence of an unsent payment, and `UNSENT` still requires every
live funding, deadline, and conflict check. This command never grants resend,
refund, deletion, or admission-capacity authority.

For bounded payment-witness reconciliation, stop the service and run:

```sh
rill-provider reconcile-payment --config provider.json --session-id <session-id>
```

This explicitly queries `TrackPaymentV2` for one retained `PAYING` swap, using
the configured LND read macaroon (not `payment_macaroon`). It is currently
loopback/regtest-only. It takes the same authoritative owner lock, never runs
the service, never prepares or submits a payment, and never connects to Core or
relays. The tracking RPC has a five-second deadline; an active payment may time
out instead of returning `IN_FLIGHT`. Backend errors fail closed, without
changing payment state. Store acquisition still performs the full integrity
check and advances the owner generation.

A reported success is independently checked against the retained contract's
payment hash. A matching preimage is atomically retained with `PAID` and the
signed peer observation, so normal settlement can resume the claim path after
restart. It proves a usable hashlock witness, not which payer settled the
invoice. The redacted `rillswap/provider-payment-reconciliation/v1` JSON result
contains only `session_id`, `payment_status`, `swap_state`, and `state_changed`.
It does not print the preimage, invoice, payment hash, credentials, or route.

`UNKNOWN`, `IN_FLIGHT`, and even a backend-reported `FAILED` preserve `PAYING`
and every dispatch record. This command tracks without payer attestation, so
another configured node's failed record cannot prove the original payment
failed. Missing records are never resend permission. This command grants no
refund, retry, deletion, or economic-capacity release authority. It performs
no reconciliation automatically.

Payer binding: preparation, submission, the post-failure fallback lookup, and
bound tracking each use one credential snapshot and one gRPC channel, and run
`GetInfo` on that channel before the payment RPC. A different identity or
network refuses the call (submission is not attempted, the consumed grant is
not restored, and the swap stays `PAYING`). For a valid version 1 record,
normal settlement tracks with this attestation, and a `FAILED` result from the
matching payer becomes terminal `FAILED` under the same trusted-LND assumption
as an immediate send failure. This is not rollback-safe evidence (a restored
LND database with the same identity is indistinguishable) and grants no resend
or economic-capacity release.

The shared sender also accepts an optional absolute monotonic deadline and
nonconsuming submission predicate for original client lifetimes. These cap the
normal 60-second submission budget, require an affirmative `True`, and fence
both sides of the predicate, after node attestation and after RPC setup before
`SendToRouteV2`. Predicate failures are redacted. Expiry or revocation prevents
new submission; it cannot undo an RPC already started. A late successful result
still reports payment knowledge and never renews signing authority. The reverse
client propagates its original lifetime through the hold payer to this boundary.
No stored dispatch is retried. Physical RPC completion and cleanup can outlive
the authorization budget; feature activation and release remain gated.

Absent, legacy (unversioned or relative-send), partial, malformed, other-hash,
or other-network records bind no payer. For them normal settlement still defers
a tracked `FAILED` result without changing the swap or its grant, and a later
matching witness remains recoverable. Existing `PAYING` swaps need no payer
migration and are never upgraded to bound records; previously terminal `FAILED`
rows are not automatically reopened. Legitimate failures of legacy dispatches
after a lost response can therefore remain `PAYING` indefinitely. Definitive
failure recovery and economic-capacity release remain production gates.

`provider.json` is strict JSON (`operator_config.OperatorConfig`, unknown
fields refused). It sets the network identity, the identity key printed
above, the identity and store paths, the age `custody_recipient`, the
`custody_identity_file`, the native crypto library, the `authority`
attestation, the negotiated `handshake` selection, the public `terms`,
`relay_urls` (with `relay_proxy`, a loopback Tor `HTTPTunnelPort` URL such as
`http://127.0.0.1:9080`, required on signet, testnet4, and mainnet unless
`allow_direct_relays` explicitly accepts exposing the host's IP address to
relays; proxied relays must be `wss://`), the optional `bitcoin_core` (`port`, `cookie_file`) and `quote`
settings, and optional schedules and limits (`max_sessions`,
`max_tombstones`, `new_sessions_per_minute`, `max_active_reservations`; `handshake_timeout`, default 600 s of idleness before a
pre-economic session expires; `max_sends_per_tick`). Relative paths resolve from the
config's directory. The config holds no secrets. The custody identity file
must be a regular, owner-owned `0600` file with exactly one
`AGE-SECRET-KEY-` line. Keep it out of the store volume's images. Both
provisioning commands refuse to overwrite anything. Refusals print one
redacted line and exit with status 2.

`handshake_custody_offline.OfflineHandshakeCustody` is an optional, **offline
key-availability primitive**, deliberately not an implementation of the live
signing interface. Its protected age X25519 identity is an external operator
root, supplied explicitly at `create_new` and `open_existing` and backed up
separately. The API explicitly provisions a new identity and then a session
key for one complete `SessionReservation` in immutable X25519-encrypted files.
It returns public `IdentityRef`/`SessionKeyRef` values, which the operator must
pin outside the writable store. `open_existing` requires the previously pinned
custody ID and complete network; `require_identity_exact` and
`require_session_exact` only check that the expected key is locally available
and bound to the recorded public intent. These calls never allocate missing
keys. No API exposes the decrypted private scalars for signing, sends or
receives a handshake, opens the PREPARED SQLite registry, or grants session,
funding, payment, or recovery authority. Treat the protected identity and the
trusted local private directory **and its ancestors** as sensitive. The
implementation uses owner-private directories and files, `O_NOFOLLOW` on the
final component, create-only hard links, bounded ciphertext/plaintext, exact
readback, and file/directory fsync; it does not defend against an untrusted
ancestor-path writer, a compromised process, or stolen decryption credentials.
An interruption after publication has an **uncertain** result and must be
reconciled manually; never retry, replace, or regenerate based on absent,
partial, older, newer, or restored files. Even a valid restored encrypted copy
can omit later allocations and can pass every exact local check: age encryption
protects confidentiality and integrity, **not freshness or provenance**.
These files have never existed in earlier releases, so upgrading does not
create or migrate them and no startup path reads them. Independent non-rollback
admission ownership, protected production signing, and authenticated ordered
delivery remain required before this primitive can be connected to live swaps.

`_nip44_v2` is an **internal, disconnected NIP-44 v2 decoder** exercised by
official, attributed interoperability vectors. It uses the matching native
`rill-crypto` optional constant-time ECDH primitive and a pinned ChaCha20
backend. It bounds encoded payloads to 128 KiB, checks canonical base64,
version, size, HMAC **before** decryption, padding, and UTF-8, and returns
only decoded text to an in-process caller. NIP-44 requires verifying the
enclosing signed NIP-01 event **before** calling this decoder; there is no
provider caller, relay subscription, signed event verifier, NIP-59 gift-wrap
or seal processing, authenticated application frame, or session admission.
Never pass relay input directly to this private helper. Missing or mismatched
native capability produces a distinct sanitized configuration failure; an
unsupported version is distinct from malformed v2 input. Neither the native
ECDH result nor decoded Python text is guaranteed erased from process memory.
An installation upgrading from the previous release gains a dependency and
these unused functions only: absent, partial, older, or restored transport
state cannot enable receive, key creation, migration, a rescan, or a swap.

`_nip01_event` is another **disconnected internal primitive**. It verifies a
bounded NIP-01 signed event's seven fields, recomputed compact-JSON ID, and
native BIP340 signature. Its exact-member, tag-shape, and timestamp bounds
are a stricter RillSwap input policy, not universal Nostr rules. The verifier
does not check event kind, recipient routing, peer session ownership, rumor
author, or application transcript. No relay traffic reaches it yet. Raw
events may remain in caller-owned memory; exception handling does not erase
caller frames or the signed event returned on success. Existing installations
gain no transport activation or state migration from this module.

`_nip59_receive` composes those two internal primitives into a **disconnected,
read-only candidate decoder** for the private-regtest RS-006 binding. The
caller explicitly supplies the selected mailbox scalar and independently
expected mailbox public key, complete network and profile. It verifies the
signed outer gift wrap **before** decrypting, requires durable kind 1059 and
exactly one matching recipient `p`, then verifies the signed empty-tag
kind-13 seal **before** decrypting its unsigned rumor. It checks exact rumor
kind/tags/ID, the direct canonical RS-001 envelope and its 16 KiB bound, and
equality of seal author, rumor author, and envelope sender. It returns only an
`_UntrustedFrameCandidate`: even a perfectly valid candidate can come from a
stranger addressing a public inbox. This module cannot prove which key role
the supplied scalar was assigned, sender freshness, authenticated session
ownership, negotiated handshake, application signature/transcript validity,
replay disposition, or financial effect safety. There is still **no relay
listener, producer, durable inbox/outbox, admission, or sending path**. Test
wrappers use isolated synthetic credentials, not independent external Nostr
interoperability. An existing installation receives no transport listener,
state read, or migration from this code; missing, partial, old, or restored
transport records cannot activate it.

`RILLSWAP_RUN_WEB_NIP59=1 RILL_CRYPTO_LIBRARY=/absolute/path/to/librill_crypto.so
 .venv/bin/pytest -q -m web_nip59_interop` is an **opt-in local** test against
the sibling working-tree web producer and docs authentication vectors. Install
the web `bun.lock` dependencies first. It covers both regtest settlement
profiles using real fixture-signed RS-001 envelopes, independent Bun
construction and native provider decoding. Missing Bun, configured native
crypto library, fixture, or web dependencies fails the explicit opt-in instead
of skipping it.
Repeated fresh wraps preserve the signed application message while changing
the outer identity; replaying one wrap still decodes. Session admission and
replay disposition are **not exercised**. This is neither relay delivery nor
authorization. The v2 local integration lock executes these two exact cases
from pinned clean archives, but it does not establish a release set.

An explicit historical baseline gate lives at
`scripts/check_integration_lock.py`. In the monorepo, run the **root wrapper**
`../scripts/replay_provider_v2.py --source-root ..` instead. It verifies the
original v2 lock and runner and creates disposable Git views of the six pinned
commits before calling this unchanged historical gate. The commands below are
for older separate checkouts with six nested `.git` directories. Use a trusted
Python 3.14 environment, `uv`, CMake, a C compiler, Bun **1.3.11**, and network
access to the pinned upstream native source and Python/Bun dependency indexes:

```sh
.venv/bin/python scripts/check_integration_lock.py --source-root .. --verify-only
.venv/bin/python scripts/check_integration_lock.py --source-root ..
```

`integration-lock.json` v2 records **six exact Git commits and trees**, two
independently compared Python producer-wheel SHA-256 digests, the exact
53-case native inventory (including all 23 historical v1 cases), and the
two-profile web NIP-59 interoperability
inventory. The runner archives the five **consumed** components (docs, crypto,
core, provider, web); the historical CLI pin remains reference-only, **not**
tested or representative of current CLI HEAD. Missing, partial, unsupported,
unavailable, or changed source refs refuse execution. After preflighting the
exact Bun version, it checks that the executing runner matches the pinned
provider source, installs archived web dependencies with a frozen `bun.lock`
and ignored lifecycle scripts, builds crypto/core/provider from clean
archives, compiles and tests native crypto, compares producer-wheel digests
before installing **non-editable wheels** into a disposable venv, and requires
both separate provider test inventories to execute without skips or failures.
The printed receipt includes executing runner and lock hashes, actual consumed
artifact digests, and `authority: none`. The native shared library and
provider wheel are **recorded, not independently release-pinned**; Python
packages use version pins rather than verified hashes, and Bun package
integrity depends on the pinned lock and trusted registry/toolchain. This
snapshot pins the provider commit immediately **before the v2 lock update**:
a file committed inside provider cannot contain its own resulting commit ID.
The runner still accepts an explicitly supplied historical v1 lock and runs
only its original 23 native cases; it does not silently upgrade v1 to web
coverage. No startup, sync, database, or persisted application state changes
on upgrade. Missing, partial, older, or restored integration metadata proves
no release readiness and never triggers automatic rebuilds or scans. This is
local interoperability evidence, not a relay, session, money-path, hosted CI,
or live-swap authorization. Re-pin and execute all gates before any release.

`handshake_store.PreparedHandshakeStore` is a separate **offline-only**,
explicitly bootstrapped SQLite PREPARED registry. It can record a canonical
RS-001 initiation and acceptance pair, a validated provider identity signature
on the inner acceptance, and a **public** custody reference in one committed
transaction. Both outer handshake envelopes are unsigned. It neither receives
or authenticates a live client, provisions a secret, signs, publishes, admits a
session, nor enables retry/send/payment. It requires a trusted local directory
and native signature verifier chosen by the caller. A result retrieved from
the local store is not freshly authenticated: its versioned checksum detects
accidental changes, not database writers who can recompute it, missing rows in
a restored snapshot, or changes on other replicas. A PREPARED row proves only
that this copy recorded those bytes, not key availability or delivery. An
UNKNOWN lookup is **not** proof of an unused session. Previous-release
installations have no such store and remain unchanged: creation requires an
explicit call, and opening absent, partial, older, newer, foreign, or corrupt
state fails closed without migration or replacement. A locally valid restored
copy can omit later prepared entries; no local marker can fence rollback or
establish globally exclusive acceptance. Any future sender requires durable
production custody, authoritative non-rollback writer fencing, inbox/outbox
ordering, transport authentication, and independent recovery handling for
already-funded or inflight sessions. No code calls this registry at startup.

`issuance_reservation.IssuanceReservationStore` is a **separate, explicitly
created reservation-only** SQLite store for a canonical RS-001 initiation. It
binds the full network, provider identity, and local supported negotiation
policy; on an explicit `reserve_init(canonical_init_bytes)` call it durably
records the unsigned initiation's bytes/digests, stream sequence zero, and a
locally generated independent provider challenge before returning it. An
identical retry returns the same challenge. Different valid canonical bytes
under the same session ID mark that session permanently `CONFLICT` in this
copy, even if the self-declared sender key changes. This conservatively blocks
ambiguous reservations at the cost of availability. **The initiation is
unsigned**: a stranger able to submit such a collision can poison a session.
Conflict is not proof that the client
equivocated. The record checksum detects accidental logical edits, not
malicious writers or backup rollback. Missing records are **unknown**, never
freshness evidence. The store signs nothing, sends nothing, owns no received
relay event, does not authenticate a client or admit a session, and grants no
financial authority. Neither this store nor the offline PREPARED v1 store may
be inferred to certify the other's rows. An older valid restored copy may omit
already used challenges; no live acceptance can depend on either copy until
independent rollback-safe ownership and external effect fencing exist.
Previous-release installations are unchanged: no automatic creation,
migration, import of prepared rows, issuance, rescan, key rotation, or startup
operation. Opening absent, partial, unsupported-version, or foreign files
refuses them without repair; only explicit operator-controlled creation of a
new file can reserve a challenge. Do not expose the challenge through a
handshake accept until separately durable signed-result and outbox ownership
exist.

The separate `core_tx_bytes.CoreTransactionReader` is an explicit,
read-only Bitcoin Core v30 RPC probe for the supported complete networks. It takes a numeric
loopback address, port, owner-private Core cookie file, and a complete trusted
network identity. Construction and opening either existing ledger make no RPC
call. An explicit probe compares the configured identity to supplied contract
terms, checks Core's chain label and genesis hash, and fetches transaction
bytes by txid for the core static funding-binding byte check. A second explicit
`observe_candidate_outpoint` probe also samples chain-only `gettxout` evidence,
derives the reported inclusion height, fetches that height's block hash and
re-reads identical transaction bytes qualified by that block hash before the
final matching tip reading. It returns a **candidate** with sampled inclusion
fields at a named tip, not a serialized best-chain lineage entry. Named-tip
outpoint probes and informational `tip_height` additionally require the exact
configured signet challenge from `getblockchaininfo`; outpoint probes check it
at both tip readings. Missing or mismatched challenge evidence fails closed,
even when the chain label and shared genesis match. Custom signet execution
remains unsupported. No missing attestation triggers migration or recovery work.
The RPC
sequence is non-atomic, can miss an ABA reorg, and does not check mempool
spends or establish action authority. It uses only
four read-only RPC methods (`getblockchaininfo`, `getblockhash`,
`getrawtransaction`, `gettxout`),
with no wallet route, redirects, environment proxy, automatic retry, or writes.

`observe_cooperative_fee_policy` is separate strict, read-only signing
preflight evidence, not the optional floating-point fallback fee estimate.
It samples `getmempoolinfo` relay/mempool floors and a conservative
`estimatesmartfee` answer between matching, network-checked tips. Public networks
require a positive whole-satoshi-per-kvB estimate whose returned block target
fits the requested signed confirmation budget. Only an explicitly requested
regtest fixed-fee mode permits an explicitly unavailable estimate. Missing or
malformed fields and transport failures never enable that exception. Fee floors
use integer ceiling arithmetic and never override signed caps or dust policy.
Runtime still must bound acquisition and evidence age, independently verify
the selected outpoint, and recheck before native effects. This reader alone
does not authorize a partial signature; independent completion preflight uses it.

`cooperative_completion_candidate` is a nonauthorizing read snapshot containing
the current prepared fallback and canonical burned binding. It exposes no
handle, nonce, or admitted partial. Missing custody, another generation,
blocked sessions, or nonqualifying arbitration return no candidate; malformed
storage raises a sanitized error. The burned transaction may have a different
fee from its fallback, so preflight must validate its exact transaction and
sighash rather than infer them from the fallback. Begin the monotonic evidence
budget before acquiring this snapshot. Atomic completion still independently
checks custody, deadlines, and winner selection. The getter adds no migration,
sampling, signing, or restart cooperation.

The `complete_cooperative_claim` coordinator validates that snapshot
and the exact burned plan, then joins fresh own-node outpoint and fee samples
at the same named tip. Its one-second monotonic budget begins before snapshot
lock acquisition and native validation, includes worker queueing, and fences
every atomic completion clock callback before and after the caller's clock
returns. Proposal and completion sampling share one retained worker slot;
timeout or cancellation never permits a second worker or reuse of late evidence.
The computed floor must fit the frozen transaction; fees are never clamped to
the signed cap. Only precommit refusal returns `None`. Once atomic completion
begins, errors propagate because custody or durable selection may have changed.
There is no automatic retry. Selected completions use the normal checked
outbox, and broadcast never depends on a client receipt. Fresh signed-result
dispatch now invokes this operation exactly once after fresh authenticated
`signed` admission, never for replay, decline, or completion receipt. Ordinary
completion failures preserve the durable admission disposition because a
winner may already be selected; stale ownership and cancellation propagate.
New signing requires healthy original-service clocks, but owed completion
delivery remains independent of those flags and Core availability. Quote
feature activation, client readiness echoes, and release gates remain closed.
The deployment namespace and consensus profile are operator assertions, not
facts Core attests. Arbitrary old confirmed transactions need Core `-txindex=1`
already configured; this probe never enables indexing or initiates a reindex.
RPC errors, absent indexed transactions, timeouts, and partial/older local
state are **unavailable evidence**, never evidence of no funding. The result
does not authenticate the binding signature or wallet inputs, establish a
best-chain view, reserve funds, authorize funding, or close D07-D09. Existing
SQLite databases are neither modified nor migrated by this optional probe.
Its connect/read timeouts are inactivity limits, **not** a total deadline.
A malfunctioning or malicious configured listener can trickle headers and
block this synchronous call indefinitely. Do not integrate it into a daemon,
background polling, service handler, or time-critical action without a new
bounded transport contract and tests.
An opt-in integration check runs pinned Bitcoin Core v30 in an isolated Docker
network namespace with `-txindex=1` and a separate pinned Python test image:

```sh
RILLSWAP_RUN_BITCOIN_CORE=1 .venv/bin/pytest -q -m bitcoin_core --basetemp=tmp/pytest
```

It exercises real Core network preflight, confirmed transaction retrieval,
rejection of a mined coinbase as funding, sampled chain-only UTXO and
block-qualified transaction response,
and an unavailable txid. The UTXO transport test deliberately substitutes a
static checker after proving that the real checker rejects coinbase funding;
it does not claim a live signed binding. The fake
HTTP tests also pass a synthetic matching funding transaction through the
real core static checker. Neither test proves a live signed swap funding
workflow or complete backend reconciliation.

An additional `native_crypto` opt-in test composes a hash-pinned public
recovery fixture's handshake and a freshly signed funding binding with the
named-tip Core diagnostic. It rejects a tampered funder signature before any
Core RPC and observes only the exact binding supplied by that test. This is
test-local interoperability, **not** a provider admission API, proof of a
complete/current replacement history, F10 closure, or permission to release a
preimage.

The separate `payment_journal` records immutable BTC-to-LN outgoing payment
requests and append-only backend-reported observations. Its database is bound
to an exact network and backend, must be created explicitly, and never
authorizes payment submission or retry. Missing results, reported failure,
contradictory statuses, and missing rows after a database restore remain
ambiguous until the real backend is reconciled. Opaque route bytes are stored
with a serialization identifier but are not validated by this journal; a
future pinned LND adapter must validate the route and limits before sending.
Route bytes are sensitive payment metadata and must not contain credentials or
signing secrets. Observations store only a caller-supplied SHA-256 digest of
backend response evidence, not raw responses, credentials, or preimages; the
journal does not verify the digest's provenance. Keep any secret-bearing
backend data in a separately specified encrypted store.
Separate journals cannot coordinate submissions to one shared backend; no
multi-instance fencing or backend attempt correlation has been implemented.
An operator-invoked, read-only RPC report recorder is described below. There
is no automated reconciliation, so crash and restart storage tests do not
complete the D01, D02, or D09 release gates.

An **explicit outgoing-only LND observation diagnostic** is available as
`LndPaymentObserver.track(payment_hash)` in
`rill_provider.lnd_payment_observation`. It uses the vendored official LND
`v0.21.0-beta` protobuf definitions (source commit and hashes in
`proto/lnd-v0.21.0-beta/README.txt`), pinned Python gRPC runtime, a numeric
loopback endpoint, a locally configured TLS trust-root certificate with
hostname verification (not exact leaf-certificate pinning), and a protected
read-only macaroon. Operators must provision a narrowly restricted
`offchain:read` macaroon; this diagnostic cannot inspect its permissions;
never use an admin macaroon or expose it through CLI arguments, logs, or
backups. The observer uses only `TrackPaymentV2`, with one total gRPC deadline,
a 256 KiB response limit, 16-update limit, disabled gRPC RPC retries, and no
application reconnect loop. It returns only
typed payment-level and separately typed HTLC-attempt status/IDs. `INITIATED`
does not mean `IN_FLIGHT`, and LND's numeric HTLC attempt ID is **not** the
Rill journal's local attempt ID. No protobuf response, preimage, route, or
credential is returned or persisted. Missing history, not-found, timeout,
auth rejection, and interrupted tracking remain unknown, not proof of failure
or absence. The payment observer does not query backend identity or network
consensus; configured regtest identity is **not independently attested** by
this method. A separate, explicitly invoked
`LndInfoObserver.get_info()` uses a different, operator-provisioned
`info:read` macaroon and an independently configured expected compressed node
key. It performs one bounded TLS `Lightning/GetInfo` call and refuses a
mismatched reported key or a chain list other than exactly `bitcoin/regtest`.
It returns the reported block height and individual chain/graph sync flags,
including false flags and height zero, never a readiness or payment token.
This is a TLS-authenticated endpoint's **claim**, not independent proof of
possession of the Lightning key or the full Rill network identity (genesis,
consensus profile, namespace); it is not atomic with payment tracking. The
restricted `info:read` credential must be provisioned and protected separately
from the `offchain:read` credential. In the pinned empty-wallet LND check,
the former can call GetInfo but not TrackPaymentV2, while the latter retains
its existing GetInfo-denial check. Neither observer writes a trust marker.
There is no startup call, journal mutation, submit, cancel, retry, invoice
lookup, payment reconciliation, or payment permission. Previous-release v1
journals remain untouched, including missing, partial, and restored states;
the observer cannot infer safety from absence. An opt-in pinned LND regtest
empty-wallet check exercises TLS, restricted `offchain:read` authorization,
raw `NOT_FOUND` for an unknown hash, and the observer's sanitized unknown
result. It does not exercise an initiated, failed, or settled real payment.
Actual payment-flow interoperability, multi-instance fencing, persisted
intent/backend correlation, and the L03/D01-D09 release gates remain open.

`CoreTransactionReader.observe_source(source_height)` is a separate explicit
read-only primitive for a known LND-reported height. It checks Core's chain label,
IBD flag, genesis and configured signet challenge, reads the active hash at that
height twice and refuses changed bracketing tips or hashes. Namespace and consensus
profile remain operator pins; matching reads do not establish atomic state.
Cookie Basic authentication authenticates the client, **not the server**. The
operator must control the loopback listener and trusted host. A replaced listener
can fabricate these claims; IBD false is not wider-network synchronization proof.

The source call has a setup/cleanup-inclusive monotonic acceptance budget of at
most ten seconds, with remaining per-RPC timeouts and late-result refusal. This is
not a hard execution deadline: file work and HTTP parsing can block longer. It
returns no usable absence, spending authority or wallet-capacity claim. Exceptions
at this new boundary detach cookie/HTTP-bearing upstream details. Existing RPC
methods retain their original inactivity timeouts. The extended digest-pinned
Core v30 fixture verifies actual genesis, tip and active inclusion-height/hash
correspondence without adding wallet actions to the existing case. CI reuses the
sidecar-compatible environment to run that fixture. No installation upgrading
from the previous release is observed, provisioned, migrated or otherwise changed
automatically. The caller must still bind full acquisition intervals to real LND
and merchant evidence before any future credit import.

`CoreTransactionReader.observe_block_transaction(txid, block_height=...,
block_hash=...)` independently acquires historical transaction bytes from an
explicit active-block hint. It needs neither wallet membership, txindex nor a
present UTXO. Strict root RPC, configured chain/genesis/signet checks, sampled
tip/block correspondence and independently computed witness-stripped txid bracket
the result. Advancing tips must preserve the earlier sampled tip's active hash.
The returned depth is a **minimum across sampled tips**, not a continuous floor,
atomic inclusion proof or guarantee against a subsequent reorg. Bounded
non-coinbase parsing supports the core inspector's explicit limits only;
unsupported/pruned/unknown/late observations remain unknown, never absence proof.

The complete explicit hint is lookup input, not authority. Missing or invalid
hints cause no discovery, scan, fallback or RPC. Namespace/profile and trusted
Core host remain operator premises; cookie authentication authenticates only the
client. Setup, streamed response limits and cleanup are enclosed by acceptance
checks, not a hard execution cutoff. The method validates no funding declaration,
claim signature, ownership or completion policy and never releases journal holds.
Confirmation thresholds remain caller-owned. Old records without retained hints
remain unchanged: no migration, wallet work or automatic payment retry is added.

The new `test_core_block_transaction_pinned.py` case disables txindex explicitly,
spends a confirmed regular wallet transfer and retrieves both historical transfer
transactions by explicit block hints through a wallet-independent reader. A wrong
active-block hint refuses without a global lookup fallback. This is actual Core
byte-acquisition conformance, not HTLC claim validation or funded treasury
conversion. CI runs this separate opt-in case alongside existing Core checks.

The explicit `merchant_proof` sidecar profile combines receiver REST with Core
cookie observation inside the existing owned network namespace. Its separate
`tests/test_merchant_source_pinned.py` scenario runs the verified Bun HTTPS factory
and concrete CLI collector against real pinned LND/Core after one ordinary
1,000-sat zero-fee payment. The signer and leaf pins come from fixture-controlled
inputs before serving. Issuance and three-URI collection credentials are separate.
Canonical quantity/hash/invoice digest agree, exactly one invoice and payer
attempt exist, and collection leaves logical merchant history and protected
inputs unchanged. No journal import, liquidity/refund-payability claim or treasury
conversion follows. Existing baseline, native-reverse and merchant-receipt
profiles retain their gates and assertions.

Run with both `RILLSWAP_RUN_LND=1 RILLSWAP_RUN_BUN_MERCHANT=1` and
`.venv/bin/python -m pytest tests/test_merchant_source_pinned.py -q`, after preparing
the checksum-verified Bun toolchain and payments dependencies. CI runs the same
funded proof case in its sidecar-compatible environment; ordinary collection
remains opt-in. Fixture-owned children are reaped before namespace teardown and
private TLS/bundle staging is deleted. This is diagnostic conformance, not
production deployment approval; upgrading installs causes no automatic work.

The separate `merchant_conversion` profile in
`tests/test_merchant_conversion_pinned.py` combines those protected mounts with
native crypto and the real provider/SDK lifecycle. One ordinary 200,000-sat
merchant payment supplies source B, then one original reserved reverse operation
pays B to provider A and claims BTC to a separate controlled Core wallet. Real
encrypted recovery, native funding/claim validation, source debit, wallet history
and final common-tip checks produce a historical receipt. The job remains
dispatched, its full 105,000-sat allocation stays held and no credit is consumed.
The old 1,000-sat proof scenario remains unchanged.

Accounting admission is **test-only**: fresh zero-push private sole-channel
construction, B's known incoming-only history, terminal receipt settlement,
drained complete topology, supported constraints, no peer discontinuity and
matching chain/observer reads establish its explicit premises. Empty HTLC lists,
stable reads or exclusive custody alone do not establish production commitment
coverage. The private generated destination independently establishes this
fixture's retained-key premise, never inferred from wallet recognition. The
WebSocket relay is fixture infrastructure without production relay-policy checks.

Run the new test with `RILLSWAP_RUN_LND=1 RILLSWAP_RUN_BUN_MERCHANT=1`, the
checksum-pinned Bun toolchain and built `tmp/native/librill_crypto.so`. CI runs it
separately. This establishes controlled funded receipt conformance, **not** hold
release, production accounting projection, crash recovery or deployment readiness.
Existing installations receive no automatic work or new authority.

The additive `test_pinned_explicit_verified_merchant_conversion_completion` case
uses the same isolated profile, then explicitly acquires fresh evidence through
`reconcile_conversion()`. It verifies actual debit consumption, full hold release,
retained canonical credit, exactly one generation increment, and repeated
terminal status without RPCs or another payer attempt. The original receipt-only
case still retains its entire allocation. This is controlled regtest financial
conformance, not automatic production completion, crash recovery or reorg safety.

The separate `test_pinned_verified_completion_process_death` cases kill an owned
Python reconciliation child with SIGKILL immediately before or after the original
completion transaction commits. Core, LND, the provider and private parent-owned
files stay alive. Before-commit reopening must preserve every journal row and its
full hold; a fresh explicit reconciliation then completes once. After-commit
reopening must find the actual debit and receipt already recorded; terminal
reconciliation performs no recovery-key/candidate/custody acquisition or RPCs and
leaves all rows unchanged. Original payment/HTLC identity and private inputs stay
unchanged. Child inputs use a private pipe and only fixed public markers escape.

This is completion atomicity and lost-acknowledgment conformance across process
death at two selected boundaries. It does not establish that a hot journal was
encountered, machine power-loss durability, torn or mid-commit writes, daemon
restarts, original SDK interruption, or restored database/fence safety. Normal
SQLite reopening of an existing positively identified database is not application
metadata repair. Missing or incompatible application state still grants no work.
The test-only increment changes no stored format or startup behavior.

The owned miner stops only after provider settlement **and** the merchant wallet
reports the originally requested claim depth. SDK claim success and provider
settlement alone do not establish that depth. Fixed diagnostic tags distinguish
SDK cooperation, actual observation/validation boundaries and receipt joins
without revealing payloads or changing the cooperative-path expectation.

The separate `merchant_restart` profile supervises only source B with exactly
two possible foreground LND launches inside one surviving owned container. Its
TERM/INT trap exits without relaunching, and a nonzero daemon exit never retries.
Only this profile retains B's original wallet password in sidecar memory. The
scenario explicitly stops the active daemon, requires LOCKED through a fresh
pinned TLS connection, unlocks the existing wallet once with zero recovery window,
then separately waits for server readiness, active channel and drained inventory.
Original leaf fingerprint, node identity, macaroons, payment/invoice history,
private inputs and dispatched journal state must remain unchanged. Host checks
attest unchanged container/PID1 identity/start time, zero Docker restarts and the
first child reaped successfully before its sole replacement launches.

Restart history comparisons retain every protobuf field using deterministic
serialization within the pinned runtime/schema. Default map wire ordering is not
an invariant; this is not a cross-version canonical serialization format. Existing
process-death snapshots and all financial/native checks remain unchanged.

The fresh receipt/completion gates remain unchanged. No Docker restart, wallet
initialization replay, reseeding, credential rotation, discovery or second SDK
execution is permitted. This establishes same-version graceful daemon restart
conformance only, not LND crash, older-wallet upgrade, machine power loss or
production commitment coverage. Existing installations and profiles get no new
startup behavior or stored format.

`test_pinned_operator_cli_verified_completion` adds a separate owned case that
runs the public `rill_cli.main:main` entrypoint in a subprocess with private,
independently supplied operator pins and only read credentials. It checks original
dispatched status, verified one-time completion and terminal/status calls after
removing the evidence/identity and supplying an unavailable native library. Actual
funding/claim/source and original accounting/privacy assertions remain unchanged.
The CLI is regtest-only and introduces no provisioning or fresh SDK invocation.

`CoreTransactionReader.observe_funding_inclusion()` is a separate explicit,
bounded observation of a **known** parsed funding binding and terms. It associates
chain-only `gettxout` depth with that response's `bestblock` and the sampled tip,
derives the inclusion height, then reads the exact block-qualified transaction.
It checks native contract/output/anchor correspondence, requires two consistent
UTXO samples and identical bracketing tips, and rechecks canonical block hashes.
Even ordinary tip advancement refuses this new acquisition; older historical
lookup and outpoint methods retain their existing policies.

The result is existing `CoreHistoricalTransaction` history, not signing, payment,
retry, ownership, custody or hold-release authority. Caller-authenticated binding
and terms, the trusted local Core listener and configured namespace/profile remain
operator premises. Block-qualified lookup relies on Core's membership claim, not
a Merkle proof. Matching samples do not establish atomicity, prevent ABA reorgs,
exclude mempool spends or guarantee continued availability. The second UTXO sample
is conservative admission, not stronger cryptographic membership evidence. This
method uses no unqualified transaction lookup, wallet fallback, txindex or scan;
unknown data fails closed without retries or effects.

This increment does not persist hints or install SDK callbacks. Existing
installations perform no new acquisition, migration or startup work when hints
are absent, partial or from an older version. Durable retention by the original
SDK invocation is a separate explicit opt-in, described below; it is not enabled
by this reader or on installation startup.

The separate original-invocation retention conformance case explicitly opts into
the CLI SDK's encrypted funding hint. It freezes only its disposable fixture miner
during capture, then checks that the real saved coordinates precede native claim
signing and correspond to the actual funded block. Subsequent fresh collection
and guarded completion use those saved coordinates. This stable-chain case does
not establish reliability during normal tip advancement or SDK process death.
The new retention case validates the actual original claim witness path, including
the SDK's already-supported unilateral fallback, with the corresponding unchanged
native receipt validator. Earlier cooperative-only cases keep their requirements.
Cooperative signature-timeout observations remain an unresolved operational risk,
not evidence of production stability.

The saved-hint public operator case additionally supplies a strict v2 evidence
manifest with only an explicit encrypted hint path, not plaintext funding-block
coordinates. The public command correlates it to native original lineage and
acquires the unchanged fresh financial proof before completion. Terminal replay
passes after removing this case's newly created hint, manifest and identity file
and selecting a missing native library. Original recovery artifacts remain
untouched; no runtime command deletes them. This is explicit regtest admission,
not producer authentication, automatic recovery or production accounting.

The separate original-SDK process-death case starts the original SDK in a child
with its own fresh reservation and invocation right, waits for actual funding
capture acknowledgment, and kills it before claim-signer acquisition. The
parent-owned provider and daemons survive. Existing public regtest manual claim
commands use only retained original funded recovery/custody inputs, followed by
native actual-byte validation, one source payment/HTLC, approved claim depth and
saved-hint fresh public completion. No SDK restart or new payment is made. The
unchanged older cases remain separate; this exact instrumented boundary is not
general crash, wallet, container, power-loss or production recovery acceptance.

An internal **treasury accounting observer** is available as
`rill_provider.lnd_treasury_observation.LndTreasuryObserver`. Provision a protected
credential with only `info:read` and `offchain:read`, numeric loopback endpoint,
configured TLS trust roots and an independently pinned node key. Named read RPCs
do not prove the supplied credential lacks write permissions. Each call uses one
setup-inclusive monotonic deadline, disabled retries, bounded messages/channel
and HTLC counts, and same-channel synchronized `GetInfo` before and after its
reads. Payment tracking is bounded and canceled before the final identity read;
owned channels are closed before accepting a result. Errors expose no upstream
cause/context or private response material.

Configuration, certificate files and their directories must remain under trusted
operator control, protected against replacement. The observer refuses symlinks
at the credential-file open and requires private macaroon permissions, but does
not enforce certificate ownership or directory integrity. An attacker able to
replace TLS trust roots and the local endpoint can receive the credential and
fabricate matching node claims; the node-key comparison is not independent
protection against that capability.

`observe_accounting()` returns classified local commitment, reserve and pending
HTLC subtotals only. Local balance fields are individually floored to satoshis
and already exclude commitment fees, anchors and outgoing committed principal.
Incoming pending value is separate, never added.
Zero satoshi floors may represent positive sub-satoshi HTLCs, not zero-value
payments. Missing constraint submessages,
custom channels and unknown commitment types make coverage incomplete. An empty
complete response is known zero channel accounting; an unclassified subtotal
is not a zero-wallet assertion. There is **no available-budget field or adapter
to the merchant journal's spendable-capacity input**. These RPCs cannot reveal
all uncommitted updates or commitment-fee buffers, guarantee route bandwidth,
or back immediately payable refund promises.

`observe_completed_payment(hash, expected_amount_msat)` requires payment-level
`SUCCEEDED` and reconciles successful shard recipient amounts and settled route
fees with exact reported value/fees. Failed attempts contribute neither settled
value nor fees; unknown or inflight attempts refuse completion. Every successful
shard requires a positive actual first-hop BTC amount equal to its route total.
Older history missing that field is unsupported, not evidence of failure or
permission to retry. Creation records may be empty or exactly LND v0.21.0-beta's
default unaccountable metadata (`106823: 00`); unknown records and custom-channel
payment economics refuse projection. This allowlist does not attest actual wire
records; numeric first-hop correspondence establishes the debit. Returned fields exclude raw protobufs,
routes, attempts, channel identifiers, preimages and credentials. This reports
source debit only, not destination receipt, order acceptance or retry permission.

Results separate `configured_network` from observed node/network-label/tip
claims. TLS roots are not necessarily exact leaf pins. Even identical bracket
tips do not make channel accounting atomic or verify genesis, signet challenge,
consensus profile or deployment namespace. Synthetic real-TLS/gRPC tests verify
transport and projections, not actual LND permission enforcement. Separately,
the opt-in digest-pinned two-node regtest `test_pinned_single_part_hold_bound_settled`
reuses its existing settled 1,000-sat payment to verify this observer's combined
`info:read`/`offchain:read` accounting and exact zero-fee debit. Either scope alone
is rejected. The existing bound-settlement and ordinary merchant invoice checks
remain in that scenario. It establishes neither positive spendability nor
receipt-to-treasury conversion. No startup
call, journal migration, automatic observation, provisioning or conversion is
introduced for upgrading installations.

To durably attach a bounded **diagnostic report** to an already recorded
outgoing intent, run this only with an explicitly initialized v1 journal and an
operator-owned `0700` evidence directory. The network file must contain the
complete journal-bound `NetworkIdentity` JSON; use the same explicit regtest
identity for the read-only observer. Protect both the evidence file and journal
backups, as payment hashes, swap IDs, amounts, and HTLC attempts are sensitive.

```sh
.venv/bin/python scripts/record_lnd_payment_track.py \
  --journal /private/payments.sqlite3 --network-identity /private/regtest-network.json \
  --backend-identity node-alpha --idempotency-key <existing-64-character-hex-key> \
  --lnd-host 127.0.0.1 --lnd-port 10009 \
  --tls-cert /private/lnd-tls.cert --read-macaroon /private/offchain-read.macaroon \
  --evidence-out /private/evidence/new-report.json
```

The command refuses a missing intent or mismatched journal before making an
RPC. It reserves a **new** `0600` evidence file before reading backend
credentials, then writes and syncs a canonical report before atomically
appending its payment-level facts to the unchanged v1 journal. `INITIATED` is
recorded as `UNKNOWN`; incomplete tracking, absent history, and reported
failure are never retry or risk-release permission. HTLC attempt IDs are kept
in the evidence, not conflated with the journal's Rill attempt ID. The route
is represented by its digest and byte length, never raw route bytes. The
configured backend name and TLS endpoint are not independently or atomically
bound to LND's actual node identity or to execution of the journaled amount,
route, or absolute expiry. This is **not** payment reconciliation or claim
authority. Errors may leave an empty/partial evidence file or a complete
orphan with no database row: inspect it and the backend manually; never
overwrite, delete, or automatically replay it. The digest is only useful
alongside the protected evidence bytes, and a restored journal may lack prior
reports. Older, partial, or foreign journals are refused without upgrade or
backfill. Previous installations do no startup polling, reindexing, migration,
submission, or retry.

The pinned LND source also includes exact `invoicesrpc/invoices.proto`
and generated **message classes only**. Although their descriptors list mutating
`AddHoldInvoice`, `CancelInvoice`, and `SettleInvoice` RPCs, no callable
`InvoicesStub` is generated. An independent, explicitly invoked
`LndInvoiceObserver.lookup(payment_hash)` reads one backend-reported
invoice over TLS with an operator-provisioned `invoices:read` macaroon. It
returns only bounded typed selected non-secret payment-hash, invoice state and amount,
timing, and **all** HTLC channel/index, state, amount, acceptance-height,
expiry-height, and MPP-total fields. It rejects a wrong hash, duplicate HTLC
identifier pair, unknown status, AMP/keysend/blinded invoices, or nonempty
`custom_channel_data` (including ordinary serialized custom TLV records).
The latter is a deliberate fail-closed compatibility boundary, not proof of a
custom channel. Payment hashes, channel IDs, and amounts remain sensitive operational
metadata and must not be logged or broadcast. Partial
amounts, zero expiries, empty HTLC lists, and canceled history are reported,
not called safely accepted; no preimage, custom records, raw protobuf, or
backend credential is returned. `NOT_FOUND`, timeout, malformed or rejected
responses prove no invoice absence or funding safety. There is no provider
runtime invoice creation, settlement, cancellation, funded hold trial, or policy caller; the
operator must independently reconcile actual HTLC state and earliest expiry
under RS-004 before *any* funding action. The pinned empty-wallet test only
proves that the restricted `invoices:read` macaroon can look up a missing hash
and cannot call AddHoldInvoice. A separate opt-in disposable LND test creates
and cancels an **unfunded** hold invoice to verify real OPEN and CANCELED
read-only decoding, with no accepted HTLC. Neither test proves an accepted
invoice or a safe funding deadline. A
previous installation does not invoke, read, or migrate invoice records at
startup; missing, partial, older, or restored state gives no absence proof.

For developers, regenerate pinned messages (no generated payment-sending or invoice stub)
after installing `requirements-dev.txt` with
`.venv/bin/python scripts/generate_lnd_protos.py`. The pinned-source hashes
and exact generation-tool versions are checked. The focused fake transport
and real synthetic loopback gRPC TLS tests run in the normal pytest suite;
the synthetic tests alone are **not** a real LND regtest integration check.

To run the four opt-in pinned **disposable-regtest** diagnostics, keep `rill-core` and
`rill-provider` as sibling source checkouts. Install `requirements-dev.txt`
in this repository's local Python 3.14 `.venv` (including pinned
`grpcio-tools`), and have Docker capable of running the pinned `linux/amd64`
Core, LND, and Python images. From this repository:

```sh
RILLSWAP_RUN_LND=1 .venv/bin/pytest -q -m lnd --basetemp=tmp/pytest
```

Each test creates uniquely named, run-labeled containers; Core has no external network,
and LND and the test client share Core's loopback namespace without published
ports. It mounts the sibling source and local environment **read-only**, and
uses tmpfs for Core data, LND wallet/credentials, and the client credential.
The test-only wallet seed and admin macaroon are handled within the isolated
sidecar and are not printed. Tmpfs is not a guarantee against host swap or
crash dumps. The original restricted-read diagnostic mines no blocks and
creates no invoice or payment. The separate invoice diagnostic mines exactly
one OP_RETURN regtest block (no spendable output or wallet), waits for LND
`SERVER_ACTIVE`, then creates one unfunded hold invoice with a fresh hash,
observes OPEN and CANCELED through an `invoices:read` macaroon, and makes no
channel or payment. An ambiguous creation result is never retried; the owned
tmpfs containers are removed. The third diagnostic creates a fresh Core
**test-only** wallet inside container tmpfs, mines 101 regtest blocks to mature
coinbase, funds one LND wallet with 0.02 test BTC, connects two distinct LND
nodes, and opens one private 1,000,000-sat channel using a single submission.
It confirms the same active funding outpoint, capacity, and peer identity on
both nodes, and a confirmed P2WSH funding output in Core. No invoice, HTLC,
Lightning payment, or swap occurs in this third test. Failed or ambiguous
channel submissions are never retried; all owned containers are torn down.
This is infrastructure evidence, **not** an accepted-hold or funded swap trial.
The fourth, independently isolated test funds another disposable channel, then
uses test-only `SendPaymentV2` to create a **single-part** accepted hold on the
receiver. It checks the pinned backend's raw accepted amount, channel, HTLC
expiry, MPP total, and sender in-flight route, cancels the invoice **once**, and
checks failed outgoing payment plus canceled incoming HTLC. The preimage is
never transmitted or settled. The production read-only invoice observer
**refuses** this ordinary pinned-LND record because it contains nonempty
`custom_channel_data`. This fourth test records that incompatibility, rather
than overriding the existing refusal test or claiming that the provider can
observe accepted holds for funding admission. It also decodes that
`custom_channel_data` with a strict, test-local BigSize TLV parser and asserts
that it equals the HTLC's reported `custom_records` (types in the custom range
of 65536 and above, only types and lengths recorded). This is characterization
evidence for a future, separately approved observer change. It does not relax
the refusal. LND may prune failed HTLC
attempt history by default: terminal FAILED with an empty history is not proof
that no attempt occurred or permission to retry. This fixture proves neither
unsafe-MPP earliest-expiry refusal (L01), partial or mismatched hold refusal (L02), nor
capability suppression on missing expiry evidence (L07).
Cleanup verifies each container's run label before removal and attempts every
container even if one cleanup step fails. If the runner is interrupted, check
for leftover `rillswap-lnd-*`, `rillswap-invoice-*`, `rillswap-channel-*`, or
`rillswap-hold-*` containers with
`docker ps -a`, then verify the
`org.rillswap.test-run` label and mounts using `docker inspect` on each exact
container. After confirming the associated runner is no longer active, use
`docker rm --force --volumes` only on those verified containers; do not delete
other test runs or any host wallet. A missing/older journal remains unknown
after this test, never a reason to send or retry.

### Funded Bun merchant conformance

The independent `tests/test_bun_merchant_pinned.py` diagnostic uses the actual
`rill-payments` Bun HTTPS/macaroons transport, merchant ledger and HTTP Fetch
handler inside the disposable regtest namespace. It requires the existing Python
3.14 environment, digest-pinned backend images, installed frozen payments
dependencies, and this official Bun 1.3.11 Linux x64 toolchain. From the workspace
root, install the pinned artifact explicitly:

```sh
mkdir -p tmp/toolchains/bun-v1.3.11
curl -fL --retry 3 \
  -o tmp/toolchains/bun-v1.3.11/bun-linux-x64.zip \
  https://github.com/oven-sh/bun/releases/download/bun-v1.3.11/bun-linux-x64.zip
printf '%s  %s\n' \
  8611ba935af886f05a6f38740a15160326c15e5d5d07adef966130b4493607ed \
  tmp/toolchains/bun-v1.3.11/bun-linux-x64.zip | sha256sum -c - && \
  python -c 'from pathlib import Path; from zipfile import ZipFile; p=Path("tmp/toolchains/bun-v1.3.11"); (p/"bun").write_bytes(ZipFile(p/"bun-linux-x64.zip").read("bun-linux-x64/bun")); (p/"bun").chmod(0o755)'
(cd rill-payments && bun install --frozen-lockfile --ignore-scripts)
RILLSWAP_RUN_LND=1 RILLSWAP_RUN_BUN_MERCHANT=1 \
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 rill-provider/.venv/bin/python -m pytest -q \
  rill-provider/tests/test_bun_merchant_pinned.py \
  --basetemp=tmp/bun-merchant-pytest
```

The archive checksum applies to the ZIP; the test independently requires extracted
binary SHA256 `6d5bb405b1d037a2a466b92757de7e47e4369930fa94bd42f8ff44ba49de6c57`
and revision `1.3.11+af24e281e`. The child checks the complete embedded revision
as well. The standard x64 binary requires a compatible AVX2 CPU; the actual
artifact was exercised in the existing pinned Python image on Linux amd64.
No executable is automatically downloaded by the test. Missing opted-in
prerequisites fail rather than silently skip.

Only the verified executable and generated bundle are mounted at fixed read-only
destinations. The client root filesystem is read-only, capabilities are dropped,
and new privileges are disabled. Core's `none` namespace, both LND namespace
references and absence of host port bindings are checked. Private merchant keys,
macaroon, journal and audit preimage remain in client `0700` tmpfs; only public
certificates and test code are host-mounted. The generated bundle contains no
runtime credentials. HTTP listens on numeric loopback with an OS-assigned port.
The controller's sensitive responses stay in sidecar pipes; host evidence contains
allowlisted phases and counts only. Audits check public response serialization
and SQLite data/side files for key and preimage encodings. Tmpfs still does not
prevent host swap or crash dumps.

The diagnostic explicitly provisions one disposable store. Reopen never creates
or replaces it. A loss after actual backend issuance leaves the same operation
unresolved; process restart recovers its original invoice without another
`AddInvoice`. A bounded read-only exact-route check precedes one payer dispatch.
After a real one-part settlement, an injected observation exception leaves the
merchant unpaid until process restart and fresh independent observation. Failed
event delivery retains the original signed event; another restart delivers and
acknowledges it once while preserving historical retrieval. Child reads, HTTP,
RPC, shutdown and total execution are bounded; only owned children are killed
and reaped before restart. Partial controller lines also obey the response
deadline. The Docker sidecar phase has a 300-second bound, with separate bounded
setup and cleanup operations. Existing hold/ordinary REST diagnostics are unchanged.

These are controlled exception and process-restart checks, not arbitrary SQLite
commit interruption, machine-crash durability, LND daemon restart or supported
browser-wallet conformance. The fixture uses the disposable admin macaroon;
production least-privilege provisioning is not established by that baseline. No
production startup, schema, provider spending or release policy changes occur,
so existing installations require no migration or new network work. Normal CI
checks the TypeScript fixture and negative mount guards offline; this additional
funded diagnostic stays explicitly manual and gated by both environment flags.
Interrupted runs use the same label-checked cleanup procedure above for exact
`rillswap-bun-merchant-*` resources, never unrelated wallets or containers.

The same opt-in command also runs an independent scoped-credential scenario.
The Python controller bakes exactly `info:read`, `invoices:read` and
`invoices:write`, and supplies that credential instead of the admin macaroon to
the Bun service. The complete funded issuance/receipt/event restart assertions
are retained, establishing sufficiency of the documented permissions, not
mathematical minimality or production key custody. Python still owns its admin
credential for disposable setup; this is not OS-level isolation between processes.

A separate read-only credential positively reads the actual node identity and
the existing merchant invoice. Valid small `AddInvoice` probes are rejected by
actual Bun transport; independent private REST checks require the pinned server's
HTTP 500, JSON code 2 and permission-denied cause, then confirm the fresh probe
hash is absent with HTTP 404/code 5. This unusual error mapping matches pinned
LND's `UNKNOWN` permission behavior; generic errors alone are not evidence.
An empty `SendPaymentV2` request with the scoped credential likewise requires
`UNKNOWN` with a private permission-denied cause. It contains no payment
destination and proves denial of that RPC only, not every spending method.

The scenario also checks Bun rejection of a valid foreign CA and a structurally
valid macaroon with one changed signature byte. Independent private TLS checks
require certificate verification failure; invalid-signature REST checks require
HTTP 500/code 2 and a signature-mismatch cause. Raw error messages and credentials
are never host evidence. Probes occur after disposable channel setup and before
the payer's invoice payment, not before wallet funding. No production permission
minting, transport expansion, key replacement or new persisted format is added.
