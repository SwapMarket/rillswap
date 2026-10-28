# rill-provider

`rill-provider` runs the provider (maker) side of RillSwap. It announces swap
terms over Nostr relays, handles client sessions, and coordinates Bitcoin,
Lightning and ERC20 settlement using your own nodes.

It is for operators running a self-hosted liquidity provider, not a hosted
service. Running it requires node credentials, liquidity, and careful
handling of encrypted keys and persistent swap state.

## Install

Use a checkout of this monorepo, Python 3.13 or later (CI uses 3.14), `uv`,
and CMake with a C compiler. From `rill-provider/`:

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
source .venv/bin/activate
cmake -S ../rill-crypto -B tmp/native -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build tmp/native --parallel 2
```

Set `native_crypto_library` in your provider config to the absolute path of
`tmp/native/librill_crypto.so` (the Linux build output). Identity
provisioning takes the same path through `--native-crypto-library`.

## Quick start

For the easiest trial, use the disposable Docker stack: from the repository
root run `dev/devctl up`, then `dev/devctl smoke`. See
[DEVELOPMENT.md](../DEVELOPMENT.md) for requirements and controls.

To run your own signet provider, first prepare synced local Bitcoin Core and
LND nodes, channel liquidity, scoped LND macaroons, `age-keygen`, and a Tor
`HTTPTunnelPort` (for example `HTTPTunnelPort 127.0.0.1:9080` in your Tor
configuration). Then, from `rill-provider/` with the environment above active:

```sh
mkdir -p -m 700 tmp/signet
age-keygen -o tmp/signet/custody.key
chmod 600 tmp/signet/custody.key
rill-provider provision-identity --out tmp/signet/provider-identity.age \
  --recipient "$(age-keygen -y tmp/signet/custody.key)" \
  --native-crypto-library "$PWD/tmp/native/librill_crypto.so"
cp examples/provider.signet.json tmp/signet/provider.json
```

Edit the copied config before starting:

- Set `provider_identity_xonly` to the public key printed by provisioning.
- Set `custody_recipient` to the output of `age-keygen -y`.
- Set the absolute native library path and your node credential paths.
- Replace the example destination script with your own P2WPKH or P2TR
  scriptPubKey hex.
- Replace the relay URL, amount bands and fees.
- Only affirm the store authority declarations if they are true.

The example serves BTC to Lightning; see [Swap profiles](#swap-profiles) for
the others. Relative file paths resolve from the config file's directory.

```sh
rill-provider provision-store --config tmp/signet/provider.json
rill-provider serve --config tmp/signet/provider.json
```

Provision the store once and run one service per store. Stop with SIGINT or
SIGTERM. Never restore an older store snapshot.

## Docker

CI publishes `ghcr.io/rillswap/rill-provider` for amd64 and arm64. It holds
`rill-provider`, the `rill` CLI, the native crypto library and a Tor client,
and runs as uid 1000. `latest` follows `main`; in production, pin an image
digest, a `sha-<full commit hash>` tag, or a version tag such as `1.2.3` from
a `v1.2.3` release.

[docker/compose.yaml](docker/compose.yaml) runs one service per swap profile
(`btc-to-ln`, `ln-to-btc`, `erc20-to-ln`, `ln-to-erc20`), each with its own
store, identity and custody key, plus one shared Tor client that offers only
an HTTP tunnel inside the Compose network. Core and LND stay on your host or
network; the containers reach them through the hosts set in `.env`.

1. In an empty directory, fetch the compose file and the environment
   template, then edit `.env` (profiles, Core and LND addresses, uid):

   ```sh
   base=https://raw.githubusercontent.com/rillswap/rillswap/main/rill-provider/docker
   curl -fsSLO "$base/compose.yaml"
   curl -fsSL -o .env "$base/example.env"
   install -d -m 0700 makers stores credentials
   ```

   Core and LND must accept connections from the Docker network: set Core's
   `rpcbind` and `rpcallowip` and LND's `rpclisten` accordingly.

2. Put the LND credentials in `./credentials`, readable by the container
   uid: `tls.cert` (it must be valid for `127.0.0.1`, as LND's generated
   certificate is) and the `read`, `payment` and `invoices` macaroons from
   [LND credentials](#lnd-credentials). Then create the Core credential:

   ```sh
   docker compose run --rm setup rill-provider-init core-credential
   ```

   It writes `credentials/core.cookie` and prints an `rpcauth` line for the
   `__cookie__` user, plus an optional `rpcwhitelist` limited to the methods
   the provider calls. Add them to `bitcoin.conf` and restart Core. This works
   alongside existing `rpcuser`/`rpcpassword` or `rpcauth` logins.

3. Create each maker. Bitcoin profiles need a destination scriptPubKey from
   your wallet (`bitcoin-cli getaddressinfo <address>` shows it); LN to BTC
   also needs the Core wallet that funds swaps:

   ```sh
   docker compose run --rm setup rill-provider-init maker --profile ln-to-btc \
     --network signet --destination-script 0014... --core-wallet rillswap \
     --affirm-store-authority
   ```

   Pass `--affirm-store-authority` only when `./stores` is outside every
   backup and snapshot restore domain and used by one host; stores refuse to
   open without that attestation. Review `makers/<profile>/provider.json`
   (amount bands, fees, relays, `quote`). ERC20 makers print an EVM signer
   address to fund with gas, and their `evm` section must be completed
   (every `REPLACE` and zero value) before the store can be provisioned.

4. Provision each store once, then start:

   ```sh
   docker compose run --rm --no-deps ln-to-btc \
     rill-provider provision-store --config /rill/config/provider.json
   docker compose up -d
   docker compose ps
   ```

   A maker turns healthy once Core, LND and the Tor tunnel answer.

5. Optionally, enable [notifications](#notifications) for a maker: write its
   Apprise URLs to `makers/<profile>/notify.urls` (mode 0600, owned by the
   container uid), add a `notifications` section with
   `"urls_file": "notify.urls"` to its `provider.json`, and run
   `docker compose up -d` again. Notifications leave through the maker's
   network directly, not through Tor.

Back up `./makers` (custody keys, identities, configs). Never back up,
restore or copy `./stores`; `./credentials` can be recreated. For offline
commands, stop the maker first and use the same mounts, for example
`docker compose stop ln-to-btc` and then `docker compose run --rm --no-deps
ln-to-btc rill-provider inspect-swaps --config /rill/config/provider.json`.
Upgrade with `docker compose pull && docker compose up -d`.

To build the image from a checkout, run
`docker build -f rill-provider/docker/Dockerfile -t rill-provider .` at the
repository root and check it with `rill-provider/docker/smoke-test.sh
rill-provider`. Third-party dependencies are hash-locked in
`docker/requirements.txt`; regenerate the locks with `docker/lock.sh`.

## Commands

| Command | Purpose |
| --- | --- |
| `provision-identity` | Create an encrypted provider identity file |
| `provision-store` | Create a new empty live session store |
| `serve` | Run the provider until SIGINT or SIGTERM |
| `inspect-swaps` | Inspect retained swap state offline |
| `reconcile-payment` | Track one `PAYING` swap without sending another payment |

Use `rill-provider <command> --help` for arguments. All commands except
`provision-identity` require `--config`. Refused operations exit with status
2 and a redacted error.

## Configuration

Start from [examples/provider.signet.json](examples/provider.signet.json).
The configuration is strict JSON; unknown fields are refused.

| Field | What to configure |
| --- | --- |
| `network` | Complete Bitcoin network identity, not just a network name |
| `provider_identity_xonly`, `identity_file` | Provisioned public identity and encrypted identity file |
| `store_path` | Authoritative live SQLite store |
| `custody_recipient`, `custody_identity_file` | Age recipient and matching private custody key file |
| `native_crypto_library` | Path to the built native crypto library |
| `bitcoin_core` | Loopback RPC `port`, `cookie_file`, optional `wallet` and `max_fee_estimate_sat_vb` |
| `lnd` | Loopback gRPC `port`, `tls_certificate` and scoped macaroon paths |
| `provider_destination_script` | Provider's P2WPKH or P2TR destination script; enables Bitcoin firm offers |
| `handshake` | Selected profile, features, encryption suites and capabilities |
| `terms` | Advertised profiles, amount bands, fees, slot label and the liquidity cap (`follow_liquidity`, `liquidity_margin_percent`) |
| `quote` | Confirmation requirements, fee caps, deadlines and timing budgets |
| `authority` | Store volume label and deployment attestations |
| `relay_urls`, `relay_proxy` | Relay WebSocket URLs and loopback Tor HTTP tunnel |
| `evm` | ERC20 chain, verified HTLC deployment, signer, tokens and timing settings |

`terms.amount_bands` are in satoshis. Fees use `base_fee_sat` and
`proportional_millionths`. Review the `quote` settings against your network
and liquidity instead of treating the defaults as guarantees.

With `terms.follow_liquidity` (default `true`), the provider announces and
accepts at most what it can pay out, less a random margin from
`terms.liquidity_margin_percent` (default `[10, 20]`), and never more than the
configured bands. Each announcement (every 30 minutes) checks the payout
liquidity again: the largest single LND channel's sendable balance for BTC to
LN and ERC20 to LN, or the funding wallet's trusted balance for LN to BTC. LN
to ERC20 keeps its configured bands. The configured maximum applies whenever
liquidity is at least `maximum / (1 - high margin)`; keep more than that to
reveal nothing about your balance. Below it, a fresh margin is drawn when
liquidity falls under the announced maximum (swaps, or a wallet drained
outside the provider) or grows past `cap / (1 - high margin)`; otherwise the
cap stays. Changes wait for the next scheduled announcement, so balance
changes are not published as they happen. Below the smallest band, the
provider stops announcing until liquidity recovers. If the source fails, the
last cap stays (the configured bands before any reading). The Docker template
uses one band of 10,000 to 10,000,000 sat.

A request the provider can no longer fill between announcements is refused
at quote time with `capacity_unavailable`, before the client pays anything:
BTC to LN and ERC20 to LN need a payable route to the invoice, and LN to BTC
needs a wallet balance covering the contract plus `quote.max_funding_fee_sat`
before a hold invoice is opened. The LN to BTC check also applies with
`follow_liquidity` off; while the balance cannot be read, quotes are admitted
as before. LN to ERC20 does not check its token balance. Concurrent quotes
each see the whole balance.

LN to BTC reads the balance with Core's `getbalances`. If your
`rpcwhitelist` does not include `getbalances`, add it and restart Core;
until then the provider logs `liquidity unavailable` and `funding
balance unavailable`, keeps the configured bands, and does not check firm
quotes against the balance.

### LN to BTC funding

The provider funds each contract at Core's economical next-block estimate
(`estimatesmartfee 2 ECONOMICAL`, Core's closest setting to "next block"),
lowered to `bitcoin_core.max_fee_estimate_sat_vb` when set, and never below
the node's `minrelaytxfee` or current `mempoolminfee`. Without an estimate
it refuses to fund rather than guess (regtest alone falls back to the node
minimum), and the swap is retried later. The ceiling is never used as a
fallback rate.

It picks the inputs itself, for privacy: the fewest coins that pay the
contract, then, among those, the set leaving the least excess. Confirmed
coins come first; safe unconfirmed change only when they are not enough.
Core adds no other inputs, and when the excess is not worth a change output,
Core adds it to the fee instead. Only single-key coins whose signed size is
known (P2TR key path, P2WPKH, P2SH-P2WPKH, P2PKH) are candidates. Run one
provider per funding wallet.

This needs Core's `listunspent`. If your `rpcwhitelist` does not include
`listunspent`, add it and restart Core; until then the provider logs a warning and lets Core pick the inputs, at the same rate.

### LN to BTC claim fee reserve

The contract holds the payout plus a claim fee reserve. The client's claim
pays exactly the reserve as its fee, so the destination receives exactly the
requested amount. Unless `quote.claim_fee_reserve_sat` is set, the provider
prices the reserve for each quote: the larger script-path claim to the
client's destination at the same next-block rate it funds with (the node's
relay and mempool minimum is only a lower bound), so the cooperative claim
pays at least that rate too, and never below the client's requested minimum.
Indicative quotes assume a P2TR destination. Fees are sampled once per tick (15 seconds), never
per request. Without a sample, or when the reserve would exceed
`quote.max_claim_fee_sat`, LN to BTC quotes answer `capacity_unavailable`. A
client asking for a minimum reserve above `quote.max_claim_fee_sat` gets
`limits_unsatisfiable`, since no claim could spend it. A cooperative claim
paying exactly the signed reserve is admitted once it meets the node's relay
and mempool minimum, even if fees rose after signing.

If your configuration does not set `claim_fee_reserve_sat` (the examples and
`rill-provider-init` never did), the upgraded provider switches from the former
fixed 1,000 sat default to automatic pricing; swaps already signed keep their
reserve. Set it to keep a fixed reserve instead.

Admission limits include `max_sessions`, `max_tombstones`,
`new_sessions_per_minute` and `max_active_reservations`. The last one bounds
unreleased firm offers and accepted swaps (default 4). A swap holds its
reservation until the provider's claim reaches the settlement depth, so with
slow blocks the default fills quickly. When it is full, the provider answers
firm quotes with `capacity_unavailable` and logs `max_active_reservations
reached`.

`transport_pow_bits` (0 to 20, default 0 = off) requires RS-006 NIP-13 proof
of work on every message a client sends. The provider drops messages without
enough work after one hash, before any decryption. Each session keeps the
work it declared when it started, so you can change the value without
stranding swaps that are in progress. Clients that predate this setting can't
use an announcement that requires work, so enable it only after the clients
you serve support it. Each extra bit doubles the cost: 16 bits is about
65,000 hashes per message on average. In desktop Chromium on an HTTPS page,
that took about half a second per small message. Larger messages, phones, and
plain HTTP pages (no WebCrypto) take several times longer, and a swap sends
several messages. Work makes floods more expensive, but
it is not rate limiting or Sybil protection, because a native sender can
still produce messages much faster than a browser.

`bitcoin_core.max_fee_estimate_sat_vb` (1 to 10,000, unset by default) caps
Core's fee estimates. Use it where the estimator is skewed: on signet, a few
transactions paying hundreds of sat/vB next to empty blocks make
`estimatesmartfee` report over 200 sat/vB for 6 blocks. Without a cap, Lightning
to BTC funding then exceeds the signed `max_funding_fee_sat` and the swap waits
until its funding window closes, cooperative claims are refused because their
fee is below the estimate, and script-path claims start at the signed fee cap.
With a cap, funding pays at most the cap (never the cap in place of a missing
estimate), and claim, refund and cooperative fee checks use the capped
estimate. Core's relay and mempool minimum fees, the signed caps and
fee bumping are unchanged. On mainnet, leave it unset unless you understand
that a low cap also lowers the starting fee of your claims and refunds;
`serve` logs a warning at startup when it is set there. The
signet example and signet makers created by `rill-provider-init` set 2
sat/vB. Clients checking a cooperative claim against, or pricing a claim
fee reserve from, their own Core need the same cap (`rill swap btc-to-ln` or
`ln-to-btc --max-fee-estimate-sat-vb`).

### Swap profiles

Select one profile per deployment with `handshake.profile` and advertise it
in `terms.profiles`. The handshake policy is bound to the store when it is
provisioned; do not repurpose an existing store for another profile.

| Profile | Required settlement setup |
| --- | --- |
| `btc-to-ln/v1` | Bitcoin Core, provider destination script, LND payment macaroon, outbound Lightning liquidity |
| `ln-to-btc/v1` | Bitcoin Core funding wallet, provider destination script, LND payment and invoices macaroons, inbound Lightning liquidity |
| `erc20-to-ln/v1` | EVM settings, Bitcoin Core tip access, LND payment macaroon, outbound Lightning liquidity |
| `ln-to-erc20/v1` | EVM settings, Bitcoin Core tip access, LND invoices macaroon, token and gas liquidity |

For Lightning to BTC, change the example's `handshake.profile` to
`ln-to-btc/v1` and `terms.profiles` to `["ln-to-btc/v1"]`, add
`lnd.invoices_macaroon`, and set `bitcoin_core.wallet` to the Core wallet that
funds swaps. Keep the payment macaroon.

For ERC20 profiles, configure `evm` with `rpc_url`, `chain_id`, `name`,
`htlc_contract`, `block_seconds`, `signer_key_file` and `tokens`. Each token
needs its contract, symbol, decimals and `rate_token_base_per_btc`. Rates are
fixed operator inputs, not a live price feed. Also set
`forward_timelock_delay_blocks`, `reverse_timelock_delay_blocks`,
`learn_and_claim_seconds` and `refund_and_ln_resolution_seconds`. Startup
verifies the Boltz ERC20Swap v6 deployment before serving.

The EVM signer file holds one hex secp256k1 private key, must be owned by the
service user, and must have owner-only permissions. Bitcoin profiles include
`cooperative-claim/v1` automatically; ERC20 profiles do not use it.

### Funding confirmations

`quote.funding_confirmations` (default 1) is how many confirmations the
funding needs before the swap moves on. For BTC to LN it is how long you wait
on the client's deposit before paying the invoice. For Lightning to BTC it is
how long the client waits on your lockup before claiming; it must be at least
1. A Lightning to BTC client may choose to claim earlier, even from the
mempool (the CLI's `--claim-confirmations`, a web Settings field), and the
provider still cooperates: the client takes the double-spend risk, and your
own funding, unspent in your node's mempool, is enough evidence. ERC20
profiles use `evm.funding_confirmations` instead (EVM blocks, at least 1).
The value is signed into every offer and announced as
`rillswap/funding-confirmations`. The web app ranks providers by it by
default (fewest confirmations first, then lowest price) and labels the
fastest and cheapest offers. Clients refuse offers that wait longer than you
announced.

Upgrading: configurations that omit the field now wait 1 confirmation instead
of 2. Set `"funding_confirmations": 2` under `quote` to keep the old
behavior. Swaps already in progress keep the depth they signed.

#### Zero confirmations (BTC to LN only)

With `"funding_confirmations": 0` the provider pays the Lightning invoice as
soon as the exact contract output is unspent in its own node's mempool, before
any confirmation. This is fast for the client and risky for you:

- **The client can double-spend.** Until the deposit confirms, the client can
  replace it (RBF, or a conflicting transaction sent straight to miners) and
  spend the same inputs elsewhere. You have already paid the invoice and
  there is nothing left to claim: you lose the full swap amount.
- **Fee bumping is a race to the bottom.** You could spend the unconfirmed
  deposit in a child transaction (CPFP) that pays enough to confirm the
  deposit and your claim together, but the client can always answer with a
  higher-fee conflict. Each round costs both sides more. The provider does
  not do this today; automating it in the future could remove the client's
  incentive to cheat.
- **Your node must see the deposit.** Payment needs the deposit in your Core
  node's mempool. A deposit your node refuses (policy, fee rate, a full
  mempool) is paid only once it confirms.
- **A double-spent swap closes only on proof.** While your Core (with a
  synced `txindex`) does not know the deposit, the provider looks for another
  transaction spending one of the deposit's own inputs, scanning from 144
  blocks below the first claim, 12 blocks per sweep. When that transaction is
  6 blocks deep on the active chain, the swap becomes `LOST`, logs an error,
  and frees its reservation in `max_active_reservations`; the store records
  the conflicting transaction and block. A conflict still in the mempool, a
  deposit merely evicted, or one your node still holds keeps the swap in
  `CLAIMING`. A restart scans again from the same floor. `LOST` is final,
  even if a reorganization deeper than 6 blocks later revives the deposit.

Consider 0 only for small amounts and keep at least 1 for larger ones. An
advertisement carries a single value, so run one maker per policy: for
example, a 0-confirmation maker with a small `terms.amount_bands` and a
1-confirmation maker for larger amounts. Each needs its own store and
identity, but they can share the same Bitcoin Core and LND nodes.

### LND credentials

Use separate scoped macaroons instead of `admin.macaroon`:

```sh
lncli bakemacaroon offchain:read info:read --save_to read.macaroon
lncli bakemacaroon offchain:read offchain:write info:read \
  --save_to payment.macaroon
lncli bakemacaroon invoices:read invoices:write info:read \
  --save_to invoices.macaroon
```

Set `lnd.macaroon` to the read macaroon, `lnd.payment_macaroon` to the payment
macaroon, and `lnd.invoices_macaroon` to the invoices macaroon when the
profile uses hold invoices. Core and LND connections use `127.0.0.1`.

### Relays and Tor

Use relays that accept your announcements (kind 39417), serve gift wraps
(kind 1059) without NIP-42 AUTH, and accept connections from Tor. The Docker
setup defaults to the same relays as the web app, including two onion relays.
Proxied relays must use `wss://`, except v3 onion relays, which may use plain
`ws://` because Tor encrypts and authenticates them. On public Bitcoin
networks, set `relay_proxy` to a loopback Tor `HTTPTunnelPort` such as
`http://127.0.0.1:9080`. Direct connections are refused unless
`allow_direct_relays` is enabled, which exposes your IP address to the
relays. Regtest allows direct connections. Without `relay_proxy`, onion
relays are skipped (one INFO log line) and are not announced.

Failed relay connections log one warning per outage while retries continue
with backoff. Once reconnection and subscription sending succeed, the provider
logs `relay available` at INFO once. Each relay is tracked independently.

Each relay connection attempt runs on its own Tor circuit: the CONNECT
request carries a fresh random `X-Tor-Stream-Isolation` value, which Tor's
default `IsolateSOCKSAuth` treats like a SOCKS user name. Connections to
different relays, and reconnects, never share a circuit, so one slow or
censoring exit cannot cut every relay at once. This needs no torrc change;
only `NoIsolateSOCKSAuth` on the `HTTPTunnelPort` turns it off.

### Notifications

The optional `notifications` section sends operator notifications through
[Apprise](https://github.com/caronc/apprise) (Telegram, ntfy, email, Matrix,
webhooks and many more). The development lock and the Docker image include
it; other installs need the `rill-provider[notifications]` extra, or `serve`
refuses to start.

```json
"notifications": {
  "urls_file": "notify.urls",
  "swap_confirmed": true,
  "summary_time": "08:00"
}
```

`urls_file` is an owner-only (0600) file with one
[Apprise URL](https://github.com/caronc/apprise/wiki/URLBasics) per line;
blank lines and lines starting with `#` are ignored. URLs carry service
tokens, so they never go in the config. Every URL is checked at startup, and
a refused one is reported by line number only.

| Field | Default | Notifies |
| --- | --- | --- |
| `swap_request` | `false` | A client accepted terms (with the amount) |
| `swap_confirmed` | `false` | A swap completed, with its revenue, costs and net |
| `swap_failed` | `false` | A swap failed, was refunded or aborted |
| `swap_lost` | `true` | A swap paid out without getting the funds back |
| `daily_summary` | `true` | Requests, success rate, revenue, costs and net profit |
| `summary_time` | `"00:00"` | When the daily summary is sent (`HH:MM`, UTC) |
| `low_liquidity` | `true` | Liquidity is below every amount band (not announcing) |
| `relays_down` | `true` | No relay is connected |
| `quotes_paused` | `true` | The chain tip or claim fee estimate is unavailable |
| `service_start_stop` | `false` | Serving started or stopped |
| `alert_after_seconds` | `300` | How long a condition lasts before it is alerted (60 to 86400) |

The three health conditions are alerted once after `alert_after_seconds` and
cleared once on recovery. Events found in the same 15-second poll are combined
into one notification.

The daily summary covers the 24 hours before `summary_time` and is computed
from the store's swap ledger (see
[Persistent state and backups](#persistent-state-and-backups)): accepted
requests and firm offers, swaps closed with their outcomes and success rate,
revenue, mining and routing costs, losses, net profit (in sat, with msat
precision) and EVM gas (in gwei, kept apart). If a closed swap has costs that
were not recorded (not reported by a backend), the summary says so and the
net profit is an upper bound.

Notifications are best effort and never affect serving. Nothing about them is
persisted: events that happen while the service is stopped are not sent one
by one, but the next daily summary counts them. Failed deliveries are logged
without the URL.

Notifications connect directly to each service, not through `relay_proxy`, so
the services see this host's IP address (use a self-hosted service such as
ntfy or a webhook if that matters). `--log-level DEBUG` logs Apprise's
requests, which can include the URLs and their tokens.

## Persistent state and backups

The store uses schema v19 and opens only a store of exactly that version (see
[Upgrades](#upgrades)).

The store keeps an append-only swap ledger: each firm offer, acceptance and
outcome, and every realized cost (Lightning routing fee, claim, funding and
refund mining fees, EVM gas), written in the same transaction as the swap
event. A cost no backend reported is listed as unrecorded instead of being
counted as zero.

Reverse spent-output scans retain a block-hash anchor and an immutable replay
floor, checking parent continuity in batches of at most 12 blocks. Above-floor
reorgs durably rewind and resume across restarts. A reorg crossing the floor
pauses automatic refund resolution for operator recovery, which can leave funds
and the held payment pending. Scan backlog also blocks refund-based cancellation.
An already recorded preimage still settles without chain access.

Every funded reverse swap commits its anchor in the same transaction as its
funding. A swap without one is refused for operator recovery: missing metadata
is not permission for a full historical scan, a refund, or a payment retry.

The live store is the authoritative swap state, not a cache. Its database and
owner-lock file belong to one host and one service.

- Keep the store outside any backup or snapshot restore domain.
- Set `authority.outside_restore_domain` and `authority.single_host` to
  `true` only when they describe your deployment.
- Back up the custody key and encrypted provider identity offline.
- Keep the custody key out of store volume images, with owner-only
  permissions and ownership matching the service user.
- Never restore an old store, copy one over the live store, or delete records
  to clear a stuck swap.

Store acquisition checks ownership and provisioned file identity, but it
cannot verify your deployment attestations or detect every storage rollback.

Reverse funding failures release only the complete input set identified by that
build. Persistence refusal requires a same-owner check proving funding remains
ungranted; uncertain commits retain locks. Existing installations' earlier locks
are not swept or inferred from missing metadata. Unknown funding-creation replies
and cancellation after a completed worker may still require operator inspection.

### Upgrades

Stop the service before installing a new version. Stores are never upgraded in
place. A store of any other schema version (including v18 and earlier) is
refused with its contents unchanged, with
`live session store version unsupported (found N, requires 19); recreate it with
provision-store`. (If the old process crashed, SQLite may still fold its
committed write-ahead log into the database file; nothing is lost.) An older
release also refuses a newer store.

To move to a release with a new schema, let every in-flight swap finish on the
old release and confirm it with that release's `inspect-swaps` (the new one
cannot open the old store), stop it, keep the old store for your records, and
create a new store with `provision-store` at a new `store_path`. Lightning hold
invoices of unfinished reverse swaps would otherwise stay in LND. The new store
does not know the payment hashes the old one used; LND still refuses to pay an
already paid payment hash or to create a second invoice for an existing one. The handshake policy is part of
the store: changing it also needs a new store.

## Operations and recovery

After a crash, preserve the store and credentials, and confirm the previous
process has stopped before restarting or running an offline command. Do not
provision a replacement store to work around an error.

### Inspect retained swaps

With the service stopped:

```sh
rill-provider inspect-swaps --config tmp/signet/provider.json --limit 100
rill-provider inspect-swaps --config tmp/signet/provider.json --session-id SESSION_ID
rill-provider inspect-swaps --config tmp/signet/provider.json --after NEXT_AFTER
```

The output is redacted JSON with `action_authority: "none"`. Page with
`next_after`; `--limit` accepts 1 to 1000. Inspection does not contact Core,
LND or relays, and never changes the store's schema.
An empty page does not prove that no external payment exists.

### Reconcile an ambiguous payment

For a retained `PAYING` swap, stop the service and run:

```sh
rill-provider reconcile-payment --config tmp/signet/provider.json \
  --session-id SESSION_ID
```

This queries LND with the read macaroon and never sends a payment. A verified
matching preimage moves the swap to `PAID`, and normal settlement resumes
after restart. `UNKNOWN`, `IN_FLIGHT` and backend-reported `FAILED` leave the
swap `PAYING`. Missing records and RPC errors are not permission to retry;
preserve the original node and store state while investigating.

## Safety limits

- The provider never recreates missing stores, repairs unknown state, replays
  consumed payment dispatches, or treats missing metadata as payment failure.
- Ambiguous payments can stay unresolved and keep their reserved capacity.
  Offline reconciliation does not authorize a retry, refund or capacity
  release.
- Cooperative Bitcoin claims are optional for safety: if the peer is
  unavailable, script-path claim or refund recovery remains.

## Tests

From `rill-provider/`, the default CI selection:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  -m 'not native_crypto and not bitcoin_core and not lnd and not web_nip59_interop' \
  --basetemp=tmp/pytest-ci
```

Opt-in diagnostics use test infrastructure, never your live credentials:

| Marker | Enable with | Needs |
| --- | --- | --- |
| `native_crypto` | `RILLSWAP_RUN_NATIVE_CRYPTO=1` | Built native library at `RILL_CRYPTO_LIBRARY` |
| `bitcoin_core` | `RILLSWAP_RUN_BITCOIN_CORE=1` | Docker for pinned Bitcoin Core regtest fixtures |
| `lnd` | `RILLSWAP_RUN_LND=1` | Python 3.14 and Docker with pinned linux/amd64 Core, LND and Python images |
| `lnd` (merchant tests) | `RILLSWAP_RUN_LND=1 RILLSWAP_RUN_BUN_MERCHANT=1` | Bun 1.3.11 and installed `rill-payments` dependencies, plus the LND prerequisites |
| `web_nip59_interop` | `RILLSWAP_RUN_WEB_NIP59=1` | `RILL_CRYPTO_LIBRARY`, Bun and installed `rill-web` dependencies |
| `anvil` | `RILLSWAP_RUN_ANVIL=1` | Local Anvil with chain ID 31337 (`RILLSWAP_ANVIL_RPC` overrides `http://127.0.0.1:8545`) |

Select one with `-m <marker>`. See the test source for exact fixture
requirements. After an interrupted Docker diagnostic, check container
ownership and test-run labels before removing leftovers.

## Further reading

- [Protocol specifications](../rill-docs/specs/)
- [Architecture](../rill-docs/ARCHITECTURE.md)
- [Development and the disposable stack](../DEVELOPMENT.md)
- [Security policy](../SECURITY.md)
