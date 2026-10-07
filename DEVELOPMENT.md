# Development environment

A complete local regtest stack: Bitcoin Core, two LND nodes, a Nostr relay, an
auto-miner, a maker (liquidity provider) for each swap direction, a user
toolbox with the `rill` CLI, and the browser swap page. Everything runs in
Docker Compose and is driven by one script, `dev/devctl`.

All data is disposable regtest data with fixed, public credentials. Never
point any of it at real funds.

## Requirements

- Docker with Compose v2 (rootless works).
- Network access for the first image build (Debian packages, PyPI, Bun
  packages, the checksum-pinned secp256k1 release on GitHub).
- Optional: Chromium/Firefox for the browser swap page.

## Quick start

```sh
dev/devctl up        # build the image, start everything, wait for bootstrap
dev/devctl info      # maker keys, relay URL, height, balances
dev/devctl smoke     # one swap in each direction, end to end
```

The first `up` takes a few minutes (image build). Later runs reuse the image and
all chain/wallet/maker state. `dev/devctl help` lists every command.

| What | Where |
| --- | --- |
| Browser swap page | http://127.0.0.1:5273/swap.html |
| Nostr relay (from the host/browser) | ws://127.0.0.1:7777 |
| Nostr relay (inside the stack) | ws://relay:8080 |

Override host ports with `RILL_DEV_WEB_PORT` and `RILL_DEV_RELAY_PORT`, and the
auto-miner interval with `RILL_DEV_BLOCK_SECONDS` (default 10, `0` disables),
for example `RILL_DEV_WEB_PORT=8090 dev/devctl up`.

## What runs

| Service | Role |
| --- | --- |
| `bitcoind` | Bitcoin Core v30 regtest, `txindex=1`. Wallets: `miner`, `user`, `maker`. |
| `lnd-maker`, `lnd-user` | LND nodes. Two 5,000,000 sat channels: maker to user and user to maker. |
| `relay` | `nostr-rs-relay`, the only channel between makers and users. |
| `bootstrap` | One-shot, idempotent setup (below). Reruns on every `up`. |
| `miner` | Mines one block every `RILL_DEV_BLOCK_SECONDS`. |
| `maker-btc-to-ln` | `rill-provider serve`: takes on-chain BTC, pays the user's Lightning invoice. |
| `maker-ln-to-btc` | `rill-provider serve`: takes a Lightning hold payment, pays on-chain BTC. |
| `tools` | User toolbox. `devctl swap`, `devctl rill`, `devctl shell` run here. |
| `web` | Builds `rill-web` (rebuilding on change) and serves `dist/`. |

`bootstrap` checks before acting at every step, so it is safe to rerun and it
completes an interrupted attempt. It creates the wallets, mines to 150 blocks,
funds both LND nodes and the `user`/`maker` Core wallets (10 BTC each), opens
the channels, provisions one maker identity, custody key, config and store per
direction, and writes the user's age key. Results land in the `state` volume:

```
/state/info.json                 maker keys, relay URLs, LND pubkeys
/state/makers/<direction>/       provider.json, identity, custody key, store
/state/user/                     age.key, network.json, Core/LND credentials
/state/user/swaps/<time>-<dir>/  recovery files from `devctl swap`
```

Rill clients only accept Core and LND on numeric loopback, so each Rill
container forwards `127.0.0.1:18443` to `bitcoind` and `127.0.0.1:10009` to its
LND node (`dev/entrypoint.sh`). Core authentication uses a static `__cookie__`
rpcauth entry, so the cookie file stays valid across restarts.

## Watching a maker

```sh
dev/devctl logs maker-btc-to-ln          # live log (filter: | grep -v httpx)
dev/devctl logs relay                    # announcements (kind 39417), gift wraps (1059)
dev/devctl maker-swaps btc-to-ln         # the maker's swap records
dev/devctl balances                      # Core wallets and LND channel balances
```

A maker publishes a signed announcement on the relay, then waits for
handshakes. One "announcement not accepted by any relay; will retry" warning at
startup is expected while its relay connection opens. Each maker's earnings
land in the Core `maker` wallet (BTC to LN claims) or in LND channel balance
(LN to BTC).

`maker-swaps` stops that maker for a few seconds, because `inspect-swaps` takes
the store's owner lock. It currently works only for `btc-to-ln`: the provider's
inspection does not yet understand LN to BTC swap states, and it fails with
"swap inspection state unsupported" once that store has swaps.

To change maker terms (fees, amount bands), edit
`/state/makers/<direction>/provider.json` in `devctl shell` and restart the
maker, or `dev/devctl reset` to start over. Bootstrap never overwrites an
existing config.

## Swapping as a user (CLI)

```sh
dev/devctl swap btc-to-ln 50000     # pay a fresh 50,000 sat user invoice with on-chain BTC
dev/devctl swap ln-to-btc 50000     # pay Lightning, receive 50,000 sat on chain
```

The helper creates the invoice (`btc-to-ln`), runs `rill swap` in the `tools`
container with the right maker key, credentials and a fresh recovery path,
and prints the `rill` output. Extra flags pass through, for example
`dev/devctl swap btc-to-ln 50000 --fee-rate 5`. The exact command is printed,
so you can rerun or vary it with `dev/devctl rill ...` or inside
`dev/devctl shell`.

## Swapping as a user (browser)

The page at http://127.0.0.1:5273/swap.html runs BTC to LN entirely in the
browser. It never touches a wallet or node, so `devctl` stands in for your
wallet.

1. `dev/devctl web-inputs 50000` prints every form value: network `regtest`,
   relay `ws://127.0.0.1:7777`, the BTC to LN maker key, a fresh user invoice,
   a refund address, the current height and the user's age recipient. Paste
   them in and click **Start swap**. Keep the limit defaults.
2. Download the terms recovery file, then click **I saved the file**.
3. The page shows a contract address and an exact BTC amount. Run
   `dev/devctl fund-psbt <address> <amount>` and paste the finalized PSBT it
   prints. Click **Check funding**.
4. Download the funded recovery file, then click **I saved the file**.
5. Run `dev/devctl broadcast <raw hex>` with the hex the page shows, then click
   **I broadcast it**.
6. The page shows the preimage once the maker pays the invoice.

Use 127.0.0.1, not `localhost`: the page's CSP allows loopback relays, and
another local server may own `localhost` on IPv6. The page caps prompts with
timeouts, so do not leave a step waiting for minutes.

The browser recovery files are encrypted to the user's age key, which lives in
the stack. To decrypt or use them with `rill recover`, copy the key out:
`docker compose -f dev/compose.yaml cp tools:/state/user/age.key tmp/`.

## Mining, timeouts and refunds

```sh
dev/devctl miner pause      # freeze the chain
dev/devctl mine 300         # jump past a refund height
dev/devctl miner resume
```

At the default 10 s block interval, the BTC to LN refund delay (288 blocks) is
about 48 minutes. To exercise refunds, pause the relevant maker
(`docker compose -f dev/compose.yaml stop maker-btc-to-ln`) after funding,
mine past the refund height, and follow the recovery steps in
[`rill-cli/README.md`](rill-cli/README.md) inside `dev/devctl shell`. The
stack-specific values are: network `/state/user/network.json`, crypto library
`$RILL_CRYPTO_LIBRARY`, identity `/state/user/age.key`, cookie
`/state/user/core.cookie`, RPC port 18443, and LND port 10009 with
`/state/user/tls.cert` and `/state/user/admin.macaroon`.

## Raw access

```sh
dev/devctl bitcoin-cli -rpcwallet=user getbalances
dev/devctl lncli maker listchannels
dev/devctl lncli user addinvoice --amt 1000
dev/devctl invoice 1000 --node maker
dev/devctl pay <bolt11>
dev/devctl shell                       # bash with rill, rill-provider, devtool
```

## Changing code

The repository is mounted read-only at `/src`, and the Python packages are
installed editable from it. After editing:

- provider code: `dev/devctl restart maker-btc-to-ln maker-ln-to-btc`
- CLI code: nothing (each `rill` run starts fresh)
- `rill-web/src`, `swap.html`, `index.html`: the `web` service rebuilds; reload
  the page
- `dev/devtool.py`: nothing for commands; `dev/devctl up` reruns bootstrap
- dependencies, native crypto, `rill-payments` (bundled into the web image),
  or `dev/Dockerfile`: `dev/devctl build && dev/devctl up`

## Stopping and resetting

```sh
dev/devctl down     # stop; keeps chain, wallets, channels and maker stores
dev/devctl reset    # delete every volume (asks first); next `up` starts fresh
```

Volumes belong to the `rillswap-dev` Compose project: `bitcoind`, `lnd-maker`,
`lnd-user`, `relay`, `state`. Reset them together. A partial reset (for
example only `bitcoind`) leaves channels and stores pointing at a chain that no
longer exists.

## Tests

`dev/tests/` checks the stack's static invariants (rpcauth hashes match the
credentials devtool and the cookie use). Run it with any Python that has
`httpx` and `pytest`, for example `rill-cli/.venv/bin/python -m pytest dev/tests`.
`dev/devctl smoke` is the end-to-end check.

## Troubleshooting

- **Image build hangs at `apt-get update`:** containers cannot resolve DNS.
  With rootless Docker, the host's ISP resolvers may not answer from
  containers. Set `"dns": ["1.1.1.1", "9.9.9.9"]` in
  `~/.config/docker/daemon.json` (rootless) or `/etc/docker/daemon.json`, then
  restart Docker.
- **Port already in use:** set `RILL_DEV_WEB_PORT` or `RILL_DEV_RELAY_PORT`.
- **A maker exits at start:** `dev/devctl logs maker-<direction>`. If its store
  or config is broken, `dev/devctl reset`.
- **Bootstrap fails:** `dev/devctl logs bootstrap`, fix, then `dev/devctl up`
  again. It resumes where it stopped.
