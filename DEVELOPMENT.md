# Development environment

A complete local regtest stack: Bitcoin Core, three LND nodes, a Nostr relay,
an auto-miner, a maker (liquidity provider) for each of the four swap
profiles, a user toolbox with the `rill` CLI, the browser swap page, a local
Anvil EVM chain with two fake stablecoins (fUSDC, fUSDT) and a gas sponsor, a
private Monero regtest chain, and a demo shop backed by the rill-payments
merchant services. Everything runs in Docker Compose and is driven by one
script, `dev/devctl`.

All data is disposable regtest data with fixed, public credentials. Never
point any of it at real funds.

## Requirements

- Docker with Compose v2 (rootless works).
- Network access for the first image build (Debian packages, PyPI, Bun
  packages, the checksum-pinned secp256k1 release on GitHub, the
  checksum-pinned Monero CLI release from getmonero.org).
- Optional: Chromium/Firefox for the browser swap page.

## Quick start

```sh
dev/devctl up        # build the image, start everything, wait for bootstrap
dev/devctl info      # maker keys, relay URL, height, balances
dev/devctl smoke     # both swap directions and a shop purchase per payment method
```

The first `up` takes a few minutes (image build). Later runs reuse the image and
all chain/wallet/maker state. `dev/devctl help` lists every command.

| What | Where |
| --- | --- |
| Browser swap page | http://127.0.0.1:5273/swap.html |
| Demo shop | http://127.0.0.1:8090/ |
| Anvil JSON-RPC (chain id 31337) | http://127.0.0.1:8545 |
| Nostr relay (from the host/browser) | ws://127.0.0.1:7777 |
| Nostr relay (inside the stack) | ws://relay:8080 |
| Read-only regtest chain API | http://127.0.0.1:8091/api |
| Explicit regtest transaction broadcast | http://127.0.0.1:8092/api/tx |
| Explicit user-node browser transport | http://127.0.0.1:8093 |
| Gas sponsor (ERC-4337 bundler stand-in) | http://127.0.0.1:8094 |

Override host ports with `RILL_DEV_WEB_PORT`, `RILL_DEV_SHOP_PORT`,
`RILL_DEV_RELAY_PORT`, `RILL_DEV_CHAIN_PORT`, `RILL_DEV_ANVIL_PORT`,
`RILL_DEV_BROADCAST_PORT`, `RILL_DEV_NODE_PORT` and `RILL_DEV_SPONSOR_PORT`, the Bitcoin auto-miner
interval with `RILL_DEV_BLOCK_SECONDS` (default 10, `0` disables), and the
Anvil block interval with `RILL_DEV_ANVIL_BLOCK_SECONDS` (default 2), and the
Monero block interval with `RILL_DEV_MONERO_BLOCK_SECONDS` (default 2), for
example `RILL_DEV_WEB_PORT=9273 RILL_DEV_CHAIN_PORT=9091 dev/devctl up`.

## What runs

| Service | Role |
| --- | --- |
| `bitcoind` | Bitcoin Core v30 regtest, `txindex=1`. Wallets: `miner`, `user`, `maker`. |
| `lnd-maker`, `lnd-user`, `lnd-merchant` | LND nodes. 5,000,000 sat channels: maker to user, user to maker, maker to merchant. |
| `relay` | `nostr-rs-relay`, the only channel between makers and users. |
| `bootstrap` | One-shot, idempotent setup (below). Reruns on every `up`. |
| `miner` | Mines one Bitcoin block every `RILL_DEV_BLOCK_SECONDS` and one Monero block (to the buyer) every `RILL_DEV_MONERO_BLOCK_SECONDS`. |
| `maker-btc-to-ln` | `rill-provider serve`: takes on-chain BTC, pays the user's Lightning invoice. |
| `maker-ln-to-btc` | `rill-provider serve`: takes a Lightning hold payment, pays on-chain BTC. |
| `maker-erc20-to-ln`, `maker-ln-to-erc20` | `rill-provider serve` for the RS-010 stablecoin profiles on Anvil (ERC20Swap v6 HTLC, fUSDC at a fixed 100,000 fUSDC/BTC). The maker's HTLC signer is Anvil account 3. |
| `tools` | User toolbox. `devctl swap`, `devctl rill`, `devctl shell` run here. |
| `web` | Builds `rill-web` (rebuilding on change) and serves `dist/`. |
| `chain`, `broadcast` | Read-only Esplora-style chain API and explicit transaction broadcast for the browser (see [Browser adapters](#browser-adapters)). |
| `user-node` | Scoped browser transport to `lnd-user` for paying from a configured node. |
| `gas-sponsor` | Local ERC-4337 bundler/paymaster stand-in for gas-sponsored stablecoin claims. |
| `merchant` | `rill-payments` merchant API (`bun src/cli.ts serve`) on `lnd-merchant`. |
| `anvil` | Foundry Anvil 1.8.4, chain id 31337, standard test mnemonic, state kept across restarts. |
| `monerod` | Monero v0.18.5.3 regtest (`fakechain`): private, fixed difficulty, no peers, chain kept across restarts (`--keep-fakechain`). |
| `monero-wallet-merchant`, `monero-wallet-buyer` | One `monero-wallet-rpc` each (wallets `merchant`, `buyer`, no password). Reachable only inside the stack. |
| `shop` | Demo storefront ([`rill-payments/examples/demo-shop`](rill-payments/examples/demo-shop)), plus the fUSDC/fUSDT and Monero receipt services. |

`bootstrap` checks before acting at every step, so it is safe to rerun and it
completes an interrupted attempt. It creates the wallets, mines to 150 blocks,
funds both LND nodes and the `user`/`maker` Core wallets (10 BTC each), opens
the channels, provisions one maker identity, custody key, config and store per
direction, deploys the ERC20Swap v6 HTLC and the fUSDC dev token on Anvil
once (one million fUSDC each to the user, Anvil account 1, and the maker
signer) and provisions the two stablecoin makers, writes the user's age key, and prepares the merchant's keys, admin
token, scoped invoice macaroon and config (the merchant provisions its own
ledger on first start), and creates the two Monero wallets and mines the
Monero chain to 130 blocks to the buyer (100 coinbase outputs: spendable
funds and enough ring decoys). Results land in the `state` volume:

```
/state/info.json                 maker keys, relay URLs, LND pubkeys
/state/makers/<direction>/       provider.json, identity, custody key, store
/state/evm/contracts.json        Anvil HTLC and fUSDC addresses, maker/user accounts
/state/user/                     age.key, network.json, Core/LND credentials
/state/user/swaps/<time>-<dir>/  recovery files from `devctl swap`
/state/merchant/                 merchant config, keys, admin token, ledger
/state/shop/orders.json          demo shop orders
/state/shop/native/              stablecoin keys; per token config.json, ledger
/state/shop/monero/              Monero rail keys, config.json, ledger
```

The shop sets up the stablecoins itself on first start: it deploys
`DevStablecoin` twice from Anvil account 0, mints one million of each to the
buyer (account 1), records each token in `/state/shop/native/<token>/config.json`
and provisions its receipt ledger. Shop revenue goes to account 2. If the Anvil
chain no longer matches those records, the shop logs it and disables the token
rails rather than redeploying: `dev/devctl reset`.

The Monero rail works the same way: on first start (empty
`/state/shop/monero/`) the shop records the merchant wallet's primary address
and the chain's block-1 hash in `config.json` and provisions its ledger. Any
partial state, another wallet, or a reset chain disables the rail; nothing is
recreated over existing state. Regtest addresses look exactly like mainnet
ones, so the rail also refuses any daemon that does not report `fakechain`.

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

Open http://127.0.0.1:5273/swap.html (use 127.0.0.1, not `localhost`: the
page's CSP allows loopback relays, and another local server may own
`localhost` on IPv6). The local build defaults to regtest, the local relay,
chain API and gas sponsor, and a recovery wallet derived and stored in the
browser. Pick the pair with **You send / You receive**.

- **BTC to Lightning:** `dev/devctl web-inputs 50000` prints a fresh user
  invoice. Paste it, get a quote, save the recovery files the page offers, then
  send the exact amount to the contract address it shows:
  `dev/devctl bitcoin-cli -rpcwallet=user sendtoaddress <address> <btc>`.
  The page waits for the first confirmation, binds the deposit, and shows the
  preimage once the maker pays the invoice. Under **Advanced** you can paste a
  finalized PSBT from `dev/devctl fund-psbt <address> <btc>` instead.
- **Lightning to BTC:** compare offers, approve one, then pay the hold invoice
  with `dev/devctl pay <bolt11>`. The page claims the on-chain output.
- **USDC/USDT to Lightning:** needs an injected EVM wallet (for example
  MetaMask) on the Anvil network (RPC http://127.0.0.1:8545, chain id 31337)
  with Anvil account 1 imported; it holds one million fUSDC. The wallet signs
  the approval and the HTLC lock.
- **Lightning to USDC/USDT:** type a receiving address, pay the hold invoice
  with `dev/devctl pay <bolt11>`; the local gas sponsor submits the claim, so
  the address needs no ETH.

Recovery files are encrypted to the browser-derived age identity. The
recovery panel can inspect them and prepare explicitly approved refunds. To
recover with the CLI instead, download `rillswap-recovery.age-key` from the
recovery details.

## Paying in the demo shop

Open http://127.0.0.1:8090/, pick a product, pick a payment method and place
the order. Prices are in USD at a fixed demo rate (1 BTC = 100,000 USD). The
shop backend creates the merchant intent and invoice with its admin token; the
browser only talks to the shop. The order page polls its status and, once the
merchant accepts the payment, verifies the merchant's signed acceptance
against the Ed25519 key the shop pinned from the merchant's event key.

- **Lightning:** `dev/devctl pay <invoice>` pays from `lnd-user`, routed
  user to maker to merchant.
- **Bitcoin on-chain:** `dev/devctl swap btc-to-ln <invoice>` funds a swap
  from the Core `user` wallet and the BTC to LN maker pays the shop's invoice.
  The browser swap page works too: paste the shop invoice instead of the one
  from `web-inputs`.
- **fUSDC / fUSDT:** `dev/devctl pay-token <order-id>` (1 token = 1 USD). This
  uses the rill-payments native sandbox receipt rail: the buyer signs an
  EIP-712 binding for the order and its next nonce, the merchant reserves it,
  the buyer sends exactly that ERC20 `transfer`, and after 6 confirmations
  (about 12 s) the merchant records a signed receipt that the shop verifies.
  A plain wallet transfer without the binding is never accepted, so MetaMask
  alone cannot pay; it can still watch balances on `http://127.0.0.1:8545`.
- **Monero:** `dev/devctl pay-xmr <order-id>` (1 XMR = 200 USD) sends the
  exact amount from the buyer wallet to the order's own subaddress;
  `--parts 2` splits it over two transactions. This uses the rill-payments
  Monero regtest receipt rail: the shop polls the merchant wallet every 3 s and
  counts confirmed incoming transfers to that subaddress (10 confirmations,
  about 20 s). Exactly the price, in blocks between order creation and expiry,
  is paid and gets a signed receipt. More than the price (even dust), any
  transfer timestamped outside that window, or an incomplete sum after expiry
  goes to reconciliation. A payment that later leaves the chain (reorg) marks
  the order's evidence impaired; the acceptance is kept.

`dev/devctl shop-smoke` buys once over Lightning and once via a swap, and
`dev/devctl token-smoke` once with each token, and `dev/devctl xmr-smoke` with
Monero (one payment, then one split in two); all check the signed acceptance. The merchant API itself is reachable only inside the stack
(`merchant:8788`, forwarded to the CLI's loopback listener), so
`dev/devctl shell` plus `curl` with the token in `/state/merchant/admin.token`
is the way to call it by hand.

## Mining, timeouts and refunds

```sh
dev/devctl miner pause      # freeze both chains (Bitcoin and Monero)
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
dev/devctl lncli merchant listinvoices
dev/devctl lncli user addinvoice --amt 1000
dev/devctl invoice 1000 --node maker
dev/devctl pay <bolt11>
dev/devctl cast block-number                           # Foundry cast on Anvil
dev/devctl cast call <token> "balanceOf(address)(uint256)" <address>
dev/devctl cast send <token> "mint(address,uint256)" <address> 1000000000 \
    --private-key <anvil key>                           # fake-token faucet
dev/devctl shell                       # bash with rill, rill-provider, devtool
docker compose -f dev/compose.yaml exec monero-wallet-buyer \
    curl -s -d '{"jsonrpc":"2.0","id":0,"method":"get_balance"}' http://127.0.0.1:18082/json_rpc
```

`dev/devctl balances` includes both Monero wallets. Monero RPC is never
published to the host: use `docker compose exec` as above (daemon on
`monerod:18081`, wallets on port 18082).

## Changing code

The repository is mounted read-only at `/src`, and the Python packages are
installed editable from it. After editing:

- provider code: `dev/devctl restart maker-btc-to-ln maker-ln-to-btc maker-erc20-to-ln maker-ln-to-erc20`
- CLI code: nothing (each `rill` run starts fresh)
- `rill-web/src`, `swap.html`, `index.html`: the `web` service rebuilds; reload
  the page
- `rill-payments/examples/demo-shop`: the shop restarts itself (`bun --watch`);
  after editing `DevStablecoin.sol`, run
  `bun examples/demo-shop/generate-stablecoin.ts` in `rill-payments` and
  reset the stack (deployed tokens are pinned by runtime code hash)
- `rill-payments/src`: `dev/devctl restart merchant shop`
- `dev/devtool.py`: nothing for commands; `dev/devctl up` reruns bootstrap
- dependencies, native crypto, `dev/entrypoint.sh`, `dev/Dockerfile`, or
  `rill-payments` code the web page imports: `dev/devctl build && dev/devctl up`

## Stopping and resetting

```sh
dev/devctl down     # stop; keeps chain, wallets, channels and maker stores
dev/devctl reset    # delete every volume (asks first); next `up` starts fresh
```

Volumes belong to the `rillswap-dev` Compose project: `bitcoind`, `lnd-maker`,
`lnd-user`, `lnd-merchant`, `anvil`, `monerod`, `monero-merchant`,
`monero-buyer`, `relay`, `state`. Reset them together. A partial reset (for
example only `bitcoind`) leaves channels and stores pointing at a chain that no
longer exists.

## Browser adapters

These small services let the browser page reach the regtest chain and node
without holding node credentials.

The chain adapter exposes read-only Esplora-compatible GET routes for block
hashes by height, tip height/hash, transaction hex/status, and confirmed
unspent-output observations (`/tx/{txid}/outspend/{vout}`). Raw transaction
responses are limited to 100,000 bytes. Null, missing, unconfirmed, spent, or
inconsistent UTXO samples return unavailable, never `spent:false`. An unspent
response still requires independently checking the raw transaction's identity
and exact output in the browser. Sequential RPC samples are trusted local
observations, not atomic snapshots or canonical-chain proofs.

It holds no swap state or keys and never mines, repairs, scans, broadcasts,
or calls wallet RPC. Host and browser Origin checks follow the
configured local ports. Its dedicated Core reader is whitelisted, but the
shared dev network and public privileged credentials are not container
compromise isolation. Apply updated Core flags and service configuration with
`docker compose -f dev/compose.yaml up -d --build bitcoind chain web`, not
`dev/devctl restart`. Existing volumes and wallets are retained; do not reset.
After building the dev image, reproduce reader authorization on an isolated
disposable node with `RILLSWAP_TEST_CHAIN_AUTH=1 pytest dev/tests/test_chain_core_auth.py`.
This check mines and sends only on its isolated disposable node, covers
confirmed/unconfirmed/spent/reorganized transaction observations, and verifies
wallet, mining, preflight, and broadcast methods are denied to the reader. It
does not mount or change existing chain volumes.

The separate broadcast adapter accepts only an explicit `POST /api/tx` from
the configured local web Origin/Host. It receives signed transaction hex, never
keys or recovery files. The chain adapter remains read-only. Core checks
regtest genesis before each submission, preflights once, then sends the exact
transaction once with a fixed 0.1 BTC/kvB fee ceiling and zero burn allowance.
That ceiling is a coarse 10,000-sat/vB backstop, not a recommended wallet fee.
Failures after sending may be unknown; neither adapter nor browser retries.
The broadcast credential allows only `testmempoolaccept,sendrawtransaction`.
Public disposable privileged credentials and local processes can bypass this
browser-origin admission boundary; it is not compromise isolation or a public
authenticated service. Its socket timeout limits inactivity, not total worker
lifetime. It stores no persistent state and never broadcasts at startup.

Apply broadcast changes with
`docker compose -f dev/compose.yaml up -d --build bitcoind chain broadcast web`.
Existing volumes are retained. Missing/partial configuration means unavailable,
not automatic repair, reindexing, reset, or transaction replay. Override the
loopback port with `RILL_DEV_BROADCAST_PORT` (default 8092).

The regtest-only `user-node` adapter makes LND's five bounded-payment RPCs
available to explicit browser actions. `/configuration` returns the expected
node identity/network and a URI-restricted macaroon only to the configured
local web Origin/Host, with `Cache-Control: no-store`. It permits `DecodePayReq`,
`GetInfo`, `QueryRoutes`, `SendToRouteV2`, and `TrackPaymentV2`, not wallet,
invoice creation, admin, or unrestricted payment-router methods. The browser
owns route selection, payment approval, limits, and durable dispatch ordering;
the adapter only transports bounded requests/streamed responses to one fixed
user node and never retries or logs payment data. Upstream TLS is verified
against the original LND certificate and expected node/network. LND's TLS
configuration, existing clients, and wallet volumes are unchanged.

This macaroon still authorizes arbitrary routed **regtest** payments. URI
restrictions do not impose an amount or destination budget. Local processes
can forge Origin/Host, and allowed-origin script compromise can steal the
credential. This is disposable development infrastructure, not a production
credential service. The browser keeps credentials only in memory. Payment
responses can contain preimages; the adapter transports them without storing
or logging them. No recovery secrets are uploaded. Real-node access requires
explicit user configuration and browser-trusted HTTPS, not certificate bypass.

Explicit bootstrap creates a new dedicated `browser-node` volume containing
only its scoped credential, public configuration, and TLS certificate. It
records configuration before baking; interrupted/partial or unsupported files
remain preserved and block provisioning. Complete matching files are never
automatically repaired or replaced. Neither adapter startup nor missing
credentials initiate a payment, reset wallets, or start scans. The adapter
does not mount the admin-credential/state volume. For a running stack, provision
only this capability without rerunning funding/bootstrap:

```sh
docker compose -f dev/compose.yaml run --rm --no-deps bootstrap python -c \
  'import sys; sys.path.insert(0,"/src/dev"); from devtool import provision_browser_node; provision_browser_node()'
docker compose -f dev/compose.yaml up -d --no-deps user-node
RILLSWAP_TEST_USER_NODE=1 pytest -q dev/tests/test_user_node_live.py
```

The opt-in live test reads identity, verifies unrelated native RPC denial,
and queries a route. It never dispatches a payment. Override the loopback port
with `RILL_DEV_NODE_PORT` (default 8093). The browser uses it when you pay a
Lightning to BTC swap from a configured node under **Advanced**.

## Tests

`dev/tests/` checks the stack's static invariants (rpcauth hashes match the
credentials devtool and the cookie use, the Monero chain persists and its RPC
stays private). Run it with any Python that has
`httpx` and `pytest`, for example `rill-cli/.venv/bin/python -m pytest dev/tests`.
`dev/devctl smoke` is the end-to-end check.

## Troubleshooting

- **Image build hangs at `apt-get update`:** containers cannot resolve DNS.
  With rootless Docker, the host's ISP resolvers may not answer from
  containers. Set `"dns": ["1.1.1.1", "9.9.9.9"]` in
  `~/.config/docker/daemon.json` (rootless) or `/etc/docker/daemon.json`, then
  restart Docker.
- **Port already in use:** set the matching `RILL_DEV_*_PORT` variable.
- **A maker exits at start:** `dev/devctl logs maker-<direction>`. If its store
  or config is broken, `dev/devctl reset`.
- **Bootstrap fails:** `dev/devctl logs bootstrap`, fix, then `dev/devctl up`
  again. It resumes where it stopped.
- **A token order stays `waiting` after an Anvil restart:** Anvil keeps blocks
  but not historical state across restarts, so a payment that was in flight
  during the restart cannot be verified. Place a new order.
- **Monero is unavailable with "order history is unreadable":** the shop
  could not parse `/state/shop/orders.json` and moved it to
  `orders.json.unreadable-<time>`. While that file exists the shop will not set
  up Monero state (it cannot tell whether Monero orders existed). Inspect it
  with `dev/devctl shell`, then delete it or `dev/devctl reset`.
- **Bootstrap says a Monero wallet does not match the chain:** the `monerod`
  volume was deleted while wallets or shop state remained. `dev/devctl reset`.
- **Anvil account keys:** the standard test mnemonic
  (`test test ... junk`), for example
  `dev/devctl cast wallet private-key --mnemonic "test test test test test test test test test test test junk" --mnemonic-index 1`.
