# rill-provider

`rill-provider` runs the provider (maker) side of RillSwap. It announces swap
terms over Nostr relays, handles client sessions, and coordinates Bitcoin,
Lightning and ERC20 settlement using your own nodes.

It is for operators testing a self-hosted liquidity provider, not a hosted
service. Running it requires node credentials, liquidity, and careful
handling of encrypted keys and persistent swap state.

**Status:** experimental and unaudited. Bitcoin funding is limited to
regtest, signet and testnet4; mainnet funding is disabled in code. Do not use
real funds.

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

## Commands

| Command | Purpose |
| --- | --- |
| `provision-identity` | Create an encrypted provider identity file |
| `provision-store` | Create a new empty live session store |
| `serve` | Run the provider until SIGINT or SIGTERM |
| `inspect-swaps` | Inspect retained swap state offline |
| `reconcile-payment` | Track one `PAYING` swap without sending another payment |
| `migrate-store` | Explicitly upgrade a v5 to v7 store offline |

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
| `bitcoin_core` | Loopback RPC `port`, `cookie_file`, and optional `wallet` |
| `lnd` | Loopback gRPC `port`, `tls_certificate` and scoped macaroon paths |
| `provider_destination_script` | Provider's P2WPKH or P2TR destination script; enables Bitcoin firm offers |
| `handshake` | Selected profile, features, encryption suites and capabilities |
| `terms` | Advertised profiles, amount bands, fees and slot label |
| `quote` | Confirmation requirements, fee caps, deadlines and timing budgets |
| `authority` | Store volume label and deployment attestations |
| `relay_urls`, `relay_proxy` | Relay WebSocket URLs and loopback Tor HTTP tunnel |
| `evm` | ERC20 chain, verified HTLC deployment, signer, tokens and timing settings |

`terms.amount_bands` are in satoshis. Fees use `base_fee_sat` and
`proportional_millionths`. Review the `quote` settings against your network
and liquidity instead of treating the defaults as guarantees.

Admission limits include `max_sessions`, `max_tombstones`,
`new_sessions_per_minute` and `max_active_reservations`. The last one bounds
unreleased firm offers and accepted swaps.

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

Use relays that accept your announcements and that clients can reach.
Proxied relays must use `wss://`. On public Bitcoin networks, set
`relay_proxy` to a loopback Tor `HTTPTunnelPort` such as
`http://127.0.0.1:9080`. Direct connections are refused unless
`allow_direct_relays` is enabled, which exposes your IP address to the
relays. Regtest allows direct connections.

## Persistent state and backups

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

Stop the service before installing a new version. Current stores use schema
v15. Stores v8 to v14 upgrade automatically when opened, including by the
inspection commands. Stores v5 to v7 need an explicit offline migration:

```sh
rill-provider migrate-store --config tmp/signet/provider.json
```

Then restart `serve`. Stores v1 to v4 (never released) are refused. Migration
does not reconcile restored snapshots or grant old payments new retry
authority. Do not assume an older release can reopen an upgraded store.

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
LND or relays, but opening an older supported store can upgrade its schema.
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

- Mainnet funding is disabled.
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
