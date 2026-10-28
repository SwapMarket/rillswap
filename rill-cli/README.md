# rill-cli

`rill` is the RillSwap command-line client. It discovers providers, swaps
between on-chain Bitcoin and Lightning, and inspects encrypted recovery files.
Unilateral recovery does not need the provider or any RillSwap service.

Live swaps use your own Bitcoin Core wallet and LND node. You choose the
provider explicitly; a directory listing does not prove liquidity,
availability or honesty.

## Install

Use a checkout of this monorepo, Python 3.13 or later (CI uses 3.14), `uv`,
and CMake with a C compiler. From `rill-cli/`:

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
source .venv/bin/activate
cmake -S ../rill-crypto -B tmp/native -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build tmp/native --parallel 2
```

Pass the absolute native library path with `--crypto-library`. The examples
use `tmp/native/librill_crypto.so`, the Linux build output. The Python
packages do not bundle the native library.

## Quick start

For a local trial, from the repository root:

```sh
dev/devctl up
dev/devctl smoke
dev/devctl swap btc-to-ln 50000
```

See [DEVELOPMENT.md](../DEVELOPMENT.md) for the local environment.

For your own signet nodes, run the Bash example below from `rill-cli/`. Set
the variables to your relay, credential file paths, wallet, age keys and
signet BOLT11 invoice, and pick provider identities from the listing. It
assumes synced nodes, wallet funds, channel liquidity, and a local Tor
`HTTPTunnelPort` on port 9080.

```bash
discovery=(--network ../rill-docs/networks/signet.json
  --crypto-library "$PWD/tmp/native/librill_crypto.so"
  --relay "$RELAY" --relay-proxy http://127.0.0.1:9080)
rill providers list "${discovery[@]}"

common=("${discovery[@]}" --max-success-fee-sat 1000
  --core-port 38332 --core-cookie "$CORE_COOKIE" --wallet "$WALLET"
  --lnd-port 10009 --lnd-tls-cert "$LND_TLS_CERT"
  --recipient "$AGE_RECIPIENT" --identity "$AGE_IDENTITY")

rill swap btc-to-ln "${common[@]}" --provider "$BTC_TO_LN_PROVIDER" \
  --invoice "$INVOICE" --lnd-macaroon "$DECODE_MACAROON" \
  --recovery-output btc-to-ln.age

rill swap ln-to-btc "${common[@]}" --provider "$LN_TO_BTC_PROVIDER" \
  --payout-sat 10000 --lnd-macaroon "$PAYMENT_MACAROON" \
  --recovery-output ln-to-btc.age
```

The forward macaroon must be able to decode invoices; the reverse macaroon
must also send payments. Use a new recovery filename for every swap.

## Commands

| Command | Purpose |
| --- | --- |
| `providers list` | List verified provider announcements |
| `swap btc-to-ln` | Pay a Lightning invoice with on-chain BTC |
| `swap ln-to-btc` | Receive on-chain BTC by paying over Lightning |
| `recover inspect` | Inspect redacted recovery metadata offline |
| `recover export`, `export-update` | Create encrypted recovery snapshots from canonical stdin |
| `recover observe-funding`, `observe-claim` | Read chain evidence for a selected funding binding |
| `recover watch-refund`, `sign-refund`, `broadcast-refund` | Watch, sign or submit a BTC to LN refund |
| `recover watch-claim`, `prepare-claim`, `broadcast-claim` | Watch, prepare or submit an LN to BTC claim |
| `treasury status`, `reconcile` | Inspect or reconcile existing regtest conversion jobs (operator tools) |

Use `rill <command> --help` for exact arguments, for example
`rill recover watch-refund --help`.

## Swapping

### Bitcoin to Lightning

`rill swap btc-to-ln` pays `--invoice` from your Core `--wallet`:

1. Verify the selected provider's announcement and negotiate a session.
2. Decode the invoice through your LND and verify the signed terms and limits.
3. Write and verify the encrypted recovery snapshot before accepting.
4. Fund the contract, writing its `.funded` snapshot before broadcasting.
5. Wait for settlement and verify the payment preimage.
6. Write a `.paid` successor before reporting success.

If payment is never observed, the contract may still be funded. A refund is
possible after the recorded refund lock height while the output is unspent.
Funding uses one confirmed P2WPKH or P2TR coin; the CLI does not combine
coins when no single one covers the amount and fee reserve.

### Lightning to Bitcoin

`rill swap ln-to-btc` receives `--payout-sat` into your Core `--wallet`:

1. Verify the provider, negotiate a session and generate a local preimage.
2. Read your Core's economical two-block fee estimate, then request and verify
   signed terms, a wallet destination and the hold invoice.
3. Write the encrypted recovery snapshot before accepting.
4. Pay the hold invoice through LND within your routing fee limit.
5. Verify the provider's funding transaction and write a `.funded` successor.
6. Wait for the required depth, then sign and broadcast the claim, bumping its
   fee within the signed limits only if it is still unconfirmed late.

The requested claim fee reserve pays the larger script-path claim at that
estimate (never below your node's relay and mempool minimum), so the
cooperative claim pays at least that rate too. The claim pays exactly the
signed reserve (or the signed claim fee cap if that is lower), so your wallet
receives exactly `--payout-sat`.
Without an estimate (outside regtest), or if that reserve exceeds
`--max-claim-fee-sat`, the swap stops before requesting terms.

The provider settles its hold invoice with the preimage revealed by the
claim, so the claim must confirm before the provider's refund window. Core
needs `txindex=1` for the funding depth lookup.

The claim watcher keeps the initial fee for the first three quarters of the
window before `refund_lock_height` minus the claim confirmations; in the last
quarter it raises the fee linearly to the ceiling, so a stuck claim still beats
the provider's refund. It reserves a final attempt for the approved fee ceiling and
keeps older attempts available for confirmation checks. Claims affirmatively
refused before broadcast are not first submitted after the safe height deadline.
Ambiguous transmissions remain eligible for rebroadcast because their preimage
may already be exposed; that policy cannot guarantee when the network first
received them. Signed bytes alone, including seeded attempts without disclosure
evidence, do not authorize late submission. Attempts remain memory-only, with no
upgrade-triggered action or retroactive disclosure assumption.

### Limits and relay privacy

| Flag | Use |
| --- | --- |
| `--max-success-fee-sat` | Required provider success fee limit |
| `--fee-rate` | Forward: funding rate, default 2 sat/vB. Reverse: optional claim rate floor above your Core's next-block estimate, default none |
| `--min-claim-fee-reserve-sat` | Reverse: optional claim fee reserve floor, default none (the next-block reserve) |
| `--max-funding-fee-sat`, `--max-refund-fee-sat` | Forward fee limits, default 5,000 sat each |
| `--max-refund-delay-blocks` | Forward refund delay limit, default 288 blocks |
| `--max-fee-estimate-sat-vb` | Cap your Core's fee estimate: forward when checking the provider's cooperative claim fee, reverse when pricing the claim fee reserve. Use it on signet, whose estimator can report hundreds of sat/vB and make you refuse every cooperative claim or overpay the reserve; relay and mempool minimums still apply. On mainnet, setting it prints a warning, since a cap can price fees below the next-block rate |
| `--max-claim-fee-sat` | Reverse claim fee ceiling, default 5,000 sat |
| `--max-routing-fee-sat` | Reverse routing fee limit, default 1,000 sat |
| `--min-refund-delay-blocks` | Reverse minimum provider refund delay, default 72 blocks |
| `--max-incoming-htlc-delay-blocks` | Reverse Lightning hold limit, default 432 blocks |
| `--timeout` | Per-answer timeout, default 60 seconds |
| `--settle-timeout` | Settlement lifetime, default 3,600 seconds |

On public networks, discovery and swaps need either
`--relay-proxy http://127.0.0.1:9080` (a local Tor `HTTPTunnelPort`) or
`--allow-direct-relay` to accept exposing your IP address. Proxied relays
must use `wss://`, except v3 onion relays (`ws://…onion`), which Tor encrypts
and authenticates; onion relays need `--relay-proxy`. There is no direct
fallback. Regtest allows direct connections. `providers list` accepts repeated
`--relay` arguments and skips onion relays quietly when there is no proxy;
compare independent relays, since a relay can withhold announcements.

## Recovery files

Recovery snapshots are encrypted age files with everything needed to inspect
and recover a swap. Protect both the files and their age identity.

- `--recovery-output swap.age` creates the initial snapshot.
- `swap.age.funded` adds the signed funding binding.
- `swap.age.paid` keeps a verified forward payment preimage.
- `.fallback` saves the signed unilateral claim before cooperative disclosure.
- `.cooperating` durably burns the reverse attempt before nonce allocation.
- `.disclosing` retains the exact signed proposal before possible disclosure.
- Files are create-only; existing paths are never overwritten.

Keep every successor and recover from the newest one. An older file can be
valid but miss later funding or payment evidence.
Cooperation has one original bounded window, including preparation, durable
publication, and relay waits. Failure leaves the unilateral claim available;
recovery never restores nonce authority. The claimant sends its completion
partial without waiting for a receipt before broadcasting a verified claim.

`--identity` takes a file path, never the key itself. The file must hold one
X25519 `AGE-SECRET-KEY-1...` line, be a regular file (not a symlink), and have
owner-only permissions such as `0600`.

```sh
rill recover inspect --network ../rill-docs/networks/signet.json \
  --crypto-library "$PWD/tmp/native/librill_crypto.so" \
  --identity "$AGE_IDENTITY" btc-to-ln.age.funded
```

Inspection prints redacted metadata without contacting nodes or providers.
For passphrase-encrypted files use `--passphrase-prompt` instead of
`--identity`.

## Recovering a swap

Select the exact `--funding-attempt-id` and `--binding-revision` recorded for
the intended funding binding, taken from your retained swap evidence.
Recovery commands use `--rpc-port` and `--rpc-cookie` (numeric loopback),
not the swap's `--core-port` and `--core-cookie`. The examples below use
regtest:

```bash
recovery=(--network ../rill-docs/networks/regtest.json
  --crypto-library "$PWD/tmp/native/librill_crypto.so"
  --identity "$AGE_IDENTITY"
  --funding-attempt-id "$ATTEMPT" --binding-revision "$REVISION"
  --rpc-cookie "$CORE_COOKIE" --rpc-port 18443)
```

### Refund a Bitcoin to Lightning swap

Run `watch-refund` once the refund lock height is reached. If the invoice is
in your own LND, pass an `invoices:read` macaroon so the watcher can check
whether it was settled:

```bash
mkdir -m 700 refund-attempts
rill recover watch-refund "${recovery[@]}" \
  --lnd-port 10009 --lnd-tls-cert "$LND_TLS_CERT" \
  --lnd-invoice-macaroon "$INVOICES_MACAROON" \
  --intent-dir refund-attempts --initial-fee-sat 300 --max-fee-sat 3000 \
  btc-to-ln.age.funded
```

For someone else's invoice, use `--chain-only` instead of the LND flags; that
mode cannot tell whether the invoice was paid. The watcher records each
attempt before sending, reloads them on restart, and raises fees within the
signed limits.

To sign and submit separately:

```bash
rill recover sign-refund "${recovery[@]}" --fee-sat 500 \
  --output refund.raw btc-to-ln.age.funded
rill recover broadcast-refund "${recovery[@]}" --fee-sat 500 \
  --intent refund-intent.json btc-to-ln.age.funded
```

`sign-refund` never broadcasts. `broadcast-refund` rebuilds and checks the
refund itself (it does not read `refund.raw`) and records an intent before
its single submission attempt.

### Claim a Lightning to Bitcoin swap

Claim while the signed timing margin still allows it:

```bash
rill recover watch-claim "${recovery[@]}" \
  --initial-fee-sat 300 --max-fee-sat 3000 ln-to-btc.age.funded
```

It keeps `--initial-fee-sat` for the first three quarters of the remaining
window and only then raises it toward `--max-fee-sat`, so choose an initial
fee that confirms soon at current rates. It signs only once the funding output
has the signed confirmation depth. Pass
the newest snapshot: from `.fallback` on, it also holds the claim the live swap
prepared, which may already be broadcast. The watcher then reports that claim
and exits with `claim_confirmed` once it confirms, without signing another.

`prepare-claim` writes an encrypted claim plan without broadcasting; the plan
reveals the preimage. `broadcast-claim` is regtest-only and requires
`--acknowledge-regtest-preimage-disclosure`.

## After a timeout or crash

1. Keep all snapshots, claim plans and submission intents.
2. Inspect any `.funded` or `.paid` successors, including ones written without
   a success message. A missing file does not prove nothing happened.
3. Check Core transactions and LND invoice or payment state (for reverse
   swaps, `lncli listpayments`).
4. Do not retry payment, signing or submission blindly, and never delete an
   intent to force another attempt. A timed-out RPC may still be running.
5. Choose the refund or claim workflow only after reconciling this evidence.

## Safety

- Use trusted network JSON and native library files, and keep recovery output
  and intent directories on trusted local storage.
- Never pass private keys, preimages, cookie contents, macaroons or
  passphrases as arguments. Credential options take file paths, and
  passphrases use a terminal prompt.
- Do not publish recovery files or secret-bearing output. Test fixtures
  contain public test secrets, not usable credentials.

## Tests

From `rill-cli/`, the default CI selection:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  -m 'not native_crypto and not bitcoin_core and not age_interop' \
  --basetemp=tmp/pytest-ci
```

| Marker | Needs |
| --- | --- |
| `native_crypto` | `RILL_CRYPTO_LIBRARY` set to the built library; `RILLSWAP_RUN_NATIVE_CRYPTO=1` for tests that require explicit opt-in |
| `bitcoin_core` | `RILLSWAP_RUN_BITCOIN_CORE=1`, Docker and the native build |
| `age_interop` | `RILL_CRYPTO_LIBRARY` and `AGE_BINARY` pointing to Go age (v1.3.1 for the pinned gate, see `scripts/check_age_interop.py --help`) |

## Further reading

- [Protocol specifications](../rill-docs/specs/)
- [Architecture](../rill-docs/ARCHITECTURE.md)
- [Development and local testing](../DEVELOPMENT.md)
- [Security policy](../SECURITY.md)
