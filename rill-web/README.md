# rill-web

The RillSwap browser app swaps Bitcoin to or from Lightning, and USDC/USDT to
or from Lightning. It is a static site with no backend of its own: it
discovers providers over Nostr, validates contracts, transactions and
signatures locally, and keeps encrypted recovery records in the browser.

**Status:** experimental and unaudited. New mainnet funding is disabled.

`swap.html` is the swap app and `index.html` a disconnected diagnostic
preview. In the GitHub Pages build, the swap app is the landing page and the
preview is `diagnostic.html`.

## Install

Use Bun 1.3.11, matching CI. This component depends on `rill-payments` from
the same checkout.

```sh
cd rill-web
bun install --frozen-lockfile
```

## Quick start

Run the full Docker development stack from the repository root:

```sh
dev/devctl up
```

Open http://127.0.0.1:5273/swap.html (the demo shop is at
http://127.0.0.1:8090/). See [DEVELOPMENT.md](../DEVELOPMENT.md) for
walkthroughs.

For standalone development, from `rill-web/`:

```sh
VITE_RILLSWAP_NETWORK=signet bunx vite --host 127.0.0.1
```

Open `/swap.html`, pick a test network in Settings, review the connection
and fee settings, and back up the recovery wallet before accepting a quote.
Loading the page or changing settings does not contact a relay.

## Configuration

Deployment defaults are set and validated at build time.

| Variable | Meaning |
| --- | --- |
| `VITE_RILLSWAP_NETWORK` | `mainnet`, `signet`, `testnet4` or `regtest` |
| `VITE_RILLSWAP_RELAYS` | Nostr relay URLs, comma or whitespace separated |
| `VITE_RILLSWAP_MEMPOOL_API` | Esplora-compatible chain API |
| `VITE_RILLSWAP_BROADCAST_API` | Transaction broadcast API |
| `VITE_RILLSWAP_NODE_API` | Optional user-node browser transport |
| `VITE_RILLSWAP_EVM_RPC` | Read-only EVM RPC endpoint |
| `VITE_RILLSWAP_EVM_SPONSOR` | Gas sponsor endpoint |
| `VITE_RILLSWAP_EVM_ENTRY_POINT` | Pinned ERC-4337 EntryPoint address |
| `VITE_RILLSWAP_EVM_7702_DELEGATE` | Pinned EIP-7702 delegate address |
| `VITE_RILLSWAP_EVM_SPONSOR_POLICY` | Optional sponsor gas policy UUID |

Set the sponsor endpoint, EntryPoint and delegate together, or none of them.
A build without configuration opens a blocked mainnet preview. The older
single-relay `VITE_RILLSWAP_RELAY` still works but cannot be combined with
`VITE_RILLSWAP_RELAYS`. Plaintext relays are only allowed on loopback for
regtest. Custom endpoints must be set at build time so the Content Security
Policy allows their origins; check their CORS support before deploying.

## Scripts

From `rill-web/`:

| Command | Purpose |
| --- | --- |
| `bun run typecheck` | Check TypeScript |
| `bun test unit` | Run unit tests |
| `bunx playwright install chromium` | Install the test browser |
| `bun run test` | Run browser tests |
| `bun run build` | Build the static site in `dist/` |
| `bun run build:pages` | Assemble the GitHub Pages site in `tmp/pages/` |
| `bun run test:pages` | Test the assembled Pages site |

Local builds and tests never publish anything.

## Using the app

Pick a pair under **You send / You receive** (or use the switch button).
Available providers and their advertised assets decide which pairs can be
quoted.

**Bitcoin to Lightning.** Paste the Lightning invoice to be paid. After
accepting the quote and saving the recovery files, send the exact amount to
the displayed contract address from any native segwit wallet (a `bitcoin:`
link and QR code are shown). Advanced users can supply a finalized PSBT. Do
not send extra or multiple deposits: deposits that break the funding rules
stop the swap and cannot currently be refunded from the panel.

**Lightning to Bitcoin.** Choose the Bitcoin payout and compare offers,
approve execution, save the recovery backup, and pay the displayed invoice
from any Lightning wallet (or a configured LND node). The app checks the
provider's funding and prepares the Bitcoin claim.

**USDC or USDT to Lightning.** Paste the Lightning invoice and connect an
injected EVM wallet on the provider's chain. Approve the token allowance if
needed and authorize the contract lock. The wallet keeps the refund key and
needs native gas.

**Lightning to USDC or USDT.** Choose the token payout and pay the displayed
invoice from any Lightning wallet. With a gas sponsor configured, just type
the receiving address; it needs no ETH. Without one, connect an injected EVM
wallet that receives the tokens and has gas for the claim. Claim promptly: a
failed wallet or sponsor request does not prove the preimage stayed private.

## Recovery

The app creates an origin-local recovery wallet. Its JSON backup holds a
12-word mnemonic, and you must confirm a matching backup before accepting a
quote. **The mnemonic alone cannot recover a swap**: also keep every
encrypted per-swap `.age` file the app asks you to download, including the
funded record.

Browser recovery keys are not encrypted at rest; same-origin scripts and
anyone with access to browser storage can read them. Do not clear browser
storage while funds are pending. The recovery wallet is not a general
spending wallet, and cloning it across devices can reuse addresses.

To reopen a swap, use **Recover a swap**, select the original network and
open the newest file, or open the bookmarked tracking link. The link carries
an encrypted recovery container in its URL fragment (never sent to the
server); treat it like the file. Opening or reloading never resumes protocol
sessions or retries payments, claims or refunds by itself.

- **Bitcoin to Lightning refunds:** use **Check funding**, wait until the
  refund matures, review the destination and fee, then prepare, download
  and broadcast as separate explicit steps. Exporting the signed refund
  disables in-app broadcast.
- **Stablecoin to Lightning:** the wallet can refund after the contract
  timelock.
- **Lightning to stablecoin:** an unexposed swap can be claimed from the same
  browser. In another browser the imported file is inspection-only.

Bitcoin refunds also work with [rill-cli](../rill-cli/README.md) and a synced
Bitcoin Core node: download `rillswap-recovery.age-key` from the recovery
details and pass it as `--identity` to `rill recover watch-refund` or
`rill recover sign-refund`. The JSON mnemonic backup is not an age identity.

## Privacy and trust

| Service | What it can learn |
| --- | --- |
| Nostr relays | Your IP, keys used for messaging, message sizes and timing; swap payloads are encrypted |
| Swap provider | The swap terms and the invoice or payout details needed for the flow |
| Chain API | Your IP and the public transactions and outputs you query |
| Gas sponsor | The claim preimage and the receiving address |

Funding checks are observations from a trusted API, not independent
consensus verification. All runtime assets are bundled; the swap app only
connects to configured endpoints. The HTML meta CSP is not a full hosting
policy and does not prevent framing, so hosts must set real HTTP security
headers. There is no update check: reloading a hosted URL can run different
code, and the build label is not authenticated release pinning.

## Hosting

### GitHub Pages

The [Pages workflow](../.github/workflows/pages.yml) tests and deploys the
site on every push to `main` or when run manually; pull requests never
deploy. Set the repository's Pages source to **GitHub Actions**.
`bun run build:pages` produces `tmp/pages/` with:

- `/`: the mainnet preview, with new funding blocked
- `/signet/`: the signet swap app
- `diagnostic.html` in each: the disconnected preview

The Pages build ignores local `VITE_RILLSWAP_*` overrides so regtest
endpoints never leak into the public site.

### Serve locally

```sh
VITE_RILLSWAP_NETWORK=signet bun run build
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

Open http://127.0.0.1:8080/swap.html. Opening files with `file://` is not
supported.

### Alchemy gas sponsor

The intended public-network sponsor is Alchemy's Wallet API:

| Setting | Value |
| --- | --- |
| Sponsor endpoint | `https://api.g.alchemy.com/v2/<key>` |
| EntryPoint | `0x0000000071727de22e5e9d8baf0edac6f37da032` |
| SMA7702 v1.1.0 delegate | `0x77021100bd87b7008e5e1989d0eb38555d0d0000` |
| Sponsor policy | Your gas policy UUID |

Restrict the API key to your site's origin. The policy may be omitted when a
proxy applies its own; unsponsored calls are refused. **Live Alchemy
responses and browser CORS have not been tested**, so verify them on a
testnet first.

## Opt-in tests

Regtest browser checks use `playwright.regtest.config.ts` and a running
disposable dev stack (see [DEVELOPMENT.md](../DEVELOPMENT.md)).

| Flag | Check | Needs |
| --- | --- | --- |
| `RILLSWAP_TEST_RECOVERY_NATIVE=1` | Native recovery, refund and reverse claim parity | Running `rillswap-dev-tools-1` container |
| `RILLSWAP_RUN_WEB_CLI_AGE=1` | Browser age files decrypted by Go age and the CLI | Chromium, local CLI, `RILL_CRYPTO_LIBRARY`, `AGE_BINARY` (Go age v1.3.1) |
| `RILLSWAP_RUN_BROWSER_REVERSE_REGTEST=1` | Funded Lightning to Bitcoin flow | Separate Compose project named `rill-reverse-browser-*` with a nondefault `RILL_DEV_WEB_PORT` |
| `RILLSWAP_RUN_BROWSER_ERC20_REGTEST=1` | Both stablecoin directions with a test EVM wallet | Dev stack with Anvil and dev tokens |

## Further reading

- [Protocol specifications](../rill-docs/specs/)
- [Architecture](../rill-docs/ARCHITECTURE.md)
- [Development and local testing](../DEVELOPMENT.md)
- [Security policy](../SECURITY.md)
