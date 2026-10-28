/**
   * Experimental browser BTC and LN client page. Everything sensitive stays in
 * contract secrets stay in this tab; the recovery root is stored locally.
 * The user's own wallet funds and broadcasts, and the
 * user's own downloads hold the age-encrypted recovery files.
 */
import "./swap.css";
import { hexToBytes } from "@noble/hashes/utils.js";
import mainnet from "./networks/mainnet.json";
import regtest from "./networks/regtest-rillswap-e2e-v1.json";
import signet from "./networks/signet.json";
import testnet4 from "./networks/testnet4.json";
import { addressScript, scriptAddress } from "./swap/address";
import { browserCosigner } from "./swap/browserCosigner";
import { type FundingRequest, type FundingSource, type SwapRequest } from "./swap/swap";
import { observeDeposit } from "./swap/depositWatch";
import { qrSvg } from "./qr";
import { TransactionRefusedError } from "./swap/transaction";
import { explorerTxUrl, mempoolApiForNetwork, relaysForNetwork, trustedEvmAsset, validateEvmSponsor, validateMempoolApi, validateRelays, type EvmSponsorDefaults, type NetworkName } from "./swap/config";
import { GasSponsor, newStagingSecret, stagingAddress } from "./swap/gasSponsor";
import { readChainTip } from "./swap/chainTip";
import { BrowserRecoveryWallet, parseWalletBackup } from "./browserRecoveryWallet";
import { type DirectoryEntry, DIRECTORY_PROFILES, discoverDirectory, discoverMarketplace, eligibleProviders, indicativeFee, ineligibilityReason, quoteProviders, quoteReverseProviders,
  estimateFromDirectory, providerLimits, type LocatedQuote, MAX_QUOTE_PROVIDERS, quoteErc20Providers, quoteLnErc20Providers, selectEvmAsset, unexpired } from "./swap/marketplace";
import { erc20Rank, fastestAndCheapest, forwardRank, lnErc20Rank, type Ranked, reverseRank, type SortMode } from "./swap/ranking";
import type { Erc20SwapRequest, PreparedErc20Swap } from "./swap/erc20Swap";
import { EvmRpc } from "./swap/evmHtlc";
import { connectEvmWallet, mountErc20Execution, mountLnErc20Execution, parseTokenAmount, tokenLabel, type LnErc20Claimer } from "./erc20Ui";
import { EvmClaimJournal } from "./evmClaimJournal";
import type { PreparedLnErc20Quote } from "./swap/lnErc20Swap";
import type { PreparedReverseQuote, ReverseSwapRequest } from "./swap/reverseSwap";
import { invoiceBinding } from "./swap/bolt11";
import { confirmationsLabel, fundingWaitText, quoteSelectionLabel, stoppedSwapAdvice } from "./swapUiStatus";
import { ASSETS, type AssetId, routeFor, STABLECOIN_SYMBOL } from "./swapPairs";
import { recoveryPanel } from "./recoveryUi";
import { parseSwapLink, swapLinkFragment } from "./swapLink";
import { mountReverseExecution, mountResumedReverseExecution } from "./reverseExecutionUi";
import { BrowserReverseJournal } from "./browserReverseJournal";
import { resumeBrowserReverseExecution } from "./browserReverseRecovery";
import { decryptRecoveryContainer } from "./recoveryKeys";

const NETWORKS = { mainnet, signet, testnet4, regtest } as const;
/** How often an idle, visible page reloads the provider directory. */
const DIRECTORY_REFRESH_MS = 5 * 60_000;

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id?: string): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  element.textContent = text;
  if (id) element.id = id;
  return element;
}

function field(root: HTMLElement, id: string, label: string, value = "", hint = ""): HTMLInputElement {
  const caption = node("label", label);
  caption.htmlFor = id;
  const input = node("input", "", id);
  input.value = value;
  input.autocomplete = "off";
  input.spellcheck = false;
  root.append(caption, input);
  if (hint) root.append(node("small", hint));
  return input;
}

/**
 * Manual-selection tags for each offer: its funding depth, plus "Fastest" and
 * "Cheapest" when several offers differ (one offer can carry both).
 */
function offerTags<T>(offers: readonly T[], key: (offer: T) => Ranked): (offer: T) => HTMLElement[] {
  const { fastest, cheapest } = fastestAndCheapest(offers, key);
  const tag = (text: string, kind: string): HTMLElement => {
    const element = node("span", text); element.className = `swap-offer-tag ${kind}`; return element;
  };
  return (offer) => [
    tag(confirmationsLabel(key(offer).depth), "depth"),
    ...(offer === fastest ? [tag("Fastest", "fastest")] : []),
    ...(offer === cheapest ? [tag("Cheapest", "cheapest")] : []),
  ];
}

const btc = (sats: bigint): string => `${sats / 100_000_000n}.${(sats % 100_000_000n).toString().padStart(8, "0")}`;

/** Link to a transaction on the user's own mempool instance. */
function txLink(api: string, txid: string): HTMLAnchorElement {
  const link = node("a", txid);
  link.href = explorerTxUrl(api, txid); link.target = "_blank"; link.rel = "noopener noreferrer";
  return link;
}

function positive(input: HTMLInputElement, what: string): bigint {
  if (!/^[0-9]{1,16}$/.test(input.value.trim())) throw new Error(`${what} must be a whole number`);
  return BigInt(input.value.trim());
}

/** Resolve when the user clicks `label`; the button is removed afterwards. */
function waitForClick(panel: HTMLElement, label: string): Promise<void> {
  const button = node("button", label);
  button.type = "button";
  panel.append(button);
  return new Promise((resolve) => {
    button.addEventListener("click", () => {
      button.remove();
      resolve();
    }, { once: true });
  });
}

function mount(root: HTMLElement): void {
  const header = node("header");
  const brand = node("a", "rill", "swap-brand");
  brand.href = "./swap.html";
  brand.setAttribute("aria-label", "RillSwap home");
  // The network indicator doubles as a switcher: a published sibling build opens
  // its own page (reload-stable URL), any other network reconfigures this one.
  const badge = node("select", "", "swap-network-badge");
  badge.setAttribute("aria-label", "Switch network");
  for (const name of Object.keys(NETWORKS)) {
    badge.append(Object.assign(node("option", name === "mainnet" ? "Mainnet" : `${name} · test funds`), { value: name }));
  }
  header.append(brand, badge);
  const intro = node("div");
  intro.className = "swap-intro";
  const heroTitle = node("h1");
  const heroTagline = node("p");
  intro.append(node("p", "BITCOIN. WITHOUT THE DETOUR.", "swap-eyebrow"), heroTitle, heroTagline);
  const card = node("section", "", "swap-card");
  const cardHead = node("div");
  cardHead.className = "card-heading";
  const settingsButton = node("button", "Settings", "swap-settings-toggle");
  settingsButton.type = "button";
  settingsButton.setAttribute("aria-haspopup", "dialog");
  const providersButton = node("button", "Providers", "swap-providers-toggle");
  providersButton.type = "button";
  providersButton.setAttribute("aria-haspopup", "dialog");
  cardHead.append(node("h2", "Swap Bitcoin"), providersButton, settingsButton);
  const settings = node("dialog", "", "swap-settings");
  const settingsHead = node("div");
  settingsHead.className = "card-heading";
  const closeSettings = node("button", "Close", "swap-settings-close");
  closeSettings.type = "button";
  settingsHead.append(node("h2", "Swap settings"), closeSettings);
  settings.append(settingsHead);
  settingsButton.onclick = () => settings.showModal();
  closeSettings.onclick = () => settings.close();
  const form = node("form", "", "swap-form");
  const networkLabel = node("label", "Network");
  const network = node("select", "", "swap-network");
  networkLabel.htmlFor = network.id;
  for (const name of Object.keys(NETWORKS)) network.append(Object.assign(node("option", name), { value: name }));
  network.value = __SWAP_DEFAULTS__.network;
  settings.append(networkLabel, network);
  const relayLabel = node("label", "Nostr relays (one per line)");
  const relay = node("textarea", "", "swap-relay");
  relayLabel.htmlFor = relay.id;
  relay.value = __SWAP_DEFAULTS__.relays.join("\n");
  relay.spellcheck = false;
  settings.append(relayLabel, relay, node("small", "Up to eight relays, used to find providers and talk to them. Each relay sees your IP unless you use Tor; onion relays only connect in Tor Browser."));
  const chainApi = field(settings, "swap-chain-api", "Mempool API", __SWAP_DEFAULTS__.mempoolApi,
    "Any mempool or Esplora instance over https, for example https://mempool.example/api. Used for confirmations and transaction links.");
  const broadcastApi = field(settings, "swap-broadcast-api", "Transaction broadcast API", __SWAP_DEFAULTS__.broadcastApi,
    "Where claim and refund transactions are sent. Usually the same as the mempool API.");
  const evmRpc = field(settings, "swap-evm-rpc", "EVM RPC (stablecoin swaps)", __SWAP_DEFAULTS__.evmRpc ?? "",
    "Read-only chain access for stablecoin swaps; your wallet extension signs. This operator sees your IP and the swap's addresses. Custom origins need a deployment CSP allowance.");
  const evmSponsor = field(settings, "swap-evm-sponsor", "Gas sponsor (receive stablecoins without a wallet)", __SWAP_DEFAULTS__.evmSponsor?.url ?? "",
    "Alchemy-compatible wallet API that pays claim gas. Leave empty to claim from your own wallet extension. The sponsor learns the claim preimage and your destination address.");
  const evmEntryPoint = field(settings, "swap-evm-entry-point", "ERC-4337 EntryPoint v0.7", __SWAP_DEFAULTS__.evmSponsor?.entryPoint ?? "",
    "Sponsored claims are bound to this EntryPoint; the browser recomputes every hash it signs.");
  const evmDelegate = field(settings, "swap-evm-delegate", "EIP-7702 account delegate", __SWAP_DEFAULTS__.evmSponsor?.delegate ?? "",
    "The only contract the browser-held claim key will delegate to. Changing it moves trust to that contract's code.");
  const evmSponsorPolicy = field(settings, "swap-evm-sponsor-policy", "Gas sponsor policy ID (optional)", __SWAP_DEFAULTS__.evmSponsor?.policyId ?? "",
    "Alchemy gas policy UUID sent with each sponsored claim. Leave empty for a sponsor proxy that applies its own policy.");
  const sponsorConfigured = (): boolean => [evmSponsor, evmEntryPoint, evmDelegate].some((input) => input.value.trim() !== "");
  const selectedSponsor = (): EvmSponsorDefaults | null => sponsorConfigured()
    ? validateEvmSponsor(evmSponsor.value.trim(), evmEntryPoint.value.trim().toLowerCase(), evmDelegate.value.trim().toLowerCase(), network.value as NetworkName,
      evmSponsorPolicy.value.trim()) : null;
  const identity = field(settings, "swap-provider", "Provider identity", "",
    "Automatic by default. Optionally pin a provider's 64-character public identity key, or choose one under Providers.");
  const rankingLabel = node("label", "Provider ranking");
  const ranking = node("select", "", "swap-ranking");
  rankingLabel.htmlFor = ranking.id;
  ranking.append(Object.assign(node("option", "Fastest payment, then lowest price"), { value: "time" }),
    Object.assign(node("option", "Lowest price, then fastest payment"), { value: "price" }));
  ranking.value = "time";
  settings.append(rankingLabel, ranking, node("small", "Fastest means the fewest funding confirmations the provider waits for. " +
    "Providers that do not announce it rank after those that do. Applies to automatic choice and the order of offers."));
  const sortMode = (): SortMode => ranking.value === "price" ? "price" : "time";
  const automaticText = (): string => sortMode() === "time" ? "fastest payment, then lowest price" : "lowest price, then fastest payment";
  identity.placeholder = "Automatic (by provider ranking)";
  // The provider directory: every announced provider with its limits and fees, browsable before any amount.
  const providers = node("dialog", "", "swap-providers");
  const providersHead = node("div");
  providersHead.className = "card-heading";
  const closeProviders = node("button", "Close", "swap-providers-close");
  closeProviders.type = "button";
  providersHead.append(node("h2", "Providers"), closeProviders);
  const providersIntro = node("p", "Fees and limits are what each provider announces; the signed quote is final.", "swap-providers-intro");
  const reloadProviders = node("button", "Refresh", "swap-providers-load");
  reloadProviders.type = "button";
  const providersStatus = node("p", "", "swap-providers-status");
  providersStatus.setAttribute("role", "status");
  const providersList = node("div", "", "swap-providers-list");
  providers.append(providersHead, providersIntro, providersStatus, reloadProviders, providersList);
  providersButton.onclick = () => providers.showModal();
  closeProviders.onclick = () => providers.close();
  const providerChoice = node("p", "", "swap-provider-choice");
  const PROFILE_TITLE: Record<string, string> = { "btc-to-ln/v1": "Bitcoin → Lightning", "ln-to-btc/v1": "Lightning → Bitcoin",
    "erc20-to-ln/v1": "Stablecoin → Lightning", "ln-to-erc20/v1": "Lightning → Stablecoin" };
  const FEE_SAMPLE = 100_000n;
  let directoryEntries: readonly DirectoryEntry[] = [];
  const showProviderChoice = (): void => {
    const pinned = identity.value.trim();
    providerChoice.textContent = pinned ? `Provider: ${pinned.slice(0, 12)}… (chosen by you)` : `Provider: automatic, ${automaticText()}`;
  };
  /** One table per swap type; a provider serving several types appears in each of them. */
  const renderDirectory = (): void => {
    const pinned = identity.value.trim();
    const choose = (value: string, idle: string): HTMLButtonElement => {
      const control = node("button", value === pinned ? "Selected" : idle);
      control.type = "button"; control.dataset.provider = value; control.disabled = value === pinned;
      control.onclick = () => { identity.value = value; showProviderChoice(); updateEstimate(); renderDirectory(); };
      return control;
    };
    const automatic = node("div", "", "swap-provider-automatic");
    automatic.append(node("p", `Automatic: ask every eligible provider and take the best signed offer (${automaticText()}).`), choose("", "Use automatic"));
    providersList.replaceChildren(automatic);
    for (const profile of DIRECTORY_PROFILES) {
      const entries = directoryEntries.filter((entry) => entry.profiles.includes(profile));
      if (entries.length === 0) continue;
      const group = node("section");
      group.className = "swap-provider-group"; group.dataset.profile = profile;
      const stablecoin = profile.includes("erc20");
      const head = node("tr");
      for (const title of ["Provider", ...(stablecoin ? ["Assets"] : []), "Limits (sat)", "Fee", `On ${FEE_SAMPLE.toLocaleString()} sat`, "Confirmations", "Listed until", ""]) {
        head.append(node("th", title));
      }
      const body = node("tbody");
      for (const entry of entries) {
        const row = node("tr");
        row.className = "swap-provider"; row.dataset.provider = entry.identity;
        if (entry.identity === pinned) row.classList.add("selected");
        const who = node("td", `${entry.identity.slice(0, 12)}…`);
        who.title = `${entry.identity} · relays: ${entry.relayUrls.join(", ")}`;
        const fee = entry.indicativeFeePolicy;
        const cells = [who,
          ...(stablecoin ? [node("td", [...new Set(entry.evmAssets.map((asset) => asset.token_symbol))].join(", "))] : []),
          node("td", entry.amountBands.map((band) => `${BigInt(band.minimum_sat).toLocaleString()} – ${BigInt(band.maximum_sat).toLocaleString()}`).join(", ")),
          node("td", `${BigInt(fee.base_sat).toLocaleString()} sat + ${(fee.proportional_millionths / 10_000).toFixed(2)}%`),
          node("td", `${indicativeFee(fee, FEE_SAMPLE).toLocaleString()} sat`),
          node("td", entry.fundingConfirmations === null ? "unknown" : String(entry.fundingConfirmations)),
          node("td", new Date(entry.expiresAt * 1000).toLocaleString())];
        const action = node("td"); action.append(choose(entry.identity, "Choose"));
        row.append(...cells, action);
        body.append(row);
      }
      const table = node("table"), thead = node("thead");
      thead.append(head); table.append(thead, body);
      group.append(node("h3", PROFILE_TITLE[profile] ?? profile), table);
      providersList.append(group);
    }
  };
  let directoryLoaded = false;
  let directoryWarnings: readonly string[] = [];
  let directoryGeneration = 0, directoryLoading = false, directoryAttemptAt = 0;
  const showDirectoryStatus = (): void => {
    const count = directoryEntries.length;
    providersStatus.textContent = count === 0 ? "No providers found on your relays." :
      `${count} provider${count === 1 ? "" : "s"} on ${network.value}.` +
      (directoryWarnings.length ? ` Discovery was incomplete: ${directoryWarnings.join("; ")}.` : "");
  };
  /**
   * Loads on page load, network change, Refresh, and periodically (see refreshDirectory); the estimate
   * line and the Providers dialog share it. Only the newest load may apply its result.
   */
  const loadDirectory = (): void => {
    const name = network.value as NetworkName;
    const generation = ++directoryGeneration; // also discards a load still running for other settings
    directoryAttemptAt = Date.now();
    let urls: readonly string[];
    try { urls = validateRelays(relay.value.trim(), name); } catch (error) {
      directoryLoading = false; reloadProviders.disabled = false;
      providersStatus.textContent = (error as Error).message; return;
    }
    directoryLoading = true;
    reloadProviders.disabled = true;
    providersStatus.textContent = "Loading providers...";
    void discoverDirectory(urls, NETWORKS[name]).then((directory) => {
      if (generation !== directoryGeneration) return;
      directoryEntries = directory.entries; directoryWarnings = directory.warnings;
      directoryLoaded = true;
      renderDirectory();
      showDirectoryStatus();
    }, (error: Error) => { if (generation === directoryGeneration) providersStatus.textContent = error.message; }).finally(() => {
      if (generation !== directoryGeneration) return;
      directoryLoading = false; reloadProviders.disabled = false; updateEstimate();
    });
  };
  reloadProviders.onclick = loadDirectory;
  identity.oninput = ranking.onchange = () => { showProviderChoice(); updateEstimate(); renderDirectory(); };
  renderDirectory();
  showProviderChoice();
  const pair = node("div", "", "swap-pair");
  const pairSide = (id: string, caption: string, value: AssetId): HTMLSelectElement => {
    const box = node("label");
    box.htmlFor = id;
    const select = node("select", "", id);
    for (const item of ASSETS) {
      select.append(Object.assign(node("option", item.unavailable ? `${item.symbol} · soon` : item.symbol),
        { value: item.id, title: item.name }));
    }
    select.value = value;
    box.append(node("span", caption), select);
    pair.append(box);
    return select;
  };
  const fromAsset = pairSide("swap-from", "You send", "btc");
  const flip = node("button", "⇄", "swap-flip");
  flip.type = "button";
  flip.title = flip.ariaLabel = "Switch direction";
  pair.append(flip);
  const toAsset = pairSide("swap-to", "You receive", "ln");
  const pairNote = node("p", "", "swap-pair-note");
  pairNote.setAttribute("role", "note");
  form.append(pair, pairNote, providerChoice);
  const invoiceBox = node("div");
  const invoice = field(invoiceBox, "swap-invoice", "Lightning invoice to pay (BOLT11)");
  invoice.placeholder = "Paste your Lightning invoice";
  const receiveBox = node("div");
  const receiveAddress = field(receiveBox, "swap-receive-address", "Bitcoin address to receive");
  receiveAddress.placeholder = "bc1... (your wallet)";
  const receiveAmount = field(receiveBox, "swap-receive-amount", "Amount to receive (sat)");
  receiveAmount.inputMode = "numeric";
  receiveAmount.placeholder = "50000";
  // Live estimate from announced fees, so Swap can proceed without a separate review when the signed quote is no worse.
  const estimate = node("p", "", "swap-estimate");
  estimate.setAttribute("role", "status");
  // The directory entry the shown estimate names: a signed offer no worse on both price and depth may skip review.
  let estimatedTotal: bigint | null = null, estimatedDepth: number | null = null;
  const withinEstimate = (price: bigint, depth: number | null): boolean => estimatedTotal !== null && price <= estimatedTotal &&
    (estimatedDepth === null || (depth !== null && depth <= estimatedDepth));
  const updateEstimate = (): void => {
    estimatedTotal = null; estimatedDepth = null;
    const route = routeFor(fromAsset.value, toAsset.value);
    if (route.profile === null || route.unavailable) { estimate.textContent = ""; return; }
    if (route.profile === "ln-to-erc20/v1") {
      estimate.textContent = `Enter the ${route.to.symbol} amount to receive. The Lightning price is quoted before connecting an EVM wallet; gas is extra.`;
      return;
    }
    let amount: bigint;
    try {
      amount = route.profile === "ln-to-btc/v1"
        ? positive(receiveAmount, "Amount to receive")
        : BigInt(invoiceBinding(invoice.value.trim(), network.value as NetworkName).amount_msat) / 1000n;
    } catch {
      estimate.textContent = route.profile === "ln-to-btc/v1" ? "Enter the amount to receive to see the fee." : "Paste a Lightning invoice that includes an amount to see the fee.";
      return;
    }
    if (route.profile === "erc20-to-ln/v1") {
      // Token prices are only known from a signed quote; the announced fee policy is denominated in sat.
      estimate.textContent = `You pay the ${amount.toLocaleString()} sat invoice in ${route.from.symbol} at the provider's signed rate, plus its fee. ` +
        "The exact amount is shown before your wallet signs.";
      return;
    }
    if (!directoryLoaded) { estimate.textContent = "Loading provider fees..."; return; }
    const found = estimateFromDirectory(directoryEntries, route.profile, amount, identity.value.trim(), undefined, sortMode());
    if ("reason" in found) { estimate.textContent = found.reason; return; }
    estimatedTotal = amount + found.feeSat; estimatedDepth = found.fundingConfirmations;
    estimate.textContent = (route.profile === "btc-to-ln/v1"
      ? `You send about ${estimatedTotal.toLocaleString()} sat (${amount.toLocaleString()} sat invoice + ${found.feeSat.toLocaleString()} sat provider fee via ${found.identity.slice(0, 12)}…). Your wallet's network fee is extra. `
      : `You pay about ${estimatedTotal.toLocaleString()} sat over Lightning (${found.feeSat.toLocaleString()} sat provider fee via ${found.identity.slice(0, 12)}…) to receive ${amount.toLocaleString()} sat. `) +
      fundingWaitText(route.profile, found.fundingConfirmations);
  };
  invoice.oninput = receiveAmount.oninput = updateEstimate;
  form.append(invoiceBox, receiveBox, estimate);
  const keyRecommendation = node("p", "Save your 12-word recovery key; it is stored in this browser, but Tor Browser and private windows may erase it on restart.", "swap-key-recommendation");
  const setup = node("details", "", "swap-wallet-setup");
  const prerequisites = node("p", "", "swap-prerequisites");
  setup.append(node("summary", "Recovery key & advanced overrides"), prerequisites);
  const walletStatus = node("p", "Preparing your browser recovery key...", "swap-wallet-status");
  const walletActions = node("div", "", "swap-wallet-actions");
  setup.append(walletStatus, walletActions);
  // Overrides apply to Bitcoin to Lightning only; the recovery key serves both directions.
  const overrides = node("div", "", "swap-forward-overrides");
  setup.append(overrides);
  const refund = field(overrides, "swap-refund", "Refund address override (optional)", "",
    "Leave empty for a fresh address derived from your browser recovery key. Otherwise use your own wallet's P2WPKH or P2TR address.");
  const tip = field(overrides, "swap-tip", "Block height override (optional)", "", "Leave empty to fetch the height from the configured mempool API.");
  const age = field(overrides, "swap-age", "Recovery encryption recipient override (optional, age1...)", "",
    "Leave empty for the browser key. An override requires keeping its corresponding private age key yourself.");
  const privacy = node("details", "", "swap-privacy");
  const chainDisclosure = node("li", "", "swap-chain-disclosure");
  const relayDisclosure = node("li", "", "swap-relay-disclosure");
  const privacyList = node("ul");
  privacyList.append(
    node("li", "No account. Your keys and swap records stay in this browser and are never uploaded."),
    relayDisclosure, chainDisclosure,
    node("li", "A provider only sees what its swap needs: your invoice, or your payout address and payment hash, or your EVM wallet address."),
    node("li", "Providers are not trusted. On-chain contracts and hold invoices enforce every swap, and you can always claim or refund."),
    node("li", "The recovery key is stored unencrypted in this browser. Save its 12 words; private windows and Tor Browser forget it on restart."),
    node("li", "Open source (MIT), provided as is, without warranty."));
  privacy.append(node("summary", "Privacy & terms"), privacyList);
  const limits = node("details");
  limits.append(node("summary", "Fee & timeout limits"));
  limits.append(node("p", "These are caps, not charges: the swap stops before funding if the " +
    "provider's signed terms exceed any of them.", "swap-limits-hint"));
  const successFee = field(limits, "swap-success-fee", "Maximum provider fee (sat)", "2000");
  const fundingFee = field(limits, "swap-funding-fee", "Maximum funding fee (sat)", "5000");
  const claimFee = field(limits, "swap-claim-fee", "Maximum claim fee (sat)", "5000");
  const refundFee = field(limits, "swap-refund-fee", "Maximum refund fee (sat)", "5000");
  const delay = field(limits, "swap-delay", "Maximum refund delay (blocks)", "288",
    "If the provider never pays, your refund unlocks within this many blocks (288 is about two days).");
  limits.append(node("p", "Lightning → Bitcoin", "swap-reverse-limits"));
  const minReserve = field(limits, "swap-min-claim-reserve", "Minimum claim fee reserve (sat)", "0",
    "Your claim pays exactly this on-chain reserve. Continue always asks for at least the next-block fee from your chain API; set a higher floor here if you want one.");
  const minRefundDelay = field(limits, "swap-min-refund-delay", "Minimum time before provider refund (blocks)", "72");
  const maxHold = field(limits, "swap-max-hold", "Maximum Lightning hold (blocks)", "432",
    "How long your Lightning payment may stay pending (432 is about three days).");
  limits.append(node("p", "Stablecoin → Lightning", "swap-erc20-limits"));
  const tokenFee = field(limits, "swap-token-fee", "Maximum provider fee (stablecoin units)", "5",
    "The provider's fee is quoted in the stablecoin on top of the invoice amount at its signed rate.");
  const evmTimelock = field(limits, "swap-evm-timelock", "Maximum lock time (EVM blocks)", "50000",
    "If the provider never pays, your refund unlocks within this many EVM blocks of the quote.");
  const evmClaimWindow = field(limits, "swap-evm-claim-window", "Minimum receive claim window (EVM blocks)", "600",
    "Lightning to stablecoin only. Claims also require at least ten minutes before the provider's refund block.");
  settings.append(limits);
  const notice = node("p", "", "swap-release-notice");
  notice.setAttribute("role", "note");
  const start = node("button", "Swap", "swap-start");
  start.type = "submit";
  start.className = "primary";
  form.append(keyRecommendation, setup, notice, start);
  // Once a swap starts, the form gives way to this tracking view; its link addresses the swap record.
  const tracking = node("div", "", "swap-tracking");
  tracking.hidden = true;
  const trackingTitle = node("h2", "Your swap");
  const another = node("a", "Start another swap", "swap-another");
  another.href = "./swap.html";
  const linkBox = node("div", "", "swap-link");
  linkBox.hidden = true;
  const linkAnchor = node("a", "Swap link", "swap-link-anchor");
  const copyLink = node("button", "Copy swap link", "swap-link-copy");
  copyLink.type = "button";
  linkBox.append(node("p", "This link holds your encrypted swap record; keep it with your recovery key."), linkAnchor, copyLink);
  tracking.append(trackingTitle, another, linkBox);
  const panel = node("div", "", "swap-panel");
  panel.setAttribute("aria-live", "polite");
  const progress = node("section", "", "swap-progress");
  const status = node("p", "Ready when you are", "swap-status");
  status.setAttribute("role", "status");
  const steps = node("ol", "", "swap-steps");
  for (const label of ["Connect", "Review", "Fund", "Paid"]) steps.append(node("li", label));
  progress.append(status, steps);
  const diagnostics = node("details", "", "swap-diagnostics");
  diagnostics.append(node("summary", "Technical activity"));
  const log = node("pre", "", "swap-log");
  diagnostics.append(log);
  card.append(cardHead, form, tracking, progress, panel, privacy, diagnostics);
  const footer = node("footer", "Provider-neutral · No account · Locally verified");
  root.replaceChildren(header, intro, card, footer, settings, providers);
  const setStatus = (text: string, step: number, state = "working"): void => {
    status.textContent = text;
    progress.dataset.state = state;
    for (const [index, item] of [...steps.children].entries()) {
      item.className = index < step ? "done" : index === step ? "current" : "";
    }
  };
  const report = (line: string): void => {
    log.textContent += `${line}\n`;
    if (line.startsWith("relay connected")) setStatus("Finding your provider", 0);
    else if (line.startsWith("provider found")) setStatus("Requesting verified terms", 1);
    else if (line.startsWith("terms:")) setStatus("Review your swap and save recovery", 1);
    else if (line.startsWith("recovery file saved")) setStatus("Ready to fund from your wallet", 2);
    else if (line.startsWith("funded recovery")) setStatus("Save your funded recovery backup", 2);
    else if (line.includes("broadcast; waiting")) setStatus("Waiting for the Lightning payment", 3);
    else if (line.startsWith("refused:") || line.startsWith("stopped:")) setStatus(line.replace(/^[^:]+: /, ""), -1, "error");
  };
  let busy = false;
  const showTracking = (title: string): void => {
    intro.hidden = form.hidden = true;
    tracking.hidden = false;
    trackingTitle.textContent = title;
  };
  let linkPublished = false;
  const publishLink = (file: Uint8Array, name: NetworkName): void => {
    const target = location.pathname + location.search + swapLinkFragment({ file, network: name });
    if (linkPublished) history.replaceState(null, "", target);
    else { history.pushState(null, "", target); linkPublished = true; }
    linkAnchor.href = location.href;
    linkBox.hidden = false;
  };
  copyLink.onclick = () => {
    void navigator.clipboard.writeText(location.href).then(() => { copyLink.textContent = "Copied"; }, () => { copyLink.textContent = "Copy failed; use the link"; });
  };
  const walletPromise = BrowserRecoveryWallet.open();
  const recovery = recoveryPanel({
    selectedNetwork: () => ({ name: network.value, identity: NETWORKS[network.value as NetworkName] }),
    browserIdentity: async () => {
      const key = await (await walletPromise).recoveryKey();
      key.file.fill(0); // This temporary key-file copy is not used for a download.
      return key.identity;
    },
    selectedChainApi: () => validateMempoolApi(chainApi.value.trim(), network.value as NetworkName),
    selectedBroadcastApi: () => validateMempoolApi(broadcastApi.value.trim(), network.value as NetworkName),
    selectedRelays: () => validateRelays(relay.value.trim(), network.value as NetworkName),
    selectedEvmRpc: () => validateMempoolApi(evmRpc.value.trim(), network.value as NetworkName),
    selectedEvmSponsor: selectedSponsor,
  });
  card.insertBefore(recovery.element, privacy);
  // Register failure handling immediately so blocked storage never becomes an unhandled rejection.
  void walletPromise.then(async (wallet) => {
    await walletBackupControls(walletActions, wallet, walletStatus);
    offerDownload(walletActions, (await wallet.recoveryKey()).file, "rillswap-recovery.age-key");
    walletStatus.textContent = wallet.newlyCreated
      ? "New browser recovery key created. Saving it is recommended, not required to swap."
      : "Using your existing browser recovery key.";
  }).catch((error: Error) => { walletStatus.textContent = error.message; });
  const updateDisclosure = (): void => {
    const chain = chainApi.value.trim(), send = broadcastApi.value.trim();
    chainDisclosure.textContent = `Mempool API ${chain} sees your IP and your swap's transactions` +
      (send === chain ? "; claims and refunds are sent there too." : `; claims and refunds are sent to ${send}.`);
    relayDisclosure.textContent = `Provider listings load from your Nostr relays when the page opens (${relay.value.trim().split(/\s+/).join(", ")}). Relays see your IP.`;
  };
  chainApi.oninput = () => { updateDisclosure(); recovery.clearFundingObservation(); };
  broadcastApi.oninput = () => { updateDisclosure(); recovery.clearFundingObservation(); };
  relay.oninput = updateDisclosure;
  updateDisclosure();
  const updateNetwork = (): void => {
    const route = routeFor(fromAsset.value, toAsset.value);
    badge.value = network.value;
    notice.hidden = true;
    heroTitle.textContent = route.title;
    heroTagline.textContent = route.tagline;
    pairNote.textContent = route.unavailable ?? "";
    pairNote.hidden = !route.unavailable;
    invoiceBox.hidden = route.profile !== "btc-to-ln/v1" && route.profile !== "erc20-to-ln/v1";
    overrides.hidden = route.profile !== "btc-to-ln/v1";
    prerequisites.textContent = route.profile === "btc-to-ln/v1"
      ? "This experimental flow needs a wallet that can sign a PSBT without broadcasting it, but creates your recovery key and refund address automatically."
      : route.profile === "erc20-to-ln/v1"
        ? `This flow needs an EVM wallet extension (MetaMask or similar) holding ${route.from.symbol} plus gas on the provider's chain. ` +
          "The wallet keeps the refund key; your browser recovery key encrypts the swap record."
        : route.profile === "ln-to-erc20/v1"
          ? (sponsorConfigured() ? "Pay from any Lightning wallet; the tokens arrive at the address you enter, with claim gas paid by the configured sponsor. Recovery is saved before the invoice is shown."
            : "Pay from any Lightning wallet. For direct receive, connect an EVM wallet with gas to claim the tokens. Recovery is saved before the invoice is shown.")
          : "Your browser recovery key is created automatically and covers every swap started here.";
    receiveBox.hidden = route.profile !== "ln-to-btc/v1" && route.profile !== "ln-to-erc20/v1";
    receiveAddress.hidden = route.profile === "ln-to-erc20/v1" && !sponsorConfigured();
    receiveBox.querySelector<HTMLLabelElement>('label[for="swap-receive-address"]')!.hidden = receiveAddress.hidden;
    receiveBox.querySelector<HTMLLabelElement>('label[for="swap-receive-address"]')!.textContent =
      route.profile === "ln-to-erc20/v1" ? `EVM address to receive ${route.to.symbol}` : "Bitcoin address to receive";
    receiveBox.querySelector<HTMLLabelElement>('label[for="swap-receive-amount"]')!.textContent = `Amount to receive (${route.profile === "ln-to-erc20/v1" ? route.to.symbol : "sat"})`;
    receiveAmount.inputMode = route.profile === "ln-to-erc20/v1" ? "decimal" : "numeric";
    start.disabled = route.unavailable !== null;
    start.textContent = route.unavailable ? "Pair unavailable" : "Swap";
    updateEstimate();
  };
  const changePair = (changed: HTMLSelectElement, other: HTMLSelectElement, previous: string): void => {
    // Picking the asset already on the other side swaps the two, like a flip.
    if (changed.value === other.value) other.value = previous;
    updateNetwork();
  };
  let lastFrom = fromAsset.value, lastTo = toAsset.value;
  fromAsset.onchange = () => { changePair(fromAsset, toAsset, lastFrom); lastFrom = fromAsset.value; lastTo = toAsset.value; };
  toAsset.onchange = () => { changePair(toAsset, fromAsset, lastTo); lastFrom = fromAsset.value; lastTo = toAsset.value; };
  flip.onclick = () => {
    [fromAsset.value, toAsset.value] = [toAsset.value, fromAsset.value];
    lastFrom = fromAsset.value; lastTo = toAsset.value;
    updateNetwork();
  };
  const applyNetwork = (): void => {
    relay.value = relaysForNetwork(network.value as NetworkName, __SWAP_DEFAULTS__).join("\n");
    chainApi.value = mempoolApiForNetwork(network.value as NetworkName, __SWAP_DEFAULTS__);
    broadcastApi.value = network.value === __SWAP_DEFAULTS__.network ? __SWAP_DEFAULTS__.broadcastApi :
      (network.value === "regtest" ? "http://127.0.0.1:8092/api" : chainApi.value);
    evmRpc.value = network.value === __SWAP_DEFAULTS__.network ? __SWAP_DEFAULTS__.evmRpc ?? "" : network.value === "regtest" ? "http://127.0.0.1:8545" : "";
    refund.value = tip.value = age.value = "";
    updateDisclosure();
    updateNetwork();
    recovery.clearFundingObservation();
    directoryEntries = []; directoryWarnings = []; directoryLoaded = false; renderDirectory(); providersStatus.textContent = "";
    loadDirectory();
  };
  network.onchange = applyNetwork;
  badge.onchange = () => {
    const deployment = __SWAP_DEFAULTS__.deployments?.[badge.value as NetworkName];
    if (deployment !== undefined && badge.value !== __SWAP_DEFAULTS__.network) {
      badge.value = network.value; // shown until the other page loads, and kept if leaving is canceled
      location.assign(deployment);
      return;
    }
    network.value = badge.value;
    applyNetwork();
  };
  updateNetwork();
  loadDirectory();
  // Offers expire (makers re-announce about every 30 minutes), so the directory drops expired entries
  // and reloads itself while the page is visible and no swap is running. A swap discovers afresh anyway.
  const refreshDirectory = (): void => {
    const live = unexpired(directoryEntries);
    if (live.length !== directoryEntries.length) {
      directoryEntries = live; renderDirectory(); updateEstimate();
      if (!directoryLoading) showDirectoryStatus();
    }
    if (document.visibilityState === "visible" && !busy && !directoryLoading &&
        Date.now() - directoryAttemptAt >= DIRECTORY_REFRESH_MS) loadDirectory();
  };
  setInterval(refreshDirectory, 60_000);
  document.addEventListener("visibilitychange", refreshDirectory);
  // A swap link reopens its encrypted record locally: inspection decrypts and parses, nothing connects.
  const savedRecoveries = node("details", "", "swap-saved-recoveries");
  savedRecoveries.append(node("summary", "Your swaps"));
  const savedList = node("div", "Loading local recovery checkpoints...", "swap-saved-recoveries-list");
  savedRecoveries.append(savedList); card.insertBefore(savedRecoveries, recovery.element);
  const refreshSavedRecoveries = async (): Promise<void> => {
    try {
      const wallet = await walletPromise, entries = await wallet.listFundedRecoveries();
      savedList.replaceChildren();
      for (const entry of entries) {
        const row = node("div"); savedList.append(row);
        if ("error" in entry) { row.append(node("p", entry.error)); continue; }
        row.append(node("p", `${entry.network}: ${entry.id.slice(-16)}`));
        for (const label of ["Open saved swap", "Prepare download"]) {
          const button = node("button", label); button.type = "button";
          button.onclick = () => {
            if (busy) return;
            button.disabled = true;
            void wallet.readFundedRecovery(entry.id).then((snapshot) => {
              if (busy) return;
              if (label === "Prepare download") {
                offerDownload(row, snapshot.ciphertext, `rillswap-funded-${entry.id.slice(-16)}.age`);
              } else {
                if (network.value !== snapshot.network) { network.value = snapshot.network; applyNetwork(); }
                history.replaceState(null, "", location.pathname + location.search);
                linkPublished = false; linkAnchor.removeAttribute("href"); linkBox.hidden = true;
                showTracking("Saved funded swap");
                setStatus("Saved funded recovery opened locally", -1, "ready");
                recovery.load(snapshot.ciphertext, "saved-funded-swap.age");
              }
            }).catch((error: Error) => { row.append(node("p", error.message)); })
              .finally(() => { button.disabled = false; });
          };
          row.append(button);
        }
      }
      const journal = await BrowserReverseJournal.open();
      try {
        const reverse = await journal.list();
        if (!entries.length && !reverse.length) savedList.append(node("p", "No swaps saved in this browser."));
        for (const record of reverse) {
          const name = (record.context.networkIdentity as { name: NetworkName }).name;
          const row = node("div"); row.dataset.reverseSession = record.context.sessionId;
          row.append(node("p", `${name}: Lightning to Bitcoin · ${record.context.request.nominal_payout_sat} sat · ${record.stage}`));
          const open = node("button", "Resume"); open.type = "button";
          row.append(open); savedList.append(row);
          open.onclick = () => {
            if (busy) return;
            busy = true; open.disabled = settingsButton.disabled = providersButton.disabled = badge.disabled = true;
            void (async () => {
              if (network.value !== name) { network.value = name; applyNetwork(); }
              const api = validateMempoolApi(chainApi.value.trim(), name), broadcast = validateMempoolApi(broadcastApi.value.trim(), name);
              const relaySelection = relay.value.trim(), urls = validateRelays(relaySelection, name);
              const current = (): void => {
                if (network.value !== name || chainApi.value.trim() !== api || broadcastApi.value.trim() !== broadcast || relay.value.trim() !== relaySelection) throw new Error("Swap settings changed");
              };
              const key = await wallet.recoveryKey(); key.file.fill(0); current();
              const plaintext = await decryptRecoveryContainer(hexToBytes(record.snapshots.at(-1)!.ciphertextHex), key.identity);
              let execution;
              try { current(); execution = await resumeBrowserReverseExecution(plaintext, key.identity, { ...NETWORKS[name], name }, urls, current); }
              finally { plaintext.fill(0); }
              current(); showTracking("Lightning to Bitcoin swap");
              steps.replaceChildren(...["Review", "Pay", "Locking", "Claim", "Done"].map((label) => node("li", label)));
              mountResumedReverseExecution(panel, execution, { network: { ...NETWORKS[name], name }, chainApi: api, broadcastApi: broadcast,
                assertCurrent: current, status: (message, step) => setStatus(message, step),
                download: offerDownload, saved: (file) => { publishLink(file, name); void refreshSavedRecoveries(); } });
            })().catch(() => {
              row.append(node("p", "Could not resume this saved swap. Keep any backups; no payment was retried."));
              busy = false; open.disabled = settingsButton.disabled = providersButton.disabled = badge.disabled = false;
            });
          };
        }
      } finally { journal.close(); }
    } catch (error) { savedList.textContent = `Could not read saved recoveries: ${(error as Error).message}`; }
  };
  void refreshSavedRecoveries();
  const link = parseSwapLink(location.hash);
  if (link) {
    if (link.network in NETWORKS && network.value !== link.network) { network.value = link.network; applyNetwork(); }
    linkPublished = true;
    linkAnchor.href = location.href;
    linkBox.hidden = false;
    showTracking("Swap record");
    setStatus("Swap record opened from its link", -1, "ready");
    recovery.load(link.file, "swap-link.age");
  }
  // Following another swap link while this page is open is a fragment-only navigation; reload so
  // the new record is opened, unless a swap is in progress in this tab.
  window.addEventListener("hashchange", () => { if (!busy && parseSwapLink(location.hash)) location.reload(); });
  // Handoffs and shared links use a fragment, never a server-visible query. Prefilling is
  // inert: no quote, connection, or payment starts automatically, and the fragment is dropped.
  const handoff = new URLSearchParams(location.hash.slice(1));
  if (!link && [...handoff.keys()].length > 0) {
    const text = (key: string, limit: number): string => { const value = handoff.get(key) ?? ""; return value.length <= limit ? value : ""; };
    const prefill = { invoice: text("invoice", 4096), address: text("address", 128), amount: text("amount", 16), from: text("from", 8) };
    if (prefill.invoice) {
      fromAsset.value = prefill.from in STABLECOIN_SYMBOL ? prefill.from : "btc"; toAsset.value = "ln"; invoice.value = prefill.invoice;
    }
    else if (prefill.address || prefill.amount) { fromAsset.value = "ln"; toAsset.value = "btc"; }
    if (prefill.address) receiveAddress.value = prefill.address;
    if (/^[0-9]{1,16}$/.test(prefill.amount)) receiveAmount.value = prefill.amount;
    lastFrom = fromAsset.value; lastTo = toAsset.value;
    history.replaceState(null, "", location.pathname + location.search);
    updateNetwork();
  }

  /** Stablecoin to Lightning: one asset per round, the wallet connected before any firm quote names its address. */
  const erc20Quote = (name: NetworkName, symbol: "USDC" | "USDT"): void => {
    let urls: readonly string[];
    let rpcUrl: string;
    let limits: Erc20SwapRequest["limits"];
    const pinned = identity.value.trim();
    try {
      urls = validateRelays(relay.value.trim(), name);
      if (!evmRpc.value.trim()) throw new Error("Set the EVM RPC endpoint in Settings for stablecoin swaps");
      rpcUrl = validateMempoolApi(evmRpc.value.trim(), name);
      if (pinned && !/^[0-9a-f]{64}$/.test(pinned)) {
        throw new Error("Provider identity must be 64 lowercase hex characters, or leave it empty for automatic selection");
      }
      invoiceBinding(invoice.value.trim(), name);
      limits = { maxSuccessFeeTokenBase: 0n, maxTimelockDelayBlocks: Number(positive(evmTimelock, "maximum lock time")) };
      parseTokenAmount(tokenFee.value, 18, "Maximum provider fee"); // decimals are only known with the asset
    } catch (error) {
      report(`refused: ${(error as Error).message}`);
      return;
    }
    const controls = [...form.elements, ...settings.querySelectorAll("input, textarea, select, button")];
    busy = true;
    for (const control of controls) (control as HTMLInputElement).disabled = true;
    settingsButton.disabled = providersButton.disabled = badge.disabled = true;
    const guard = (unload: BeforeUnloadEvent): void => unload.preventDefault();
    window.addEventListener("beforeunload", guard);
    const cancellation = new AbortController();
    let executing = false;
    let arrivals: readonly LocatedQuote<PreparedErc20Swap>[] = [];
    const done = node("button", "Edit swap", "swap-edit");
    done.type = "button";
    const restore = (): void => {
      busy = false;
      for (const control of controls) (control as HTMLInputElement).disabled = false;
      settingsButton.disabled = providersButton.disabled = badge.disabled = false;
      window.removeEventListener("beforeunload", guard);
      updateNetwork();
    };
    done.onclick = () => {
      if (executing) return;
      cancellation.abort();
      for (const quote of arrivals) quote.dispose();
      panel.replaceChildren();
      setStatus("Ready for a new quote", -1, "ready");
      restore();
    };
    const assertCurrent = (): void => { cancellation.signal.throwIfAborted(); };
    panel.replaceChildren(node("p", "Checking signed provider announcements across your relays..."), done);
    setStatus("Finding available providers", 0);
    void (async () => {
      try {
        const binding = invoiceBinding(invoice.value.trim(), name);
        const principal = BigInt(binding.amount_msat) / 1000n;
        const trusted = trustedEvmAsset(symbol, name, NETWORKS[name].deployment_namespace, __SWAP_DEFAULTS__);
        const directory = await discoverMarketplace(urls, NETWORKS[name], pinned || undefined, cancellation.signal, "erc20-to-ln/v1");
        assertCurrent();
        for (const warning of directory.warnings) report(warning);
        const mode = sortMode();
        const eligible = eligibleProviders(directory.providers, principal, mode);
        if (eligible.length === 0) throw new Error(ineligibilityReason(providerLimits(directory.providers), principal));
        const selection = selectEvmAsset(eligible, trusted);
        if (selection === null) throw new Error(`No announced provider serves ${symbol} for this network.`);
        const { asset } = selection;
        report(`${asset.token_symbol} on ${asset.name} (chain ${asset.chain_id}) served by ${selection.providers.length} provider(s)`);
        const rpc = new EvmRpc(rpcUrl);
        setStatus("Connect your EVM wallet", 0);
        const { wallet, account } = await connectEvmWallet(rpc, asset);
        assertCurrent();
        report(`wallet ${account} connected on chain ${asset.chain_id}`);
        const evmTip = await rpc.blockNumber();
        assertCurrent();
        const request: Omit<Erc20SwapRequest, "identity"> = {
          network: NETWORKS[name], invoice: invoice.value.trim(), asset, clientEvmAddress: account, evmTip, ageRecipient: "",
          limits: { ...limits, maxSuccessFeeTokenBase: parseTokenAmount(tokenFee.value, asset.token_decimals, "Maximum provider fee") },
        };
        const recoveryWallet = await walletPromise; assertCurrent();
        const info = await recoveryWallet.info(); assertCurrent();
        setStatus("Comparing verified provider quotes", 1);
        report(`Requesting up to ${MAX_QUOTE_PROVIDERS} eligible offers from ${selection.providers.length} announced providers`);
        const result = await quoteErc20Providers(selection.providers, { ...request, ageRecipient: info.recipient }, cancellation.signal, mode);
        arrivals = result.quotes;
        if (cancellation.signal.aborted) return;
        if (arrivals.length === 0) throw new Error(`No provider returned acceptable terms (${result.reasons.join("; ")}). Nothing was accepted or locked.`);
        let selected = arrivals[0]!;
        const review = node("div", "", "swap-quote-review");
        const quoteSummary = node("div", "", "swap-quote-summary");
        const priceClaim = node("p", "", "swap-quote-selection");
        const showQuote = (): void => {
          const quote = selected.prepared.quote;
          priceClaim.textContent = quoteSelectionLabel(selected === arrivals[0], arrivals.length, mode);
          quoteSummary.replaceChildren(node("h2", tokenLabel(quote.lockAmountTokenBase, asset)),
            node("p", `Pays your ${principal.toLocaleString()} sat invoice at ${tokenLabel(quote.rateTokenBasePerBtc, asset)} per BTC. ` +
              `Provider fee: ${tokenLabel(quote.successFeeTokenBase, asset)}. Your wallet's gas is extra.`),
            node("small", `The provider pays after ${quote.fundingConfirmations} EVM block confirmation${quote.fundingConfirmations === 1 ? "" : "s"} of your lock. ` +
              `Refundable from EVM block ${quote.timelockBlock} if the provider never pays. Offer expires ${new Date(quote.expiresAt * 1000).toLocaleTimeString()}.`));
        };
        showQuote();
        review.append(quoteSummary, priceClaim, node("small", "Signatures authenticate offers, not provider reputation."));
        if (directory.warnings.length || result.failures || selection.providers.length > MAX_QUOTE_PROVIDERS) {
          review.append(node("small", "Some relays or providers did not return complete results. This is not a market-wide best-price guarantee."));
        }
        const offers = node("details");
        offers.append(node("summary", "Provider details & manual selection"));
        const tags = offerTags(arrivals, erc20Rank);
        for (const [index, quote] of arrivals.entries()) {
          const label = node("label"), option = node("input");
          option.type = "radio"; option.name = "verified-provider"; option.checked = index === 0;
          option.onchange = () => { selected = quote; showQuote(); };
          label.append(option, node("span", `${tokenLabel(quote.prepared.quote.lockAmountTokenBase, asset)} · ${quote.prepared.quote.providerIdentity.slice(0, 12)}…`),
            ...tags(quote), node("small", `Transport: ${quote.relayUrl}; identity: ${quote.prepared.quote.providerIdentity}`));
          offers.append(label);
        }
        const accept = node("button", "Swap with this quote", "swap-quote-accept");
        accept.type = "button";
        review.append(offers, node("p", "By continuing you accept the provider's signed terms. " +
          "Your wallet will ask you to approve and lock the tokens; it keeps the refund key.", "swap-quote-consent"), accept, done);
        panel.replaceChildren(review);
        setStatus("Quote ready. Review before continuing", 1);
        const accepted = await new Promise<LocatedQuote<PreparedErc20Swap> | null>((resolve) => {
          accept.onclick = () => { for (const option of offers.querySelectorAll("input")) option.disabled = true; accept.disabled = true; resolve(selected); };
          cancellation.signal.addEventListener("abort", () => resolve(null), { once: true });
        });
        if (!accepted || cancellation.signal.aborted) return;
        // The browser-stored recovery key is the approval; only an identity change blocks acceptance.
        if ((await recoveryWallet.info()).fingerprint !== info.fingerprint) throw new Error("Recovery identity changed. Request a fresh quote.");
        if (Date.now() / 1000 >= accepted.prepared.quote.expiresAt) throw new Error("Quote expired. Request a fresh quote.");
        executing = true;
        for (const quote of arrivals) if (quote !== accepted) quote.dispose();
        arrivals = [accepted];
        showTracking(`${asset.token_symbol} to Lightning swap`);
        await mountErc20Execution(panel, {
          prepared: accepted.prepared, asset, rpc, wallet, account, ageRecipient: info.recipient, signal: cancellation.signal,
          status: (message, step, state) => setStatus(message, step, state), report,
          download: (root, file, fileName) => { offerDownload(root, file, fileName); publishLink(file, name); },
        });
      } catch (error) {
        if (!cancellation.signal.aborted) {
          panel.replaceChildren(node("p", (error as Error).message, "swap-error"), done);
          report(`stopped: ${(error as Error).message}`);
        }
      } finally {
        if (!executing) { if (!cancellation.signal.aborted) restore(); }
        else { window.removeEventListener("beforeunload", guard); }
      }
    })();
  };

  /** Token amounts can be priced without a destination or a connected Lightning node. */
  const lnErc20Quote = (name: NetworkName, symbol: "USDC" | "USDT"): void => {
    let urls: readonly string[], rpcUrl: string, api: string, sponsor: EvmSponsorDefaults | null;
    const pinned = identity.value.trim(), amount = receiveAmount.value.trim(), destination = receiveAddress.value.trim().toLowerCase();
    try {
      urls = validateRelays(relay.value.trim(), name);
      rpcUrl = validateMempoolApi(evmRpc.value.trim(), name);
      api = validateMempoolApi(chainApi.value.trim(), name);
      sponsor = selectedSponsor();
      if (sponsor && !/^0x[0-9a-f]{40}$/.test(destination)) throw new Error(`Enter the 0x address that should receive ${symbol}`);
      if (pinned && !/^[0-9a-f]{64}$/.test(pinned)) throw new Error("Provider identity must be 64 lowercase hex characters");
      if (parseTokenAmount(amount, 18, "Amount to receive") <= 0n) throw new Error("Amount to receive must be positive");
    } catch (error) { report(`refused: ${(error as Error).message}`); return; }
    const controls = [...form.elements, ...settings.querySelectorAll("input, textarea, select, button")];
    busy = true; for (const control of controls) (control as HTMLInputElement).disabled = true;
    settingsButton.disabled = providersButton.disabled = badge.disabled = true;
    const cancellation = new AbortController(), guard = (event: BeforeUnloadEvent): void => event.preventDefault();
    window.addEventListener("beforeunload", guard);
    let executing = false, arrivals: readonly LocatedQuote<PreparedLnErc20Quote>[] = [];
    const current = (): void => cancellation.signal.throwIfAborted();
    const restore = (): void => {
      busy = false; for (const control of controls) (control as HTMLInputElement).disabled = false;
      settingsButton.disabled = providersButton.disabled = badge.disabled = false; window.removeEventListener("beforeunload", guard); updateNetwork();
    };
    const edit = node("button", "Edit swap", "swap-edit"); edit.type = "button";
    edit.onclick = () => {
      if (executing) return; cancellation.abort(); for (const quote of arrivals) quote.dispose();
      panel.replaceChildren(); setStatus("Ready for a new quote", -1, "ready"); restore();
    };
    panel.replaceChildren(node("p", "Finding stablecoin providers..."), edit); setStatus("Finding available providers", 0);
    void (async () => {
      try {
        const trusted = trustedEvmAsset(symbol, name, NETWORKS[name].deployment_namespace, __SWAP_DEFAULTS__);
        const directory = await discoverMarketplace(urls, NETWORKS[name], pinned || undefined, cancellation.signal, "ln-to-erc20/v1"); current();
        const selection = selectEvmAsset(directory.providers, trusted);
        if (!selection) throw new Error(`No announced provider serves ${symbol} for this network`);
        for (const warning of directory.warnings) report(warning);
        const asset = selection.asset, payoutTokenBase = parseTokenAmount(amount, asset.token_decimals, "Amount to receive");
        const mode = sortMode();
        const result = await quoteLnErc20Providers(selection.providers, { network: NETWORKS[name], asset, payoutTokenBase, limits: {
          maxSuccessFeeSat: positive(successFee, "provider fee"), minTimelockDelayBlocks: Number(positive(evmClaimWindow, "minimum EVM claim window")),
          maxIncomingHtlcDelayBlocks: Number(positive(maxHold, "maximum Lightning hold")),
        } }, cancellation.signal, mode);
        arrivals = result.quotes; current();
        if (!arrivals.length) throw new Error(`No acceptable estimate (${result.reasons.join("; ")}). Nothing was accepted or paid.`);
        let selected = arrivals[0]!;
        const review = node("div", "", "swap-quote-review"), summary = node("div", "", "swap-quote-summary");
        const priceClaim = node("p", "", "swap-quote-selection");
        const show = (): void => {
          const offer = selected.prepared.quote.offer;
          priceClaim.textContent = quoteSelectionLabel(selected === arrivals[0], arrivals.length, mode);
          summary.replaceChildren(node("h2", `${BigInt(offer.economics.hold_invoice_sat).toLocaleString()} sat`),
            node("p", `Pay over Lightning to receive ${tokenLabel(payoutTokenBase, asset)} on ${asset.name}. ` +
              `Provider fee: ${offer.economics.success_fee_sat} sat. Your EVM wallet pays claim gas.`),
            node("small", `Claim after ${offer.funding_confirmations} EVM block confirmation${offer.funding_confirmations === 1 ? "" : "s"} of the provider's lock. ` +
              `Claim window: ${offer.timelock_delay_blocks} EVM blocks. Lightning hold budget: ${offer.incoming_htlc_expiry_delta_blocks} Bitcoin blocks.`));
        };
        show(); review.append(summary, priceClaim);
        const choices = node("details"); choices.append(node("summary", "Provider details & manual selection"));
        const tags = offerTags(arrivals, lnErc20Rank);
        for (const [index, quote] of arrivals.entries()) {
          const label = node("label"), radio = node("input"); radio.type = "radio"; radio.name = "verified-provider"; radio.checked = index === 0;
          radio.onchange = () => { selected = quote; show(); };
          label.append(radio, node("span", `${quote.prepared.quote.offer.economics.hold_invoice_sat} sat · ${quote.prepared.quote.providerIdentity.slice(0, 12)}`),
            ...tags(quote), node("small", `Identity: ${quote.prepared.quote.providerIdentity}; transport: ${quote.relayUrl}`)); choices.append(label);
        }
        const accept = node("button", "Swap with this quote", "swap-quote-accept"); accept.type = "button";
        review.append(choices, node("p", "By continuing you accept the provider's signed terms. " +
          (sponsor ? `The tokens are sent to ${destination}; the gas sponsor pays the claim. ` : "Connect an EVM wallet to receive the tokens; ") +
          "Pay the invoice from any Lightning wallet. The firm price cannot exceed this estimate."), accept, edit);
        if (result.failures || directory.warnings.length || selection.providers.length > MAX_QUOTE_PROVIDERS) review.append(node("small", "Incomplete provider results; this is not a market-wide best-price guarantee."));
        panel.replaceChildren(review); setStatus("Quote ready. Review before continuing", 1);
        const chosen = await new Promise<LocatedQuote<PreparedLnErc20Quote> | null>((resolve) => {
          accept.onclick = () => { accept.disabled = true; for (const input of choices.querySelectorAll("input")) input.disabled = true; resolve(selected); };
          cancellation.signal.addEventListener("abort", () => resolve(null), { once: true });
        });
        if (!chosen) return; current(); executing = true;
        for (const quote of arrivals) if (quote !== chosen) quote.dispose();
        const rpc = new EvmRpc(rpcUrl);
        let claimer: LnErc20Claimer;
        if (sponsor) {
          if (await rpc.chainId() !== asset.chain_id) throw new Error(`The configured EVM RPC does not serve ${asset.name} (chain ${asset.chain_id}). Change it in Settings.`);
          const secret = newStagingSecret();
          claimer = { kind: "sponsored", sponsor: new GasSponsor({ ...sponsor, chainId: asset.chain_id }), secret, destination };
        } else {
          const { wallet, account } = await connectEvmWallet(rpc, asset); claimer = { kind: "wallet", wallet, account };
        }
        current(); await rpc.verifyHtlc(asset.htlc_contract); current();
        const recoveryWallet = await walletPromise, info = await recoveryWallet.info(); current();
        const journal = new EvmClaimJournal();
        const btcTip = await readChainTip(api, { name, genesis_hash: NETWORKS[name].genesis_hash as string }, { signal: cancellation.signal }); current();
        const prepared = await chosen.prepared.prepareExecution({
          clientEvmAddress: claimer.kind === "wallet" ? claimer.account : stagingAddress(claimer.secret),
          ...(claimer.kind === "sponsored" ? { claimKey: claimer.secret, claimDestination: claimer.destination } : {}),
          btcTip: btcTip.height, evmTip: await rpc.blockNumber(), ageRecipient: info.recipient, saveSecrets: (file, sessionId) => journal.create(`secrets:${sessionId}`, file) });
        if ((await recoveryWallet.info()).fingerprint !== info.fingerprint) { prepared.dispose(); throw new Error("Recovery identity changed; request fresh terms"); }
        showTracking(`Lightning to ${asset.token_symbol} swap`);
        await mountLnErc20Execution(panel, { prepared, rpc, claimer, journal, status: setStatus, report, signal: cancellation.signal,
          download: (root, file, fileName) => { offerDownload(root, file, fileName); publishLink(file, name); } });
      } catch (error) {
        if (!cancellation.signal.aborted) { panel.append(node("p", (error as Error).message, "swap-error"), edit); report(`stopped: ${(error as Error).message}`); }
      } finally {
        for (const quote of arrivals) quote.dispose();
        if (!executing && !cancellation.signal.aborted) restore();
        else window.removeEventListener("beforeunload", guard);
      }
    })();
  };

  /** Indicative comparison first; only the selected provider can enter durable execution. */
  const reverseQuote = (name: NetworkName): void => {
    let request: Omit<ReverseSwapRequest, "identity">;
    let urls: readonly string[];
    const pinned = identity.value.trim();
    try {
      urls = validateRelays(relay.value.trim(), name);
      if (pinned && !/^[0-9a-f]{64}$/.test(pinned)) {
        throw new Error("Provider identity must be 64 lowercase hex characters, or leave it empty for automatic selection");
      }
      // The address is only needed, checked and sent when you continue with the selected provider.
      if (receiveAddress.value.trim()) addressScript(receiveAddress.value.trim(), name);
      request = {
        network: NETWORKS[name],
        payoutSat: positive(receiveAmount, "Amount to receive"),
        limits: {
          maxSuccessFeeSat: positive(successFee, "provider fee"),
          minClaimFeeReserveSat: positive(minReserve, "claim fee reserve"),
          maxClaimFeeSat: positive(claimFee, "claim fee"),
          minRefundDelayBlocks: Number(positive(minRefundDelay, "refund delay")),
          maxIncomingHtlcDelayBlocks: Number(positive(maxHold, "maximum hold")),
        },
      };
      if (request.payoutSat === 0n) throw new Error("Amount to receive must be positive");
    } catch (error) {
      report(`refused: ${(error as Error).message}`);
      return;
    }
    // The payout address stays editable until continuation; everything else is frozen with the estimate.
    const controls = [...form.elements, ...settings.querySelectorAll("input, textarea, select, button")].filter((control) => control !== receiveAddress);
    busy = true;
    for (const control of controls) (control as HTMLInputElement).disabled = true;
    settingsButton.disabled = providersButton.disabled = badge.disabled = true;
    const cancellation = new AbortController();
    const selection = (): string => JSON.stringify([network.value, fromAsset.value, toAsset.value, receiveAmount.value, relay.value, identity.value,
      chainApi.value, broadcastApi.value, successFee.value, minReserve.value, claimFee.value, minRefundDelay.value, maxHold.value]);
    const captured = selection();
    let destination = "";
    const assertCurrent = (): void => {
      cancellation.signal.throwIfAborted();
      if (captured !== selection() || (destination && receiveAddress.value.trim() !== destination)) throw new Error("Swap selection changed");
    };
    let executing = false;
    let arrivals: readonly LocatedQuote<PreparedReverseQuote>[] = [];
    const done = node("button", "Edit swap", "swap-edit");
    done.type = "button";
    const restore = (): void => {
      busy = false;
      for (const control of controls) (control as HTMLInputElement).disabled = false;
      settingsButton.disabled = providersButton.disabled = badge.disabled = false;
      receiveAddress.disabled = false;
      updateNetwork();
    };
    done.onclick = () => {
      if (executing) return;
      cancellation.abort();
      for (const quote of arrivals) quote.dispose();
      panel.replaceChildren();
      setStatus("Ready for a new quote", -1, "ready");
      restore();
    };
    panel.replaceChildren(node("p", "Checking signed provider announcements across your relays..."), done);
    setStatus("Finding available providers", 0);
    void (async () => {
      try {
        const directory = await discoverMarketplace(urls, request.network, pinned || undefined, cancellation.signal, "ln-to-btc/v1");
        for (const warning of directory.warnings) report(warning);
        const mode = sortMode();
        const eligible = eligibleProviders(directory.providers, request.payoutSat, mode);
        if (eligible.length === 0) throw new Error(ineligibilityReason(providerLimits(directory.providers), request.payoutSat));
        setStatus("Comparing provider estimates", 1);
        report(`Requesting up to ${MAX_QUOTE_PROVIDERS} eligible offers from ${eligible.length} announced providers`);
        const result = await quoteReverseProviders(eligible, request, cancellation.signal, mode);
        arrivals = result.quotes;
        if (cancellation.signal.aborted) return;
        if (arrivals.length === 0) throw new Error(`No provider returned acceptable terms (${result.reasons.join("; ")}). Nothing was paid.`);
        let selected = arrivals[0]!;
        const quote = selected.prepared.quote;
        const review = node("div", "", "swap-quote-review");
        review.append(node("p", "Estimated price", "swap-quote-kind"), node("h2", `${quote.holdInvoiceSat.toLocaleString()} sat`),
          node("p", `You pay this over Lightning (plus your wallet's routing fee) and receive ${quote.payoutSat.toLocaleString()} sat on-chain.`),
          node("small", `Provider fee: ${quote.successFeeSat.toLocaleString()} sat. Claim fee reserve: ${quote.claimFeeReserveSat.toLocaleString()} sat. ` +
            `${fundingWaitText("ln-to-btc/v1", quote.fundingConfirmations)} ` +
            `If the swap fails, your Lightning payment may stay pending for up to about ${quote.incomingHtlcExpiryDeltaBlocks} blocks. ` +
            `Estimate expires ${new Date(quote.expiresAt * 1000).toLocaleTimeString()}.`),
          node("p", `${mode === "time" ? "Fastest" : "Lowest"} estimate among ${arrivals.length} responding provider${arrivals.length === 1 ? "" : "s"}` +
            `${mode === "time" ? " (fewest funding confirmations, then lowest price)" : ""}.`, "swap-quote-selection"),
          node("p", "Nothing was paid and no address or payment hash was shared. Continue checks the selected provider's final signed terms before any payment.", "swap-reverse-pending"));
        if (directory.warnings.length || result.failures || eligible.length > MAX_QUOTE_PROVIDERS) {
          review.append(node("small", "Some relays or providers did not return complete results. This is not a market-wide best-price guarantee."));
        }
        const providers = node("details"); providers.append(node("summary", "Provider details & manual selection"));
        const chosen = node("p", `Selected provider: ${selected.prepared.quote.providerIdentity}`, "swap-reverse-selected");
        const tags = offerTags(arrivals, reverseRank);
        for (const [index, located] of arrivals.entries()) {
          const label = node("label"), option = node("input"); option.type = "radio"; option.name = "reverse-provider"; option.checked = index === 0;
          option.onchange = () => {
            selected = located;
            chosen.textContent = `Selected provider: ${located.prepared.quote.providerIdentity}. Estimated hold: ${located.prepared.quote.holdInvoiceSat} sat. ` +
              fundingWaitText("ln-to-btc/v1", located.prepared.quote.fundingConfirmations);
          };
          label.append(option, node("span", `${located.prepared.quote.holdInvoiceSat} sat · ${located.prepared.quote.providerIdentity.slice(0, 12)}…`), ...tags(located));
          providers.append(label);
        }
        const wallet = await walletPromise; assertCurrent(); const info = await wallet.info(); assertCurrent();
        const continueSwap = node("button", "Continue with selected provider", "swap-reverse-continue"); continueSwap.type = "button";
        const refusal = node("p", "", "swap-reverse-refusal");
        /** True once continuation started; false when the address or estimate blocks it (the review explains). */
        const continueWith = (): boolean => {
          if (executing) return false;
          let destinationScript: string;
          try {
            if (!receiveAddress.value.trim()) throw new Error("Enter the Bitcoin address that should receive the payout");
            destinationScript = addressScript(receiveAddress.value.trim(), name);
            if (Date.now() / 1000 >= selected.prepared.quote.expiresAt) throw new Error("Estimate expired. Request a fresh quote.");
          } catch (error) { refusal.textContent = (error as Error).message; return false; }
          refusal.textContent = "";
          destination = receiveAddress.value.trim();
          continueSwap.disabled = receiveAddress.disabled = true;
          void (async () => {
            // The browser-stored recovery key is the approval; only an identity change blocks continuation.
            const current = await wallet.info(); assertCurrent();
            if (current.fingerprint !== info.fingerprint) throw new Error("Recovery identity changed");
            executing = true; done.disabled = true;
            for (const quote of arrivals) if (quote !== selected) quote.dispose();
            arrivals = [selected];
            showTracking("Lightning to Bitcoin swap");
            steps.replaceChildren(...["Review", "Pay", "Locking", "Claim", "Done"].map((label) => node("li", label)));
            await mountReverseExecution(panel, { prepared: selected.prepared, network: { ...NETWORKS[name], name }, destinationScript,
              ageRecipient: info.recipient, chainApi: chainApi.value.trim(), broadcastApi: broadcastApi.value.trim(), assertCurrent,
              nodeApi: __SWAP_DEFAULTS__.network === name ? __SWAP_DEFAULTS__.nodeApi ?? "" : name === "regtest" ? "http://127.0.0.1:8093" : "",
              status: (message, step) => setStatus(message, step), report,
              download: offerDownload, saved: (file) => { publishLink(file, name); void refreshSavedRecoveries(); } });
          })().catch(() => { report("stopped: Reverse execution could not continue. Keep backups; no uncertain payment will be retried."); });
          return true;
        };
        continueSwap.onclick = () => { continueWith(); };
        review.append(providers, chosen, node("p", "By continuing you accept the provider's signed terms.", "swap-reverse-consent"),
          refusal, continueSwap, done);
        // One-step swap: a signed price no worse than the shown estimate, with the address already entered, continues directly.
        if (withinEstimate(quote.holdInvoiceSat, quote.fundingConfirmations) && receiveAddress.value.trim()) {
          report(`signed price ${quote.holdInvoiceSat} sat is within the shown estimate ${estimatedTotal} sat; continuing`);
          if (continueWith()) return;
        }
        panel.replaceChildren(review);
        setStatus("Estimate ready. Enter your payout address, then continue", 1);
      } catch (error) {
        if (!cancellation.signal.aborted) {
          panel.replaceChildren(node("p", (error as Error).message, "swap-error"), done);
          report(`stopped: ${(error as Error).message}`);
        }
      } finally {
        // Preserve selected private sessions for the explicit Continue action.
        if (arrivals.length === 0 && !cancellation.signal.aborted) restore();
      }
    })();
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;
    const name = network.value as NetworkName;
    const route = routeFor(fromAsset.value, toAsset.value);
    if (route.unavailable || route.profile === null) {
      report(`refused: ${route.unavailable ?? "This pair cannot be quoted yet."}`);
      return;
    }
    if (route.profile === "ln-to-btc/v1") {
      reverseQuote(name);
      return;
    }
    if (route.profile === "erc20-to-ln/v1") {
      erc20Quote(name, STABLECOIN_SYMBOL[route.from.id]!);
      return;
    }
    if (route.profile === "ln-to-erc20/v1") {
      lnErc20Quote(name, STABLECOIN_SYMBOL[route.to.id]!);
      return;
    }
    let request: SwapRequest;
    let urls: readonly string[];
    let api: string;
    const automaticTip = !tip.value.trim();
    const needsWallet = !refund.value.trim() || !age.value.trim();
    try {
      urls = validateRelays(relay.value.trim(), name);
      api = validateMempoolApi(chainApi.value.trim(), name);
      if (identity.value.trim() && !/^[0-9a-f]{64}$/.test(identity.value.trim())) {
        throw new Error("Provider identity must be 64 lowercase hex characters, or leave it empty for automatic selection");
      }
      request = {
        identity: identity.value.trim(),
        network: NETWORKS[name],
        invoice: invoice.value.trim(),
        refundScript: refund.value.trim() ? addressScript(refund.value, name) : "",
        tipHeight: tip.value.trim() ? Number(positive(tip, "block height")) : 0,
        ageRecipient: age.value.trim(),
        limits: {
          maxSuccessFeeSat: positive(successFee, "provider fee"),
          maxFundingFeeSat: positive(fundingFee, "funding fee"),
          maxClaimFeeSat: positive(claimFee, "claim fee"),
          maxRefundFeeSat: positive(refundFee, "refund fee"),
          maxRefundDelayBlocks: Number(positive(delay, "refund delay")),
        },
      };
      invoiceBinding(request.invoice, name);
      if (tip.value.trim() && (!Number.isSafeInteger(request.tipHeight) || request.tipHeight >= 500_000_000)) {
        throw new Error("Block height override is invalid");
      }
    } catch (error) {
      setup.open = true;
      report(`refused: ${(error as Error).message}`);
      return;
    }
    const controls = [...form.elements, ...settings.querySelectorAll("input, textarea, select, button")];
    busy = true;
    for (const input of controls) {
      (input as HTMLInputElement).disabled = true;
    }
    settingsButton.disabled = providersButton.disabled = badge.disabled = true;
    const guard = (unload: BeforeUnloadEvent): void => unload.preventDefault();
    window.addEventListener("beforeunload", guard);
    let cancelled = false;
    const cancellation = new AbortController();
    let executing = false;
    let arrivals: readonly LocatedQuote[] = [];
    let cancelReview: (() => void) | undefined;
    const cancel = node("button", "Edit swap", "swap-edit");
    cancel.type = "button";
    const restore = (): void => {
      busy = false;
      for (const control of controls) (control as HTMLInputElement).disabled = false;
      settingsButton.disabled = providersButton.disabled = badge.disabled = false;
      updateNetwork();
      window.removeEventListener("beforeunload", guard);
    };
    cancel.onclick = () => {
      if (executing) return;
      cancelled = true;
      cancellation.abort();
      for (const quote of arrivals) quote.dispose();
      cancelReview?.();
      panel.replaceChildren();
      setStatus("Ready for a new quote", -1, "ready");
      restore();
    };
    panel.replaceChildren(node("p", "Checking signed provider announcements across your relays..."), cancel);
    setStatus("Finding available providers", 0);
    void (async () => {
      try {
        let wallet: BrowserRecoveryWallet | undefined;
        let walletFingerprint: string | undefined;
        if (needsWallet) {
          wallet = await walletPromise;
          if (cancelled) return;
          const info = await wallet.info();
          walletFingerprint = info.fingerprint;
          if (cancelled) return;
          if (!request.refundScript) {
            const allocation = await wallet.allocateRefund(name);
            request = { ...request, refundScript: allocation.script, refundAllocation: allocation };
          }
          if (!request.ageRecipient) request = { ...request, ageRecipient: info.recipient };
        }
        if (cancelled) return;
        if (automaticTip) {
          setStatus("Fetching block height from your configured API", 0);
          const observed = await readChainTip(api, { name, genesis_hash: request.network.genesis_hash as string }, { signal: cancellation.signal });
          request = { ...request, tipHeight: observed.height };
          report(`Trusted chain API observed block ${observed.height} (${observed.hash})`);
        }
        if (cancelled) return;
        const directory = await discoverMarketplace(urls, request.network, request.identity || undefined, cancellation.signal);
        if (cancelled) return;
        for (const warning of directory.warnings) report(warning);
        const binding = invoiceBinding(request.invoice, name);
        const mode = sortMode();
        const eligible = eligibleProviders(directory.providers, BigInt(binding.amount_msat) / 1000n, mode);
        if (eligible.length === 0) throw new Error(ineligibilityReason(providerLimits(directory.providers), BigInt(binding.amount_msat) / 1000n));
        setStatus("Comparing verified provider quotes", 1);
        report(`Requesting up to ${MAX_QUOTE_PROVIDERS} eligible offers from ${eligible.length} announced providers`);
        const result = await quoteProviders(eligible, request, cancellation.signal, mode);
        arrivals = result.quotes;
        if (cancelled) { for (const quote of arrivals) quote.dispose(); return; }
        if (arrivals.length === 0) throw new Error(`No provider returned acceptable terms (${result.reasons.join("; ")}). Nothing was accepted or funded.`);
        let selected = arrivals[0]!;
        const review = node("div", "", "swap-quote-review");
        const quoteSummary = node("div", "", "swap-quote-summary");
        const priceClaim = node("p", "", "swap-quote-selection");
        const showQuote = (): void => {
          const quote = selected.prepared.quote;
          priceClaim.textContent = quoteSelectionLabel(selected === arrivals[0], arrivals.length, mode);
          quoteSummary.replaceChildren(node("h2", `${quote.contractAmountSat.toLocaleString()} sat`),
            node("p", `Provider fee: ${quote.successFeeSat.toLocaleString()} sat. Your wallet's network fee is extra. ` +
              fundingWaitText("btc-to-ln/v1", quote.fundingConfirmations)),
            node("small", `Refund after block ${quote.refundLockHeight}. Offer expires ${new Date(quote.expiresAt * 1000).toLocaleTimeString()}.`));
        };
        showQuote();
        review.append(quoteSummary, priceClaim, node("small", "Signatures authenticate offers, not provider reputation."));
        if (request.refundAllocation) review.append(node("small", "Refunds pay your derived browser-wallet address. " +
          "Browser refunding and spending are not implemented yet. Test funds only; use an external refund-address override if needed."));
        if (directory.warnings.length || result.failures || eligible.length > MAX_QUOTE_PROVIDERS) {
          review.append(node("small", "Some relays or providers did not return complete results. This is not a market-wide best-price guarantee."));
        }
        const offers = node("details");
        offers.append(node("summary", "Provider details & manual selection"));
        const tags = offerTags(arrivals, forwardRank);
        for (const [index, quote] of arrivals.entries()) {
          const label = node("label");
          const option = node("input");
          option.type = "radio";
          option.name = "verified-provider";
          option.checked = index === 0;
          option.onchange = () => { selected = quote; showQuote(); };
          label.append(option, node("span", `${quote.prepared.quote.contractAmountSat} sat · ${quote.prepared.quote.providerIdentity.slice(0, 12)}…`),
            ...tags(quote), node("small", `Transport: ${quote.relayUrl}; identity: ${quote.prepared.quote.providerIdentity}`));
          offers.append(label);
        }
        const accept = node("button", "Use this quote", "swap-quote-accept");
        accept.type = "button";
        review.append(offers, node("p", "By continuing you accept the provider's signed terms.", "swap-quote-consent"), accept, cancel);
        // One-step swap: a signed price no worse than the shown estimate is accepted without a separate review.
        const direct = withinEstimate(selected.prepared.quote.contractAmountSat, selected.prepared.quote.fundingConfirmations);
        if (direct) report(`signed price ${selected.prepared.quote.contractAmountSat} sat is within the shown estimate ${estimatedTotal} sat; continuing`);
        else { panel.replaceChildren(review); setStatus("Quote ready. Review before continuing", 1); }
        const accepted = direct ? selected : await new Promise<LocatedQuote | null>((resolve) => {
          accept.onclick = () => {
            for (const option of offers.querySelectorAll("input")) option.disabled = true;
            accept.disabled = true;
            resolve(selected);
          };
          cancelReview = () => resolve(null);
        });
        if (!accepted || cancelled) return;
        if (wallet) {
          // The browser-stored recovery key is the approval; only an identity change blocks acceptance.
          const info = await wallet.info();
          if (info.fingerprint !== walletFingerprint) throw new Error("Recovery identity changed. Request a fresh quote.");
        }
        if (cancelled) return;
        if (Date.now() / 1000 >= accepted.prepared.quote.expiresAt) throw new Error("Quote expired. Request a fresh quote.");
        executing = true;
        for (const quote of arrivals) if (quote !== accepted) quote.dispose();
        arrivals = [accepted];
        showTracking("Bitcoin to Lightning swap");
        const paid = await run(accepted, name, panel, report, (file) => publishLink(file, name),
          () => validateMempoolApi(chainApi.value.trim(), name), async (file) => {
            await (await walletPromise).saveFundedRecovery(name, file);
            await refreshSavedRecoveries();
          });
        if (paid) setStatus("Lightning invoice paid", 4, "success");
      } catch (error) {
        if (!cancelled) {
          panel.replaceChildren(node("p", (error as Error).message, "swap-error"));
          report(`stopped: ${(error as Error).message}`);
        }
      } finally {
        for (const quote of arrivals) quote.dispose();
        if (!executing && !cancelled) restore();
        if (executing) window.removeEventListener("beforeunload", guard);
      }
    })();
  });
}

/** A key download is not verification, and a key backup cannot replace per-swap files. */
async function walletBackupControls(
  panel: HTMLElement, wallet: BrowserRecoveryWallet, status?: HTMLElement,
  verified?: () => Promise<void>,
): Promise<void> {
  const message = status ?? node("p", "Download your recovery key, then choose the saved file to check it.");
  if (!status) panel.append(message);
  const show = node("button", "Show 12 words", "swap-wallet-show-words"); show.type = "button";
  const words = node("pre", "", "swap-wallet-words"); words.hidden = true;
  panel.append(show, words);
  show.onclick = () => {
    if (!words.hidden) { words.textContent = ""; words.hidden = true; show.textContent = "Show 12 words"; return; }
    show.disabled = true;
    void (async () => {
      const backup = await wallet.exportBackup();
      try {
        words.textContent = parseWalletBackup(new TextDecoder().decode(backup)).mnemonic;
        words.hidden = false; show.textContent = "Hide words";
      } finally { backup.fill(0); }
    })().catch(() => { message.textContent = "Could not read the recovery key. Keep any existing backup."; })
      .finally(() => { show.disabled = false; });
  };
  offerDownload(panel, await wallet.exportBackup(), "rillswap-recovery-key.json");
  const label = node("label", "Check an existing recovery-key backup");
  const upload = node("input");
  upload.type = "file";
  upload.accept = ".json,application/json";
  label.append(upload); panel.append(label);
  upload.onchange = () => {
    void (async () => {
      const file = upload.files?.[0];
      if (!file || file.size > 4096) throw new Error("Choose a recovery-key JSON backup smaller than 4 KiB");
      await wallet.verifyBackup(await file.text());
      await verified?.();
      message.textContent = "Matching key backup checked. Keep it private and save every encrypted per-swap recovery file too.";
    })().catch((error: Error) => { message.textContent = error.message; });
  };
}

function offerDownload(panel: HTMLElement, file: Uint8Array, name: string): void {
  const url = URL.createObjectURL(new Blob([Uint8Array.from(file)], { type: "application/octet-stream" }));
  const link = node("a", `Download ${name}`);
  link.href = url;
  link.download = name;
  panel.append(link);
}

/** The deposit watcher stops on a visible outcome; the swap then continues or reports the refusal. */
const DEPOSIT_POLL_MS = 10_000;

function fundingPrompt(panel: HTMLElement, networkName: NetworkName, request: FundingRequest, chainApi: () => string,
  addressShown: () => void): Promise<FundingSource> {
  const address = scriptAddress(request.contractScript, networkName);
  const uri = `bitcoin:${address}?amount=${btc(request.amountSat)}`;
  const open = node("a", "Open in your wallet", "swap-funding-uri"); open.href = uri;
  const copy = node("button", "Copy address", "swap-funding-copy"); copy.type = "button";
  copy.onclick = () => { void navigator.clipboard?.writeText(address).then(() => { copy.textContent = "Copied"; }, () => {}); };
  const status = node("p", "Waiting for your payment. This page checks your mempool API every 10 seconds.", "swap-deposit-status");
  status.setAttribute("role", "status");
  // Zero-confirmation terms: the provider pays from its mempool, so the page binds the payment as soon as it sees it.
  const zeroConf = request.fundingConfirmations === 0;
  panel.replaceChildren(
    node("h2", "Send Bitcoin to fund the swap"),
    node("p", `Send exactly ${btc(request.amountSat)} BTC (${request.amountSat.toLocaleString()} sat, ` +
      `including the ${request.successFeeSat.toLocaleString()} sat provider fee) from any wallet to:`),
    qrSvg(uri, `QR code: ${uri}`, "swap-funding-qr"),
    node("pre", address, "swap-contract-address"),
    open, copy,
    node("p", `Send it in one transaction from a native segwit wallet, with a network fee of at most ` +
      `${request.maxFundingFeeSat.toLocaleString()} sat. Keep this page open until it ${zeroConf ? "sees the payment" : "confirms"}; the swap then continues by itself.`, "swap-funding-rules"),
    ...(zeroConf ? [node("p", "This provider pays before your payment confirms. Do not bump its fee or replace it in your wallet: " +
      `a replaced payment is not the one bound to the swap, and you could only refund it after block ${request.refundLockHeight}.`, "swap-zero-conf-warning")] : []),
    node("p", `If the provider does not pay, you can refund after block ${request.refundLockHeight}.`),
    node("p", "Pay only once: a second payment to this address is not swapped and may be lost.", "swap-second-deposit-warning"),
    status,
  );
  const advanced = node("details", "", "swap-funding-advanced");
  advanced.append(node("summary", "Advanced: fund with a finalized PSBT instead"),
    node("p", "Create the transaction in your wallet, sign and finalize it as a PSBT, and paste it here without broadcasting. " +
      "The page checks it, shares it with the provider, then asks you to broadcast it."));
  const psbtLabel = node("label", "Finalized PSBT (base64 or hex)");
  const psbt = node("textarea", "", "swap-psbt");
  psbtLabel.htmlFor = psbt.id;
  advanced.append(psbtLabel, psbt);
  panel.append(advanced);
  addressShown();
  return new Promise<FundingSource>((resolve, reject) => {
    let settled = false;
    const finish = (outcome: () => void): void => { if (!settled) { settled = true; clearTimeout(timer); outcome(); } };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async (): Promise<void> => {
      try {
        const seen = await observeDeposit(chainApi(), { address, script: request.contractScript, amountSat: request.amountSat },
          { acceptUnconfirmed: zeroConf });
        if (settled) return;
        if (seen.status === "confirmed" || seen.status === "mempool") { finish(() => resolve({ deposit: seen.funding })); return; }
        if (seen.status === "ambiguous") {
          finish(() => reject(new Error(`Several confirmed payments reached this address (${seen.txids.join(", ")}); ` +
            "none was bound to the swap. Each is refundable after the refund block; keep the terms backup.")));
          return;
        }
        if (seen.status === "unconfirmed") status.replaceChildren("Payment ", txLink(chainApi(), seen.txid), " seen, waiting for its first confirmation.");
        else status.textContent = "Waiting for your payment. This page checks your mempool API every 10 seconds.";
      } catch (error) {
        if (settled) return;
        if (error instanceof TransactionRefusedError) { finish(() => reject(new Error(`Your deposit could not be verified: ${error.message}`))); return; }
        status.textContent = "Your mempool API did not answer; trying again.";
      }
      timer = setTimeout(() => { void poll(); }, DEPOSIT_POLL_MS);
    };
    void poll();
    waitForClick(advanced, "Check funding").then(() => finish(() => resolve({ psbt: psbt.value })));
  });
}

async function run(
  quote: LocatedQuote,
  networkName: NetworkName,
  panel: HTMLElement,
  report: (line: string) => void,
  publish: (file: Uint8Array) => void,
  chainApi: () => string,
  persistFunded: (file: Uint8Array) => Promise<void>,
): Promise<boolean> {
  let fundsMayBeCommitted = false;
  // Backups stay visible while the stage prompts below them change.
  const backups = node("details", "", "swap-backups"), latestBackup = node("div");
  backups.append(node("summary", "Advanced"), latestBackup);
  const updateBackup = (file: Uint8Array, kind: string): void => {
    for (const old of latestBackup.querySelectorAll<HTMLAnchorElement>("a")) if (old.href.startsWith("blob:")) URL.revokeObjectURL(old.href);
    latestBackup.replaceChildren();
    offerDownload(latestBackup, file, `rillswap-${kind}-recovery.age`);
    latestBackup.querySelector("a")!.textContent = "Download swap backup";
  };
  const stage = node("div", "", "swap-stage");
  panel.replaceChildren(backups, stage);
  panel = stage;
  try {
    report(`Selected provider ${quote.prepared.quote.providerIdentity} via ${quote.relayUrl}`);
    const outcome = await quote.prepared.execute({
      report,
      saveRecovery: async (file, kind) => {
        updateBackup(file, kind);
        publish(file);
        if (kind === "funded") await persistFunded(file);
        report(kind === "terms" ? "recovery file saved to the backups list" : "funded recovery file added to the backups list");
      },
      // Showing the address can commit funds: anything sent there is the user's deposit from that moment.
      fundingSource: (funding) => fundingPrompt(panel, networkName, funding, chainApi, () => { fundsMayBeCommitted = true; }),
      beforeFundingCommit: async () => { fundsMayBeCommitted = true; },
      broadcast: async (raw, txid) => {
        panel.replaceChildren(
          node("h2", "Broadcast the funding transaction"),
          node("p", `The provider acknowledged funding ${txid}. Broadcast this exact transaction from your wallet ` +
            "or node:"),
          node("pre", raw, "swap-funding-raw"),
          node("p", "Most wallets broadcast a finalized PSBT or raw transaction from a Broadcast or Send " +
            "Transaction menu."),
        );
        await waitForClick(panel, "I broadcast it");
        panel.replaceChildren(node("p", "Waiting for the provider to pay the invoice..."));
      },
      cosigner: browserCosigner,
    });
    panel.replaceChildren(
      node("h2", "Invoice paid"),
      node("p", "The provider paid the invoice; this preimage proves it:"),
      node("pre", outcome.preimage, "swap-preimage"),
      node("p", outcome.cooperation === "verified"
        ? "You cosigned the provider's private key-path claim, so the swap leaves no script trace on chain."
        : "The provider claims with the preimage (cooperation was skipped). Nothing else is needed from you.",
        "swap-cooperation"),
      node("p", "Optional: keep the paid recovery file from the backups list as a record of the completed swap."),
    );
    updateBackup(outcome.paidRecovery, "paid");
    publish(outcome.paidRecovery);
    return true;
  } catch (error) {
    const message = (error as Error).message;
    const next = stoppedSwapAdvice(fundsMayBeCommitted);
    panel.replaceChildren(
      node("h2", "Swap stopped"),
      node("p", message, "swap-error"),
      node("p", next, "swap-next-step"),
    );
    report(`stopped: ${message}`);
    return false;
  } finally {
    quote.dispose();
  }
}

const root = document.getElementById("swap");
if (!root) throw new Error("Static application root missing");
mount(root);
