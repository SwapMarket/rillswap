/**
   * Experimental browser BTC and LN client page. Everything sensitive stays in
 * contract secrets stay in this tab; the recovery root is stored locally.
 * The user's own wallet funds and broadcasts, and the
 * user's own downloads hold the age-encrypted recovery files.
 */
import "./swap.css";
import mainnet from "./networks/mainnet.json";
import regtest from "./networks/regtest-rillswap-e2e-v1.json";
import signet from "./networks/signet.json";
import testnet4 from "./networks/testnet4.json";
import { addressScript, scriptAddress } from "./swap/address";
import { browserCosigner } from "./swap/browserCosigner";
import { type FundingRequest, type FundingSource, type SwapRequest } from "./swap/swap";
import { observeDeposit } from "./swap/depositWatch";
import { TransactionRefusedError } from "./swap/transaction";
import { mempoolApiForNetwork, relaysForNetwork, validateMempoolApi, validateRelays, type NetworkName } from "./swap/config";
import { readChainTip } from "./swap/chainTip";
import { BrowserRecoveryWallet } from "./browserRecoveryWallet";
import { type DirectoryEntry, discoverDirectory, discoverMarketplace, eligibleProviders, indicativeFee, ineligibilityReason, quoteProviders, quoteReverseProviders,
  estimateFromDirectory, providerLimits, type LocatedQuote, MAX_QUOTE_PROVIDERS } from "./swap/marketplace";
import type { PreparedReverseQuote, ReverseSwapRequest } from "./swap/reverseSwap";
import { invoiceBinding } from "./swap/bolt11";
import { quoteSelectionLabel, stoppedSwapAdvice } from "./swapUiStatus";
import { ASSETS, type AssetId, routeFor } from "./swapPairs";
import { recoveryPanel } from "./recoveryUi";
import { parseSwapLink, swapLinkFragment } from "./swapLink";
import { mountReverseExecution } from "./reverseExecutionUi";

const NETWORKS = { mainnet, signet, testnet4, regtest } as const;

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

const btc = (sats: bigint): string => `${sats / 100_000_000n}.${(sats % 100_000_000n).toString().padStart(8, "0")}`;

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
  const badge = node("span", "", "swap-network-badge");
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
  settings.append(relayLabel, relay, node("small",
    "Up to four relays. Connect only when you request a quote. Each operator sees your IP and transport metadata."));
  const chainApi = field(settings, "swap-chain-api", "Mempool API", __SWAP_DEFAULTS__.mempoolApi,
    "Trusted height observations, not independent chain verification. Custom origins need a deployment CSP allowance.");
  const broadcastApi = field(settings, "swap-broadcast-api", "Transaction broadcast API", __SWAP_DEFAULTS__.broadcastApi,
    "Used only after explicit refund or claim approval and a broadcast click. Custom origins need a deployment CSP allowance.");
  const identity = field(settings, "swap-provider", "Provider identity", "",
    "Automatic by default. Optionally pin a provider's 64-character public identity key, or choose one under Providers.");
  identity.placeholder = "Automatic (lowest verified provider price)";
  // The provider directory: every announced provider with its limits and fees, browsable before any amount.
  const providers = node("dialog", "", "swap-providers");
  const providersHead = node("div");
  providersHead.className = "card-heading";
  const closeProviders = node("button", "Close", "swap-providers-close");
  closeProviders.type = "button";
  providersHead.append(node("h2", "Providers"), closeProviders);
  const providersIntro = node("p", "", "swap-providers-intro");
  const loadProviders = node("button", "Load providers", "swap-providers-load");
  loadProviders.type = "button";
  const providersStatus = node("p", "", "swap-providers-status");
  providersStatus.setAttribute("role", "status");
  const providersList = node("div", "", "swap-providers-list");
  providers.append(providersHead, providersIntro, loadProviders, providersStatus, providersList);
  providersButton.onclick = () => {
    providersIntro.textContent = `Load connects to your configured relays and lists every provider announced for ${network.value}. ` +
      "Signatures authenticate announcements, not reputation; limits and fees are indicative until a signed quote.";
    providers.showModal();
  };
  closeProviders.onclick = () => providers.close();
  const providerChoice = node("p", "", "swap-provider-choice");
  const DIRECTION: Record<string, string> = { "btc-to-ln/v1": "Bitcoin to Lightning", "ln-to-btc/v1": "Lightning to Bitcoin" };
  let directoryEntries: readonly DirectoryEntry[] = [];
  const showProviderChoice = (): void => {
    const pinned = identity.value.trim();
    providerChoice.textContent = pinned ? `Provider: ${pinned.slice(0, 12)}… (chosen by you)` : "Provider: automatic, lowest verified price";
    for (const option of providersList.querySelectorAll<HTMLInputElement>("input[type=radio]")) option.checked = option.value === pinned;
  };
  const renderDirectory = (): void => {
    const pinned = identity.value.trim();
    const choice = (value: string, text: string): HTMLLabelElement => {
      const label = node("label"), option = node("input");
      option.type = "radio"; option.name = "directory-provider"; option.value = value; option.checked = value === pinned;
      option.onchange = () => { identity.value = value; showProviderChoice(); };
      label.append(option, node("strong", text));
      return label;
    };
    const automatic = node("article");
    automatic.className = "swap-provider";
    automatic.append(choice("", "Automatic"), node("p", "Compares the eligible providers' signed quotes and picks the lowest verified price."));
    providersList.replaceChildren(automatic);
    for (const entry of directoryEntries) {
      const article = node("article");
      article.className = "swap-provider";
      const bands = entry.amountBands.map((band) => `${BigInt(band.minimum_sat).toLocaleString()} to ${BigInt(band.maximum_sat).toLocaleString()} sat`).join(", ");
      const fee = entry.indicativeFeePolicy;
      const sample = 100_000n;
      article.append(choice(entry.identity, `${entry.identity.slice(0, 12)}…`),
        node("p", `Directions: ${entry.profiles.map((profile) => DIRECTION[profile] ?? profile).join(", ")}`),
        node("p", `Limits: ${bands}`),
        node("p", `Fee: ${BigInt(fee.base_sat).toLocaleString()} sat + ${(fee.proportional_millionths / 10_000).toFixed(2)}% ` +
          `(about ${indicativeFee(fee, sample).toLocaleString()} sat on a ${sample.toLocaleString()} sat swap)`),
        node("small", `Identity: ${entry.identity}. Slot: ${entry.slot}. Relays: ${entry.relayUrls.join(", ")}. ` +
          `Announcement expires ${new Date(entry.expiresAt * 1000).toLocaleString()}.`));
      providersList.append(article);
    }
  };
  let directoryLoaded = false;
  /** Explicit directory load; the estimate line and the Providers dialog share it. */
  const loadDirectory = (): void => {
    const name = network.value as NetworkName;
    let urls: readonly string[];
    try { urls = validateRelays(relay.value.trim(), name); } catch (error) { providersStatus.textContent = (error as Error).message; return; }
    loadProviders.disabled = true;
    providersStatus.textContent = "Checking signed announcements on your relays...";
    void discoverDirectory(urls, NETWORKS[name]).then((directory) => {
      directoryEntries = directory.entries;
      directoryLoaded = true;
      renderDirectory();
      providersStatus.textContent = directory.entries.length === 0 ? "No provider announced on these relays." :
        `${directory.entries.length} announced provider${directory.entries.length === 1 ? "" : "s"}.` +
        (directory.warnings.length ? ` Some relays were incomplete: ${directory.warnings.join("; ")}.` : "");
    }, (error: Error) => { providersStatus.textContent = error.message; }).finally(() => { loadProviders.disabled = false; updateEstimate(); });
  };
  loadProviders.onclick = loadDirectory;
  identity.oninput = () => { showProviderChoice(); updateEstimate(); };
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
  const estimateLoad = node("button", "Show fees", "swap-estimate-load");
  estimateLoad.type = "button";
  estimateLoad.onclick = () => { estimateLoad.disabled = true; loadDirectory(); };
  let estimatedTotal: bigint | null = null;
  const updateEstimate = (): void => {
    estimatedTotal = null;
    estimateLoad.hidden = directoryLoaded;
    estimateLoad.disabled = false;
    const route = routeFor(fromAsset.value, toAsset.value);
    if (route.profile === null || route.unavailable) { estimate.textContent = ""; return; }
    let amount: bigint;
    try {
      amount = route.profile === "btc-to-ln/v1"
        ? BigInt(invoiceBinding(invoice.value.trim(), network.value as NetworkName).amount_msat) / 1000n
        : positive(receiveAmount, "Amount to receive");
    } catch { estimate.textContent = directoryLoaded ? "Enter an amount to see the fee." : "Load announced fees to see the estimate before you swap."; return; }
    if (!directoryLoaded) { estimate.textContent = "Load announced fees to see the estimate before you swap."; return; }
    const found = estimateFromDirectory(directoryEntries, route.profile, amount, identity.value.trim());
    if ("reason" in found) { estimate.textContent = found.reason; return; }
    estimatedTotal = amount + found.feeSat;
    estimate.textContent = route.profile === "btc-to-ln/v1"
      ? `You send about ${estimatedTotal.toLocaleString()} sat (${amount.toLocaleString()} sat invoice + ${found.feeSat.toLocaleString()} sat provider fee via ${found.identity.slice(0, 12)}…). Your wallet's network fee is extra.`
      : `You pay about ${estimatedTotal.toLocaleString()} sat over Lightning (${found.feeSat.toLocaleString()} sat provider fee via ${found.identity.slice(0, 12)}…) to receive ${amount.toLocaleString()} sat.`;
  };
  invoice.oninput = receiveAmount.oninput = updateEstimate;
  form.append(invoiceBox, receiveBox, estimate, estimateLoad);
  const setup = node("details", "", "swap-wallet-setup");
  const prerequisites = node("p", "", "swap-prerequisites");
  setup.append(node("summary", "Recovery key & advanced overrides"), prerequisites);
  const walletStatus = node("p", "Preparing your browser recovery key...", "swap-wallet-status");
  const walletActions = node("div", "", "swap-wallet-actions");
  setup.append(walletStatus, walletActions, node("small", "Stored unencrypted in this browser. Same-origin scripts can read it. " +
    "Keep both the key backup and each encrypted swap recovery file. Clearing storage can lose access to refunds."));
  // Overrides apply to Bitcoin to Lightning only; the recovery key serves both directions.
  const overrides = node("div", "", "swap-forward-overrides");
  setup.append(overrides);
  const refund = field(overrides, "swap-refund", "Refund address override (optional)", "",
    "Leave empty for a fresh address derived from your browser recovery key. Otherwise use your own wallet's P2WPKH or P2TR address.");
  const tip = field(overrides, "swap-tip", "Block height override (optional)", "", "Leave empty to fetch the height from the configured mempool API.");
  const age = field(overrides, "swap-age", "Recovery encryption recipient override (optional, age1...)", "",
    "Leave empty for the browser key. An override requires keeping its corresponding private age key yourself.");
  const privacy = node("details", "", "swap-privacy");
  const chainDisclosure = node("p", "", "swap-chain-disclosure");
  const relayDisclosure = node("p", "", "swap-relay-disclosure");
  privacy.append(node("summary", "Privacy & terms"),
    node("p", "Requesting a quote or checking recovery funding authorizes the configured connections for that attempt. " +
      "Nothing connects on page load or when you change settings."),
    chainDisclosure, relayDisclosure,
    node("p", "For Bitcoin to Lightning, responding providers receive your Lightning invoice. For Lightning to Bitcoin, " +
      "only the selected firm provider receives your payout script and payment hash. Encrypted messages do not hide transport metadata. " +
      "Signatures authenticate offers, not provider reputation."),
    node("p", "Connecting a Lightning node discloses its scoped credential to this tab and sends the signed hold invoice to that node. " +
      "Credentials are not saved. Approving the exact route authorizes one payment attempt; signing and broadcasting a reverse claim reveals its preimage."),
    node("p", "Recovery keys and files are not uploaded. The recovery root is stored unencrypted in this browser, " +
      "where same-origin scripts can access it. Keep private backups and every encrypted per-swap recovery file. " +
      "Clearing browser storage can lose access to refunds."),
    node("p", "Unaudited experimental software, test funds only. New mainnet swaps remain blocked. " +
      "A quote is not a funding commitment; review it and verify your key backup before continuing."));
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
  const minReserve = field(limits, "swap-min-claim-reserve", "Minimum claim fee reserve (sat)", "500",
    "On-chain fee budget the provider must lock for your claim.");
  const minRefundDelay = field(limits, "swap-min-refund-delay", "Minimum time before provider refund (blocks)", "72");
  const maxHold = field(limits, "swap-max-hold", "Maximum Lightning hold (blocks)", "432",
    "How long your Lightning payment may stay pending (432 is about three days).");
  settings.append(limits);
  const notice = node("p", "", "swap-release-notice");
  notice.setAttribute("role", "note");
  const start = node("button", "Swap", "swap-start");
  start.type = "submit";
  start.className = "primary";
  form.append(setup, notice, start);
  const safety = node("details", "", "swap-safety");
  safety.append(node("summary", "Before using this preview"),
    node("p", "Unaudited and experimental. Use fake-money test networks only. Contract secrets live in this tab; " +
      "keep it open until the swap finishes."),
    node("p", "Save your recovery key and each encrypted swap backup before funding or paying. Browser recovery below can check funding, " +
      "prepare a Bitcoin refund after its lock height, or recover a Lightning-to-Bitcoin claim. Missing evidence stays blocked; never pay again to recover an uncertain attempt.", "swap-refund-intro"));
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
  linkBox.append(node("p", "This page's address now holds your encrypted swap record. Bookmark it or copy it: opening it later " +
    "shows the swap and its recovery actions. Only your recovery key can read it; the link is never sent anywhere."), linkAnchor, copyLink);
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
  card.append(cardHead, form, tracking, progress, panel, privacy, safety, diagnostics);
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
  });
  card.insertBefore(recovery.element, safety);
  // Register failure handling immediately so blocked storage never becomes an unhandled rejection.
  void walletPromise.then(async (wallet) => {
    await walletBackupControls(walletActions, wallet, walletStatus);
    offerDownload(walletActions, (await wallet.recoveryKey()).file, "rillswap-recovery.age-key");
    walletStatus.textContent = wallet.newlyCreated
      ? "New browser recovery key created. It does not restore earlier swaps. Download and check your backup before funding."
      : "Using your existing browser recovery key.";
  }).catch((error: Error) => { walletStatus.textContent = error.message; });
  const updateDisclosure = (): void => {
    chainDisclosure.textContent = `Chain API: ${chainApi.value.trim()}. This operator sees your IP when automatic height or recovery funding is checked, ` +
      "and the selected public transaction ID and output for recovery checks, which can reveal their public addresses and amounts. " +
      "It receives no keys, recovery files, or invoices. " +
      "Its observations are trusted, not independent chain verification.";
    chainDisclosure.textContent += ` Broadcast API: ${broadcastApi.value.trim()}. An explicit broadcast sends the signed transaction, revealing its public addresses and amounts, never recovery secrets. ` +
      "Signed downloads can be broadcast by anyone who receives them. Approval is required before signing or exporting.";
    relayDisclosure.textContent = `Nostr relays: ${relay.value.trim().split(/\s+/).join(", ")}. Operators see your IP and transport metadata.`;
  };
  chainApi.oninput = () => { updateDisclosure(); recovery.clearFundingObservation(); };
  broadcastApi.oninput = () => { updateDisclosure(); recovery.clearFundingObservation(); };
  relay.oninput = updateDisclosure;
  updateDisclosure();
  const updateNetwork = (): void => {
    const main = network.value === "mainnet";
    const route = routeFor(fromAsset.value, toAsset.value);
    badge.textContent = main ? "Mainnet · preview" : `${network.value} · test funds`;
    notice.textContent = main
      ? "Mainnet swaps are blocked until release safety checks are complete. Choose a test network in Settings."
      : "Experimental preview. Test funds only. Review wallet and recovery setup before continuing.";
    heroTitle.textContent = route.title;
    heroTagline.textContent = route.tagline;
    pairNote.textContent = route.unavailable ?? "";
    pairNote.hidden = !route.unavailable;
    invoiceBox.hidden = route.profile !== "btc-to-ln/v1";
    overrides.hidden = route.profile !== "btc-to-ln/v1";
    prerequisites.textContent = route.profile === "btc-to-ln/v1"
      ? "This experimental flow needs a wallet that can sign a PSBT without broadcasting it, but creates your recovery key and refund address automatically."
      : "Your browser recovery key is created automatically and covers every swap started here.";
    receiveBox.hidden = route.profile !== "ln-to-btc/v1";
    start.disabled = main || route.unavailable !== null;
    start.textContent = main ? "Mainnet swaps unavailable" : route.unavailable ? "Pair unavailable" : "Swap";
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
    refund.value = tip.value = age.value = "";
    updateDisclosure();
    updateNetwork();
    recovery.clearFundingObservation();
    directoryEntries = []; directoryLoaded = false; renderDirectory(); providersStatus.textContent = "";
  };
  network.onchange = applyNetwork;
  updateNetwork();
  // A swap link reopens its encrypted record locally: inspection decrypts and parses, nothing connects.
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
    const prefill = { invoice: text("invoice", 4096), address: text("address", 128), amount: text("amount", 16) };
    if (prefill.invoice) { fromAsset.value = "btc"; toAsset.value = "ln"; invoice.value = prefill.invoice; }
    else if (prefill.address || prefill.amount) { fromAsset.value = "ln"; toAsset.value = "btc"; }
    if (prefill.address) receiveAddress.value = prefill.address;
    if (/^[0-9]{1,16}$/.test(prefill.amount)) receiveAmount.value = prefill.amount;
    lastFrom = fromAsset.value; lastTo = toAsset.value;
    history.replaceState(null, "", location.pathname + location.search);
    updateNetwork();
  }

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
    settingsButton.disabled = providersButton.disabled = true;
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
      settingsButton.disabled = providersButton.disabled = false;
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
        const eligible = eligibleProviders(directory.providers, request.payoutSat);
        if (eligible.length === 0) throw new Error(ineligibilityReason(providerLimits(directory.providers), request.payoutSat));
        setStatus("Comparing provider estimates", 1);
        report(`Requesting up to ${MAX_QUOTE_PROVIDERS} eligible offers from ${eligible.length} announced providers`);
        const result = await quoteReverseProviders(eligible, request, cancellation.signal);
        arrivals = result.quotes;
        if (cancellation.signal.aborted) return;
        if (arrivals.length === 0) throw new Error(`No provider returned acceptable terms (${result.reasons.join("; ")}). Nothing was paid.`);
        let selected = arrivals[0]!;
        const quote = selected.prepared.quote;
        const review = node("div", "", "swap-quote-review");
        review.append(node("p", "Estimated price", "swap-quote-kind"), node("h2", `${quote.holdInvoiceSat.toLocaleString()} sat`),
          node("p", `You pay this over Lightning (plus your wallet's routing fee) and receive ${quote.payoutSat.toLocaleString()} sat on-chain.`),
          node("small", `Provider fee: ${quote.successFeeSat.toLocaleString()} sat. Claim fee reserve: ${quote.claimFeeReserveSat.toLocaleString()} sat. ` +
            `Payout after ${quote.fundingConfirmations} confirmation${quote.fundingConfirmations === 1 ? "" : "s"} (about ${quote.fundingConfirmations * 10} min). ` +
            `If the swap fails, your Lightning payment may stay pending for up to about ${quote.incomingHtlcExpiryDeltaBlocks} blocks. ` +
            `Estimate expires ${new Date(quote.expiresAt * 1000).toLocaleTimeString()}.`),
          node("p", `Lowest estimate among ${arrivals.length} responding provider${arrivals.length === 1 ? "" : "s"}.`, "swap-quote-selection"),
          node("p", "Nothing was paid and no address or payment hash was shared. Continue checks the selected provider's final signed terms before any payment.", "swap-reverse-pending"));
        if (directory.warnings.length || result.failures || eligible.length > MAX_QUOTE_PROVIDERS) {
          review.append(node("small", "Some relays or providers did not return complete results. This is not a market-wide best-price guarantee."));
        }
        const providers = node("details"); providers.append(node("summary", "Provider details & manual selection"));
        const chosen = node("p", `Selected provider: ${selected.prepared.quote.providerIdentity}`, "swap-reverse-selected");
        for (const [index, located] of arrivals.entries()) {
          const label = node("label"), option = node("input"); option.type = "radio"; option.name = "reverse-provider"; option.checked = index === 0;
          option.onchange = () => { selected = located; chosen.textContent = `Selected provider: ${located.prepared.quote.providerIdentity}. Estimated hold: ${located.prepared.quote.holdInvoiceSat} sat.`; };
          label.append(option, node("span", `${located.prepared.quote.holdInvoiceSat} sat · ${located.prepared.quote.providerIdentity.slice(0, 12)}…`)); providers.append(label);
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
            await mountReverseExecution(panel, { prepared: selected.prepared, network: { ...NETWORKS[name], name }, destinationScript,
              ageRecipient: info.recipient, chainApi: chainApi.value.trim(), broadcastApi: broadcastApi.value.trim(), assertCurrent,
              nodeApi: __SWAP_DEFAULTS__.network === name ? __SWAP_DEFAULTS__.nodeApi ?? "" : name === "regtest" ? "http://127.0.0.1:8093" : "",
              status: (message, step) => setStatus(message, step),
              download: (root, file, fileName) => { offerDownload(root, file, fileName); if (fileName.endsWith(".age")) publishLink(file, name); } });
          })().catch(() => { report("stopped: Reverse execution could not continue. Keep backups; no uncertain payment will be retried."); });
          return true;
        };
        continueSwap.onclick = () => { continueWith(); };
        review.append(providers, chosen, node("p", "By continuing you accept the selected provider's signed terms and this preview's test-funds-only conditions. " +
          "Your browser recovery key covers this swap; download it from Recovery key & advanced overrides whenever you like.", "swap-reverse-consent"),
          refusal, continueSwap, done);
        // One-step swap: a signed price no worse than the shown estimate, with the address already entered, continues directly.
        if (estimatedTotal !== null && quote.holdInvoiceSat <= estimatedTotal && receiveAddress.value.trim()) {
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
    if (name === "mainnet") {
      report("refused: Mainnet swaps are blocked until release safety checks are complete.");
      return;
    }
    const route = routeFor(fromAsset.value, toAsset.value);
    if (route.unavailable || route.profile === null) {
      report(`refused: ${route.unavailable ?? "This pair cannot be quoted yet."}`);
      return;
    }
    if (route.profile === "ln-to-btc/v1") {
      reverseQuote(name);
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
    settingsButton.disabled = providersButton.disabled = true;
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
      settingsButton.disabled = providersButton.disabled = false;
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
        const eligible = eligibleProviders(directory.providers, BigInt(binding.amount_msat) / 1000n);
        if (eligible.length === 0) throw new Error(ineligibilityReason(providerLimits(directory.providers), BigInt(binding.amount_msat) / 1000n));
        setStatus("Comparing verified provider quotes", 1);
        report(`Requesting up to ${MAX_QUOTE_PROVIDERS} eligible offers from ${eligible.length} announced providers`);
        const result = await quoteProviders(eligible, request, cancellation.signal);
        arrivals = result.quotes;
        if (cancelled) { for (const quote of arrivals) quote.dispose(); return; }
        if (arrivals.length === 0) throw new Error(`No provider returned acceptable terms (${result.reasons.join("; ")}). Nothing was accepted or funded.`);
        let selected = arrivals[0]!;
        const review = node("div", "", "swap-quote-review");
        const quoteSummary = node("div", "", "swap-quote-summary");
        const priceClaim = node("p", "", "swap-quote-selection");
        const showQuote = (): void => {
          const quote = selected.prepared.quote;
          priceClaim.textContent = quoteSelectionLabel(selected === arrivals[0], arrivals.length);
          quoteSummary.replaceChildren(node("h2", `${quote.contractAmountSat.toLocaleString()} sat`),
            node("p", `Provider fee: ${quote.successFeeSat.toLocaleString()} sat. Your wallet's network fee is extra.`),
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
        for (const [index, quote] of arrivals.entries()) {
          const label = node("label");
          const option = node("input");
          option.type = "radio";
          option.name = "verified-provider";
          option.checked = index === 0;
          option.onchange = () => { selected = quote; showQuote(); };
          label.append(option, node("span", `${quote.prepared.quote.contractAmountSat} sat · ${quote.prepared.quote.providerIdentity.slice(0, 12)}…`),
            node("small", `Transport: ${quote.relayUrl}; identity: ${quote.prepared.quote.providerIdentity}`));
          offers.append(label);
        }
        const accept = node("button", "Use this quote", "swap-quote-accept");
        accept.type = "button";
        review.append(offers, node("p", "By continuing you accept the selected provider's signed terms and this preview's test-funds-only conditions. " +
          "Your browser recovery key covers this swap; download it from Recovery key & advanced overrides whenever you like.", "swap-quote-consent"), accept, cancel);
        // One-step swap: a signed price no worse than the shown estimate is accepted without a separate review.
        const direct = estimatedTotal !== null && selected.prepared.quote.contractAmountSat <= estimatedTotal;
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
          () => validateMempoolApi(chainApi.value.trim(), name));
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
  panel.replaceChildren(
    node("h2", "Send Bitcoin to fund the swap"),
    node("p", `Send exactly ${btc(request.amountSat)} BTC (${request.amountSat.toLocaleString()} sat, ` +
      `including the ${request.successFeeSat.toLocaleString()} sat provider fee) from any wallet to:`),
    node("pre", address, "swap-contract-address"),
    open, copy,
    node("p", `Send it once, in one transaction, from a native segwit wallet (addresses starting with bc1), with a network fee of at most ` +
      `${request.maxFundingFeeSat.toLocaleString()} sat. The swap continues by itself once the payment has one confirmation. ` +
      "Keep this page open until then: closing it before the confirmation leaves the deposit unbound to the swap.", "swap-funding-rules"),
    node("p", `If the provider does not pay, you can refund after block ${request.refundLockHeight}.`),
    node("p", "Pay this address once, in this one transaction. A second payment to it is not a new swap: " +
      "it is never paid over Lightning, the refund tools cover only the bound funding output, and once " +
      "the provider knows the preimage it can claim any output at this address. It may be lost.",
    "swap-second-deposit-warning"),
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
        const seen = await observeDeposit(chainApi(), { address, script: request.contractScript, amountSat: request.amountSat });
        if (settled) return;
        if (seen.status === "confirmed") { finish(() => resolve({ deposit: seen.funding })); return; }
        if (seen.status === "ambiguous") {
          finish(() => reject(new Error(`Several confirmed payments reached this address (${seen.txids.join(", ")}); ` +
            "none was bound to the swap. Each is refundable after the refund block; keep the terms backup.")));
          return;
        }
        status.textContent = seen.status === "unconfirmed"
          ? `Payment ${seen.txid} seen, waiting for its first confirmation.`
          : "Waiting for your payment. This page checks your mempool API every 10 seconds.";
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
): Promise<boolean> {
  let fundsMayBeCommitted = false;
  // Backups stay visible while the stage prompts below them change.
  const backups = node("section", "", "swap-backups");
  backups.append(node("p", "Encrypted recovery files for this swap. The funded file is what lets you refund; keep it with your recovery key.", "swap-backups-intro"));
  const stage = node("div", "", "swap-stage");
  panel.replaceChildren(backups, stage);
  panel = stage;
  try {
    report(`Selected provider ${quote.prepared.quote.providerIdentity} via ${quote.relayUrl}`);
    const outcome = await quote.prepared.execute({
      report,
      saveRecovery: async (file, kind) => {
        offerDownload(backups, file, `rillswap-${kind}-recovery-${Math.floor(Date.now() / 1000)}.age`);
        publish(file);
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
    offerDownload(backups, outcome.paidRecovery, `rillswap-paid-recovery-${Math.floor(Date.now() / 1000)}.age`);
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
