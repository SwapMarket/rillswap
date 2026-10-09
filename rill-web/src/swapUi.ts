/**
 * Experimental browser BTC to LN client page. Everything sensitive stays in
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
import { type FundingRequest, type SwapRequest } from "./swap/swap";
import { mempoolApiForNetwork, relaysForNetwork, validateMempoolApi, validateRelays, type NetworkName } from "./swap/config";
import { readChainTip } from "./swap/chainTip";
import { BrowserRecoveryWallet } from "./browserRecoveryWallet";
import { discoverMarketplace, eligibleProviders, quoteProviders, quoteReverseProviders, type LocatedQuote, MAX_QUOTE_PROVIDERS } from "./swap/marketplace";
import type { PreparedReverseQuote, ReverseSwapRequest } from "./swap/reverseSwap";
import { invoiceBinding } from "./swap/bolt11";
import { quoteSelectionLabel, stoppedSwapAdvice } from "./swapUiStatus";
import { ASSETS, type AssetId, routeFor } from "./swapPairs";

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
  cardHead.append(node("h2", "Swap Bitcoin"), settingsButton);
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
  const identity = field(settings, "swap-provider", "Provider identity", "",
    "Automatic by default. Optionally pin a provider's 64-character public identity key.");
  identity.placeholder = "Automatic (lowest verified provider price)";
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
  form.append(pair, pairNote);
  const invoiceBox = node("div");
  const invoice = field(invoiceBox, "swap-invoice", "Lightning invoice to pay (BOLT11)");
  invoice.placeholder = "Paste your Lightning invoice";
  const receiveBox = node("div");
  const receiveAddress = field(receiveBox, "swap-receive-address", "Bitcoin address to receive");
  receiveAddress.placeholder = "bc1... (your wallet)";
  const receiveAmount = field(receiveBox, "swap-receive-amount", "Amount to receive (sat)");
  receiveAmount.inputMode = "numeric";
  receiveAmount.placeholder = "50000";
  form.append(invoiceBox, receiveBox);
  const setup = node("details", "", "swap-wallet-setup");
  setup.append(node("summary", "Recovery key & advanced overrides"),
    node("p", "This experimental flow needs a wallet that can sign a PSBT without broadcasting it, " +
      "but creates your recovery key and refund address automatically.", "swap-prerequisites"));
  const walletStatus = node("p", "Preparing your browser recovery key...", "swap-wallet-status");
  const walletActions = node("div", "", "swap-wallet-actions");
  setup.append(walletStatus, walletActions, node("small", "Stored unencrypted in this browser. Same-origin scripts can read it. " +
    "Keep both the key backup and each encrypted swap recovery file. Clearing storage can lose access to refunds."));
  const refund = field(setup, "swap-refund", "Refund address override (optional)", "",
    "Leave empty for a fresh address derived from your browser recovery key. Otherwise use your own wallet's P2WPKH or P2TR address.");
  const tip = field(setup, "swap-tip", "Block height override (optional)", "", "Leave empty to fetch the height from the configured mempool API.");
  const age = field(setup, "swap-age", "Recovery encryption recipient override (optional, age1...)", "",
    "Leave empty for the browser key. An override requires keeping its corresponding private age key yourself.");
  const privacy = node("details", "", "swap-privacy");
  const chainDisclosure = node("p", "", "swap-chain-disclosure");
  const relayDisclosure = node("p", "", "swap-relay-disclosure");
  privacy.append(node("summary", "Privacy & terms"),
    node("p", "Requesting a quote authorizes the configured connections for this attempt. " +
      "Nothing connects on page load or when you change settings."),
    chainDisclosure, relayDisclosure,
    node("p", "Responding providers receive your Lightning invoice. Encrypted messages do not hide transport metadata. " +
      "Signatures authenticate offers, not provider reputation."),
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
  const start = node("button", "Get quote", "swap-start");
  start.type = "submit";
  start.className = "primary";
  form.append(setup, notice, start);
  const safety = node("details", "", "swap-safety");
  safety.append(node("summary", "Before using this preview"),
    node("p", "Unaudited and experimental. Use fake-money test networks only. Contract secrets live in this tab; " +
      "keep it open until the swap finishes."),
    node("p", "Browser recovery is not implemented yet. Save the encrypted recovery file before funding. " +
      "If the provider does not pay, refund after the lock height with rill recover watch-refund --chain-only " +
      "and your own Bitcoin Core node.", "swap-refund-intro"));
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
  card.append(cardHead, form, progress, panel, privacy, safety, diagnostics);
  const footer = node("footer", "Provider-neutral · No account · Locally verified");
  root.replaceChildren(header, intro, card, footer, settings);
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
  const walletPromise = BrowserRecoveryWallet.open();
  // Register failure handling immediately so blocked storage never becomes an unhandled rejection.
  void walletPromise.then(async (wallet) => {
    await walletBackupControls(walletActions, wallet, walletStatus);
    offerDownload(walletActions, (await wallet.recoveryKey()).file, "rillswap-recovery.age-key");
    walletStatus.textContent = wallet.newlyCreated
      ? "New browser recovery key created. It does not restore earlier swaps. Download and check your backup before funding."
      : "Using your existing browser recovery key.";
  }).catch((error: Error) => { walletStatus.textContent = error.message; });
  const updateDisclosure = (): void => {
    chainDisclosure.textContent = `Chain API: ${chainApi.value.trim()}. When automatic height is used, this operator sees your IP, ` +
      "but receives no keys, invoices, or addresses. Its observations are trusted, not independent chain verification.";
    relayDisclosure.textContent = `Nostr relays: ${relay.value.trim().split(/\s+/).join(", ")}. Operators see your IP and transport metadata.`;
  };
  chainApi.oninput = relay.oninput = updateDisclosure;
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
    setup.hidden = route.profile !== "btc-to-ln/v1";
    receiveBox.hidden = route.profile !== "ln-to-btc/v1";
    start.disabled = main || route.unavailable !== null;
    start.textContent = main ? "Mainnet swaps unavailable" : route.unavailable ? "Pair unavailable" : "Get quote";
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
  network.onchange = () => {
    relay.value = relaysForNetwork(network.value as NetworkName, __SWAP_DEFAULTS__).join("\n");
    chainApi.value = mempoolApiForNetwork(network.value as NetworkName, __SWAP_DEFAULTS__);
    refund.value = tip.value = age.value = "";
    updateDisclosure();
    updateNetwork();
  };
  updateNetwork();

  let busy = false;
  /** LN to BTC: verified quotes only. Paying a hold invoice is not implemented, so nothing is committed. */
  const reverseQuote = (name: NetworkName): void => {
    let request: Omit<ReverseSwapRequest, "identity">;
    let urls: readonly string[];
    const pinned = identity.value.trim();
    try {
      urls = validateRelays(relay.value.trim(), name);
      if (pinned && !/^[0-9a-f]{64}$/.test(pinned)) {
        throw new Error("Provider identity must be 64 lowercase hex characters, or leave it empty for automatic selection");
      }
      if (!receiveAddress.value.trim()) throw new Error("Enter the Bitcoin address that should receive the payout");
      // Checked now so mistakes surface early; it is not sent until you continue with a swap.
      addressScript(receiveAddress.value, name);
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
    const controls = [...form.elements, ...settings.querySelectorAll("input, textarea, select, button")];
    busy = true;
    for (const control of controls) (control as HTMLInputElement).disabled = true;
    settingsButton.disabled = true;
    const cancellation = new AbortController();
    let arrivals: readonly LocatedQuote<PreparedReverseQuote>[] = [];
    const done = node("button", "Edit swap", "swap-edit");
    done.type = "button";
    const restore = (): void => {
      busy = false;
      for (const control of controls) (control as HTMLInputElement).disabled = false;
      settingsButton.disabled = false;
      updateNetwork();
    };
    done.onclick = () => {
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
        if (eligible.length === 0) throw new Error("No eligible Lightning to Bitcoin provider found. Try another relay or amount.");
        setStatus("Comparing provider estimates", 1);
        report(`Requesting up to ${MAX_QUOTE_PROVIDERS} eligible offers from ${eligible.length} announced providers`);
        const result = await quoteReverseProviders(eligible, request, cancellation.signal);
        arrivals = result.quotes;
        if (cancellation.signal.aborted) return;
        if (arrivals.length === 0) throw new Error("No provider returned acceptable terms. Nothing was paid.");
        const quote = arrivals[0]!.prepared.quote;
        const review = node("div", "", "swap-quote-review");
        review.append(node("p", "Estimated price", "swap-quote-kind"), node("h2", `${quote.holdInvoiceSat.toLocaleString()} sat`),
          node("p", `You pay this over Lightning (plus your wallet's routing fee) and receive ${quote.payoutSat.toLocaleString()} sat on-chain.`),
          node("small", `Provider fee: ${quote.successFeeSat.toLocaleString()} sat. Claim fee reserve: ${quote.claimFeeReserveSat.toLocaleString()} sat. ` +
            `Payout after ${quote.fundingConfirmations} confirmation${quote.fundingConfirmations === 1 ? "" : "s"} (about ${quote.fundingConfirmations * 10} min). ` +
            `If the swap fails, your Lightning payment may stay pending for up to about ${quote.incomingHtlcExpiryDeltaBlocks} blocks. ` +
            `Estimate expires ${new Date(quote.expiresAt * 1000).toLocaleTimeString()}.`),
          node("p", `Lowest estimate among ${arrivals.length} responding provider${arrivals.length === 1 ? "" : "s"}.`, "swap-quote-selection"),
          node("p", "Paying Lightning to Bitcoin swaps in the browser is coming next. Final signed terms are checked before any payment; " +
            "nothing was paid and no address or payment hash was shared.", "swap-reverse-pending"));
        if (directory.warnings.length || result.failures || eligible.length > MAX_QUOTE_PROVIDERS) {
          review.append(node("small", "Some relays or providers did not return complete results. This is not a market-wide best-price guarantee."));
        }
        review.append(done);
        panel.replaceChildren(review);
        setStatus("Estimate ready. Payment is not available yet", 1);
      } catch (error) {
        if (!cancellation.signal.aborted) {
          panel.replaceChildren(node("p", (error as Error).message, "swap-error"), done);
          report(`stopped: ${(error as Error).message}`);
        }
      } finally {
        // Quote-only: discard every offer's private state now.
        for (const quote of arrivals) quote.dispose();
        if (!cancellation.signal.aborted) restore();
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
    settingsButton.disabled = true;
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
      settingsButton.disabled = false;
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
        if (eligible.length === 0) throw new Error("No eligible provider found. Try another relay or pin a provider in Settings.");
        setStatus("Comparing verified provider quotes", 1);
        report(`Requesting up to ${MAX_QUOTE_PROVIDERS} eligible offers from ${eligible.length} announced providers`);
        const result = await quoteProviders(eligible, request, cancellation.signal);
        arrivals = result.quotes;
        if (cancelled) { for (const quote of arrivals) quote.dispose(); return; }
        if (arrivals.length === 0) throw new Error("No provider returned acceptable terms. Nothing was accepted or funded.");
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
        if (wallet) {
          const backupPanel = node("section", "", "swap-quote-backup");
          review.append(backupPanel);
          const refreshBackupGate = async (): Promise<void> => {
            const info = await wallet!.info();
            if (info.fingerprint !== walletFingerprint) throw new Error("Recovery identity changed. Request a fresh quote.");
            accept.disabled = !info.backupVerified;
          };
          await refreshBackupGate();
          if (cancelled) return;
          await walletBackupControls(backupPanel, wallet, undefined, refreshBackupGate);
          if (cancelled) return;
        }
        review.append(offers, accept, cancel);
        panel.replaceChildren(review);
        setStatus("Quote ready. Review before continuing", 1);
        const accepted = await new Promise<LocatedQuote | null>((resolve) => {
          accept.onclick = () => {
            for (const option of offers.querySelectorAll("input")) option.disabled = true;
            accept.disabled = true;
            resolve(selected);
          };
          cancelReview = () => resolve(null);
        });
        if (!accepted || cancelled) return;
        if (wallet) {
          const info = await wallet.info();
          if (!info.backupVerified || info.fingerprint !== walletFingerprint) {
            throw new Error("A matching recovery-key backup must be verified before accepting this quote");
          }
        }
        if (cancelled) return;
        if (Date.now() / 1000 >= accepted.prepared.quote.expiresAt) throw new Error("Quote expired. Request a fresh quote.");
        executing = true;
        for (const quote of arrivals) if (quote !== accepted) quote.dispose();
        arrivals = [accepted];
        const paid = await run(accepted, name, panel, report);
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

function fundingPrompt(panel: HTMLElement, networkName: NetworkName, request: FundingRequest): Promise<string> {
  panel.replaceChildren(
    node("h2", "Fund the swap from your wallet"),
    node("p", "Do not use your wallet's normal Send button: it broadcasts immediately. Instead create a " +
      "transaction, sign and finalize it as a PSBT, and paste it below. The page checks it first."),
    node("p", `The transaction must pay exactly ${btc(request.amountSat)} BTC (${request.amountSat} sat, ` +
      `including a ${request.successFeeSat} sat provider fee) to:`),
    node("pre", scriptAddress(request.contractScript, networkName), "swap-contract-address"),
    node("p", `Keep the network fee at or below ${request.maxFundingFeeSat} sat. Use only native segwit inputs. ` +
      "Sign and finalize in your wallet, then paste the finalized PSBT (base64 or hex) here. Do not broadcast yet. " +
      "In Sparrow: on the Send tab choose Create Transaction, then Finalize Transaction for Signing, then Sign; " +
      "copy or save the signed PSBT as Base64 and do not click Broadcast Transaction. " +
      "In Bitcoin Core, run walletcreatefundedpsbt, then walletprocesspsbt, and copy its psbt field."),
    node("p", `If the provider does not pay, you can refund after block ${request.refundLockHeight}.`),
    node("p", "Pay this address once, in this one transaction. A second payment to it is not a new swap: " +
      "it is never paid over Lightning, the refund tools cover only the bound funding output, and once " +
      "the provider knows the preimage it can claim any output at this address. It may be lost.",
    "swap-second-deposit-warning"),
  );
  const psbtLabel = node("label", "Finalized PSBT (base64 or hex)");
  const psbt = node("textarea", "", "swap-psbt");
  psbtLabel.htmlFor = psbt.id;
  panel.append(psbtLabel, psbt);
  return waitForClick(panel, "Check funding").then(() => psbt.value);
}

async function run(
  quote: LocatedQuote,
  networkName: NetworkName,
  panel: HTMLElement,
  report: (line: string) => void,
): Promise<boolean> {
  let fundsMayBeCommitted = false;
  try {
    report(`Selected provider ${quote.prepared.quote.providerIdentity} via ${quote.relayUrl}`);
    const outcome = await quote.prepared.execute({
      report,
      saveRecovery: async (file, stage) => {
        const name = `rillswap-${stage}-recovery-${Math.floor(Date.now() / 1000)}.age`;
        panel.replaceChildren(node("h2", stage === "terms" ? "Save the recovery file" : "Save the funded recovery file"),
          node("p", stage === "terms"
            ? "It proves the signed terms. Nothing is funded yet."
            : "This file is what lets you refund. Save it before broadcasting."));
        offerDownload(panel, file, name);
        await waitForClick(panel, "I saved the file");
      },
      fundingPsbt: (funding) => fundingPrompt(panel, networkName, funding),
      beforeFundingCommit: async () => { fundsMayBeCommitted = true; },
      broadcast: async (raw, txid) => {
        panel.replaceChildren(
          node("h2", "Broadcast the funding transaction"),
          node("p", `The provider acknowledged funding ${txid}. Broadcast this exact transaction from your wallet ` +
            "or node:"),
          node("pre", raw, "swap-funding-raw"),
          node("p", "Most wallets broadcast a finalized PSBT or raw transaction from a Broadcast or Send " +
            "Transaction menu; with Bitcoin Core use sendrawtransaction."),
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
      node("p", "Optional: keep this paid recovery file as a record of the completed swap."),
    );
    offerDownload(panel, outcome.paidRecovery, `rillswap-paid-recovery-${Math.floor(Date.now() / 1000)}.age`);
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
