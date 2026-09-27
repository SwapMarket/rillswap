/**
 * Experimental browser BTC to LN client page. Everything sensitive stays in
 * this tab's memory; the user's own wallet funds and broadcasts, and the
 * user's own downloads hold the age-encrypted recovery files.
 */
import "./style.css";
import regtest from "./networks/regtest-rillswap-e2e-v1.json";
import signet from "./networks/signet.json";
import testnet4 from "./networks/testnet4.json";
import { addressScript, scriptAddress } from "./swap/address";
import { RelayConnection } from "./swap/relay";
import { type FundingRequest, runSwap, type SwapRequest } from "./swap/swap";

const NETWORKS = { signet, testnet4, regtest } as const;
type NetworkName = keyof typeof NETWORKS;

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
  root.replaceChildren(
    node("h1", "Pay a Lightning invoice with on-chain BTC"),
    node("p", "Experimental. Signet, testnet4, and regtest only; mainnet is refused until release acceptance. " +
      "Keys live only in this tab. Keep it open until the swap finishes."),
    node("p", "Before funding you download an age-encrypted recovery file. If the provider does not pay, " +
      "refund after the refund height with `rill recover watch-refund` on the funded recovery file."),
  );
  const form = node("form", "", "swap-form");
  const networkLabel = node("label", "Network");
  const network = node("select", "", "swap-network");
  networkLabel.htmlFor = network.id;
  for (const name of Object.keys(NETWORKS)) network.append(Object.assign(node("option", name), { value: name }));
  form.append(networkLabel, network);
  const relay = field(form, "swap-relay", "Relay (wss://)", "", "The relay the provider announces on.");
  const identity = field(form, "swap-provider", "Provider identity (x-only public key, hex)");
  const invoice = field(form, "swap-invoice", "Lightning invoice to pay (BOLT11)");
  const refund = field(form, "swap-refund", "Your refund address (P2WPKH or P2TR)");
  const tip = field(form, "swap-tip", "Current block height", "", "From a block explorer or your node; " +
    "it caps how long your funds can be locked.");
  const age = field(form, "swap-age", "Recovery file age recipient (age1...)", "",
    "The files are encrypted to this key; keep its identity safe.");
  const successFee = field(form, "swap-success-fee", "Maximum provider fee (sat)", "2000");
  const fundingFee = field(form, "swap-funding-fee", "Maximum funding fee (sat)", "5000");
  const claimFee = field(form, "swap-claim-fee", "Maximum claim fee (sat)", "5000");
  const refundFee = field(form, "swap-refund-fee", "Maximum refund fee (sat)", "5000");
  const delay = field(form, "swap-delay", "Maximum refund delay (blocks)", "288");
  const start = node("button", "Start swap", "swap-start");
  start.type = "submit";
  form.append(start);
  const panel = node("div", "", "swap-panel");
  const log = node("pre", "", "swap-log");
  root.append(form, panel, log);
  const report = (line: string): void => {
    log.textContent += `${line}\n`;
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const name = network.value as NetworkName;
    let request: SwapRequest;
    try {
      request = {
        identity: identity.value.trim(),
        network: NETWORKS[name],
        invoice: invoice.value.trim(),
        refundScript: addressScript(refund.value, name),
        tipHeight: Number(positive(tip, "block height")),
        ageRecipient: age.value.trim(),
        limits: {
          maxSuccessFeeSat: positive(successFee, "provider fee"),
          maxFundingFeeSat: positive(fundingFee, "funding fee"),
          maxClaimFeeSat: positive(claimFee, "claim fee"),
          maxRefundFeeSat: positive(refundFee, "refund fee"),
          maxRefundDelayBlocks: Number(positive(delay, "refund delay")),
        },
      };
    } catch (error) {
      report(`refused: ${(error as Error).message}`);
      return;
    }
    for (const input of form.elements) (input as HTMLInputElement).disabled = true;
    const guard = (unload: BeforeUnloadEvent): void => unload.preventDefault();
    window.addEventListener("beforeunload", guard);
    void run(relay.value, name, request, panel, report).finally(() => {
      window.removeEventListener("beforeunload", guard);
    });
  });
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
    node("p", `Send exactly ${btc(request.amountSat)} BTC (${request.amountSat} sat, including a ` +
      `${request.successFeeSat} sat provider fee) to:`),
    node("pre", scriptAddress(request.contractScript, networkName), "swap-contract-address"),
    node("p", `Keep the network fee at or below ${request.maxFundingFeeSat} sat. Use only native segwit inputs. ` +
      "Sign and finalize in your wallet, then paste the finalized PSBT (base64 or hex) here. Do not broadcast yet."),
    node("p", `If the provider does not pay, you can refund after block ${request.refundLockHeight}.`),
    node("p", "Pay this address once, in this one transaction. A second payment to it is not a new swap: " +
      "it is never paid over Lightning, the refund tools cover only the bound funding output, and once " +
      "the provider knows the preimage it can claim any output at this address. It may be lost.",
    "swap-second-deposit-warning"),
  );
  const psbt = node("textarea", "", "swap-psbt");
  panel.append(psbt);
  return waitForClick(panel, "Check funding").then(() => psbt.value);
}

async function run(
  relayUrl: string,
  networkName: NetworkName,
  request: SwapRequest,
  panel: HTMLElement,
  report: (line: string) => void,
): Promise<void> {
  let relay: RelayConnection | null = null;
  try {
    relay = await RelayConnection.open(relayUrl);
    report("relay connected");
    const outcome = await runSwap(relay, request, {
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
      broadcast: async (raw, txid) => {
        panel.replaceChildren(
          node("h2", "Broadcast the funding transaction"),
          node("p", `The provider acknowledged funding ${txid}. Broadcast this exact transaction from your wallet ` +
            "or node:"),
          node("pre", raw, "swap-funding-raw"),
        );
        await waitForClick(panel, "I broadcast it");
        panel.replaceChildren(node("p", "Waiting for the provider to pay the invoice..."));
      },
    });
    panel.replaceChildren(
      node("h2", "Invoice paid"),
      node("p", "The provider paid the invoice; this preimage proves it:"),
      node("pre", outcome.preimage, "swap-preimage"),
    );
  } catch (error) {
    const message = (error as Error).message;
    panel.replaceChildren(node("h2", "Swap stopped"), node("p", message, "swap-error"));
    report(`stopped: ${message}`);
  } finally {
    relay?.close();
  }
}

const root = document.getElementById("swap");
if (!root) throw new Error("Static application root missing");
mount(root);
