/** Explicit browser-only reverse steps. No connection, payment or resume on mount. */
import canonicalize from "canonicalize";
import { BrowserReverseJournal } from "./browserReverseJournal";
import { BrowserHoldPayer } from "./swap/browserHoldPayer";
import { validateMempoolApi, type NetworkName } from "./swap/config";
import { readBoundedChainText, readChainTip } from "./swap/chainTip";
import { parseStrictEventJson } from "./strictEventJson";
import type { PreparedReverseQuote } from "./swap/reverseSwap";
import type { PreparedReverseExecution } from "./swap/reverseExecution";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id = ""): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag); element.textContent = text; if (id) element.id = id; return element;
}
function input(root: HTMLElement, label: string, id: string, value = ""): HTMLInputElement {
  const caption = node("label", label), field = node("input", "", id); field.value = value; field.autocomplete = "off"; field.spellcheck = false;
  caption.htmlFor = id; root.append(caption, field); return field;
}
function check(root: HTMLElement, text: string, id: string): HTMLInputElement {
  const label = node("label", "", id + "-label"), field = node("input", "", id); field.type = "checkbox"; label.append(field, document.createTextNode(text)); root.append(label); return field;
}
function button(root: HTMLElement, text: string, id: string): HTMLButtonElement {
  const control = node("button", text, id); control.type = "button"; root.append(control); return control;
}

export interface ReverseExecutionUiOptions {
  readonly prepared: PreparedReverseQuote;
  readonly network: { readonly name: NetworkName; readonly genesis_hash: string };
  readonly destinationScript: string;
  readonly chainApi: string;
  readonly broadcastApi: string;
  readonly ageRecipient: string;
  readonly nodeApi: string;
  readonly assertCurrent: () => void;
  readonly status: (message: string, step: number) => void;
  readonly download: (root: HTMLElement, file: Uint8Array, name: string) => void;
}

/** Called on the selected provider's explicit Continue action, after matching key-backup verification. */
export async function mountReverseExecution(root: HTMLElement, options: ReverseExecutionUiOptions): Promise<() => void> {
  options = { ...options, network: structuredClone(options.network) };
  let disposed = false;
  const current = (): void => { if (disposed) throw new Error("Execution tab closed"); options.assertCurrent(); }; current();
  const api = validateMempoolApi(options.chainApi, options.network.name), broadcastApi = validateMempoolApi(options.broadcastApi, options.network.name);
  const journal = await BrowserReverseJournal.open(); current();
  let execution: PreparedReverseExecution | undefined;
  const backups = node("section", "", "swap-reverse-backups"), steps = node("section", "", "swap-reverse-steps"), message = node("p", "", "swap-reverse-message");
  root.replaceChildren(backups, steps, message);
  const error = (): void => { message.textContent = "Action stopped. Keep the encrypted backups. An uncertain payment or claim is never retried. Use browser recovery to inspect the saved state."; };
  const act = (control: HTMLButtonElement, work: () => Promise<void>): void => {
    control.onclick = () => { control.disabled = true; message.textContent = ""; void work().catch(error); };
  };
  const download = (file: Uint8Array, stage: string): void => { options.download(backups, file, `rillswap-ln-to-btc-${stage}.age`); };
  const stopped = (): void => { disposed = true; execution?.dispose(); journal.close(); window.removeEventListener("pagehide", stopped); };
  window.addEventListener("pagehide", stopped, { once: true });
  try {
    options.status("Checking signed final terms", 1);
    const tip = await readChainTip(api, options.network); current();
    execution = await options.prepared.prepareExecution({ destinationScript: options.destinationScript, tipHeight: tip.height, ageRecipient: options.ageRecipient, journal, assertCurrent: current }); current();
    const e = execution, terms = e.terms;
    download(e.recoveryFile, "terms");
    steps.append(node("h2", "Final signed price"), node("p", `Pay ${terms.economics.hold_invoice_sat} sat over Lightning, plus the routing fee, to receive at least ${terms.economics.nominal_payout_sat} sat on-chain.`),
      node("small", `Provider fee: ${terms.economics.success_fee_sat} sat. Claim reserve: ${terms.economics.claim_fee_reserve_sat} sat. Funding requires ${terms.funding_confirmations} confirmation(s). Provider refund height: ${terms.refund_lock_height}.`));
    const saved = check(steps, "I saved the encrypted swap backup and verified my recovery-key backup.", "swap-reverse-backup-saved");
    const accept = button(steps, "Accept signed terms", "swap-reverse-accept"); accept.disabled = true; saved.onchange = () => { accept.disabled = !saved.checked; };
    const acknowledge = (): void => { current(); if (!saved.checked) throw new Error("Backup not acknowledged"); };
    act(accept, async () => {
      await e.accept(acknowledge); current(); saved.disabled = true;
      options.status("Signed terms accepted. Connect your Lightning node", 2);
      const nodeSettings = node("details"); nodeSettings.append(node("summary", "Lightning node settings"));
      const endpoint = input(nodeSettings, "LND REST endpoint (direct browser access)", "swap-reverse-node-api", options.nodeApi);
      const identity = input(nodeSettings, "Pinned node compressed public key", "swap-reverse-node-identity"), credential = input(nodeSettings, "Scoped macaroon (hex, this tab only)", "swap-reverse-macaroon"); credential.type = "password";
      const routingFee = input(nodeSettings, "Maximum routing fee (sat)", "swap-reverse-routing-fee", "1000"); routingFee.inputMode = "numeric";
      steps.append(node("p", options.network.name === "regtest" ? "Connect authorizes the disposable regtest node adapter to disclose its scoped credential to this tab. It can spend test Lightning funds. Nothing is paid until you approve the exact route." :
        "Use an LND node with browser-trusted TLS, explicit CORS, and scoped permissions. The credential stays in this tab. No public remote node is supplied."), nodeSettings);
      const connect = button(steps, options.network.name === "regtest" ? "Connect regtest test node" : "Connect configured Lightning node", "swap-reverse-connect");
      act(connect, async () => {
        acknowledge(); const nodeApi = validateMempoolApi(endpoint.value.trim(), options.network.name);
        const feeValue = routingFee.value.trim(); if (!/^(0|[1-9][0-9]{0,15})$/.test(feeValue)) throw new Error("Invalid routing fee");
        let macaroon = credential.value.trim(), key = identity.value.trim();
        if (options.network.name === "regtest" && !macaroon && !key) {
          const signal = AbortSignal.timeout(10000), response = await fetch(nodeApi + "/configuration", { signal, method: "GET", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
          const data = parseStrictEventJson(await readBoundedChainText(response, signal, 16384), 16384) as Record<string, unknown>;
          acknowledge(); if (Object.keys(data).sort().join() !== "macaroon,network_identity,node_identity" || canonicalize(data.network_identity) !== canonicalize(options.network) ||
            typeof data.macaroon !== "string" || typeof data.node_identity !== "string") throw new Error("Node configuration mismatch");
          macaroon = data.macaroon; key = data.node_identity;
        }
        acknowledge(); const payer = new BrowserHoldPayer({ endpoint: nodeApi, macaroon, nodeIdentity: key, network: options.network }); credential.value = "";
        endpoint.disabled = identity.disabled = credential.disabled = routingFee.disabled = true;
        const approval = (): void => { acknowledge(); if (endpoint.value.trim() !== nodeApi || routingFee.value.trim() !== feeValue) throw new Error("Node selection changed"); };
        const plan = await e.planPayment(payer, nodeApi, BigInt(feeValue), approval); approval();
        steps.append(node("p", `Exact route: ${terms.economics.hold_invoice_sat} sat plus ${(BigInt(plan.feeMsat) / 1000n).toString()} sat (${plan.feeMsat} msat) routing fee. Maximum absolute HTLC expiry: block ${plan.limits.maxExpiryHeight}.`));
        const pay = button(steps, "Pay this exact Lightning route once", "swap-reverse-pay");
        act(pay, async () => {
          const result = await e.pay(payer, plan, nodeApi, approval); current();
          options.status(`Payment ${result.toLowerCase().replaceAll("_", " ")}. Checking signed funding evidence`, 3);
          steps.append(node("p", "The payment attempt is durably UNKNOWN even while tracking. Never pay another invoice to recover it. Funding checks and claims are separate explicit actions."));
          const funding = button(steps, "Check provider funding", "swap-reverse-funding");
          const inspectFunding = async (): Promise<void> => {
            try {
              const file = await e.receiveFunding(30000); current(); download(file, "funded"); funding.disabled = true;
              options.status("Funding authenticated. Wait for confirmations, then approve your claim", 3);
              const feeMax = [BigInt(terms.economics.claim_fee_reserve_sat), BigInt(terms.max_claim_fee_sat)].reduce((a, b) => a < b ? a : b);
              const fee = input(steps, "Claim network fee (sat, maximum " + feeMax + ")", "swap-reverse-claim-fee", String(feeMax)); fee.inputMode = "numeric";
              const approved = check(steps, `I approve a claim to the signed payout script ${terms.client_destination_script} at the fee above. Signing uses my private preimage.`, "swap-reverse-claim-approved");
              const prepare = button(steps, "Check confirmations and prepare claim", "swap-reverse-prepare-claim");
              let value = "";
              const claimApproval = (): void => { current(); if (!approved.checked || fee.value.trim() !== value) throw new Error("Claim approval changed"); };
              act(prepare, async () => {
                value = fee.value.trim(); if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) throw new Error("Invalid fee"); claimApproval();
                try {
                  const prepared = await e.prepareClaim(api, BigInt(value), claimApproval); current(); download(prepared.recoveryFile, "claim"); fee.disabled = true;
                  steps.append(node("p", `Prepared claim ${prepared.claim.txid}: ${prepared.claim.outputValueSat} sat to your payout, ${prepared.claim.feeSat} sat network fee (${prepared.claim.vsize} vbytes).`));
                  const expose = check(steps, "I saved the claim backup and approve revealing the preimage in this exact signed transaction. Broadcast sends it to the configured API; downloads can be broadcast by anyone.", "swap-reverse-exposure-approved");
                  const approveExposure = (): void => { claimApproval(); if (!expose.checked) throw new Error("Exposure not approved"); };
                  const broadcast = button(steps, "Broadcast claim once", "swap-reverse-broadcast"), exportClaim = button(steps, "Download exact signed claim", "swap-reverse-export");
                  let confirmation: HTMLButtonElement | undefined;
                  const exposeAction = async (action: "download" | "broadcast"): Promise<void> => {
                    approveExposure(); const result = await e.exposeClaim(api, broadcastApi, action, approveExposure); current();
                    broadcast.disabled = true;
                    if (result.transactionHex) options.download(backups, new TextEncoder().encode(result.transactionHex), "rillswap-signed-claim.hex");
                    // Only identical manual re-export stays available after exposure.
                    exportClaim.disabled = false;
                    options.status(`Claim ${result.outcome}: ${result.txid}`, result.outcome === "accepted" ? 4 : 3);
                    message.textContent = result.outcome === "accepted" ? "Claim broadcast accepted. Chain confirmation and Lightning settlement still need verification." : "Claim exposure outcome is unknown or exported. The app will not submit it again. Preserve these exact bytes.";
                    if (!confirmation) {
                      confirmation = button(steps, "Check claim confirmation and Lightning settlement", "swap-reverse-settlement");
                      const check = confirmation;
                      act(check, async () => {
                        try {
                          current(); const signal = AbortSignal.timeout(15000), tip = await readChainTip(api, options.network, { signal }); current();
                          const response = await fetch(`${api}/tx/${result.txid}/status`, { signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
                          const inclusion = parseStrictEventJson(await readBoundedChainText(response, signal, 4096), 4096) as Record<string, unknown>; current();
                          if (inclusion.confirmed !== true || typeof inclusion.block_height !== "number" || !Number.isSafeInteger(inclusion.block_height) || inclusion.block_height < 1 ||
                            inclusion.block_height > tip.height || typeof inclusion.block_hash !== "string" || !/^[0-9a-f]{64}$/.test(inclusion.block_hash)) throw new Error("Claim not confirmed");
                          const blockResponse = await fetch(`${api}/block-height/${inclusion.block_height}`, { signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
                          if (await readBoundedChainText(blockResponse, signal, 64) !== inclusion.block_hash) throw new Error("Claim chain mismatch");
                          const payment = await payer.status(plan.paymentHash, plan.invoiceBinding.amount_msat); current();
                          if (payment === "SUCCEEDED") {
                            options.status("Swap complete. Bitcoin claim confirmed and Lightning payment settled", 4);
                            message.textContent = `Trusted API observed ${tip.height - inclusion.block_height + 1} claim confirmation(s). Your pinned Lightning node reports payment succeeded. Keep all recovery backups.`;
                          } else message.textContent = `Claim confirmed according to the trusted API. Lightning payment: ${payment.toLowerCase()}. No payment will be retried.`;
                        } catch { message.textContent = "Confirmation or settlement evidence is not available yet. Check again without resubmitting the payment or claim."; }
                        finally { check.disabled = false; }
                      });
                    }
                  };
                  act(broadcast, () => exposeAction("broadcast")); act(exportClaim, () => exposeAction("download"));
                } catch { error(); if (e.record.stage === "funded") prepare.disabled = false; }
              });
            } catch { funding.disabled = false; message.textContent = "No usable signed funding evidence yet. Check again without making another payment."; }
          };
          act(funding, inspectFunding);
          // Receive-only waiting follows payment; it cannot pay, sign or broadcast.
          funding.disabled = true; await inspectFunding();
        });
      });
    });
    return stopped;
  } catch { stopped(); error(); return stopped; }
}
