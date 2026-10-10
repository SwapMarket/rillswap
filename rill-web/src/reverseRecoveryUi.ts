/** Imported reverse controls remain disconnected until an explicit action. */
import { inspectReverseRecoveryPlaintext } from "./recoveryInspection";
import { observeReverseRecoveryFunding } from "./recoveryFunding";
import { loadBrowserReverseRecovery, recoverBrowserReverseFunding, prepareRecoveredReverseClaim, exposeRecoveredReverseClaim } from "./browserReverseRecovery";
import { scriptAddress } from "./swap/address";
import type { NetworkName } from "./swap/config";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id = ""): HTMLElementTagNameMap[K] { const e = document.createElement(tag); e.textContent = text; if (id) e.id = id; return e; }
function button(root: HTMLElement, text: string, id: string): HTMLButtonElement { const e = node("button", text, id); e.type = "button"; root.append(e); return e; }
function download(root: HTMLElement, file: Uint8Array, name: string): void { const e = node("a", "Download " + name); e.href = URL.createObjectURL(new Blob([Uint8Array.from(file)])); e.download = name; root.append(e); }

export function reverseRecoveryControls(root: HTMLElement, options: {
  readonly plaintext: Uint8Array; readonly identity: string; readonly network: { readonly name: NetworkName; readonly genesis_hash: string };
  readonly chainApi: () => string; readonly broadcastApi: () => string; readonly relays: () => readonly string[]; readonly assertCurrent: () => void;
}): () => void {
  const document = Uint8Array.from(options.plaintext), network = structuredClone(options.network); let disposed = false, busy = false;
  const current = (): void => { if (disposed) throw new Error("Selection changed"); options.assertCurrent(); };
  const report = inspectReverseRecoveryPlaintext(document, network), message = node("p", "", "swap-reverse-recovery-message"), controls = node("section"), files = node("section");
  let confirmSaved: (saved: { claimTxid: string | null; claimFeeSat: string | null; stage: string }) => void = () => {};
  root.replaceChildren(node("h3", "Lightning to Bitcoin recovery verified"), node("p", `${report.networkName} · ${report.fundingHistory.length} signed funding revision(s). Payout: ${scriptAddress(report.destinationScript, report.networkName)}.`),
    node("p", "This proves internal consistency under embedded signers, not provenance, ownership or current funding. Nothing connected or was paid. Recovery never accepts or pays another invoice."), controls, files, message);
  const act = (control: HTMLButtonElement, run: () => Promise<void>): void => { control.onclick = () => {
    if (busy || disposed) return; busy = true; control.disabled = true;
    void run().catch(() => { message.textContent = "Recovery remains blocked for this selection. Keep the originals. No uncertain payment or claim will be retried."; })
      .finally(() => { busy = false; if (!disposed) control.disabled = control.dataset.locked === "true"; });
  }; };
  const local = button(controls, "Inspect local execution state", "swap-reverse-recovery-local");
  act(local, async () => { current(); const saved = await loadBrowserReverseRecovery(document, options.identity, network); current();
    message.textContent = `Local state: ${saved.stage}. This is not a new payment authorization.`; download(files, saved.ciphertext, "rillswap-reverse-latest.age"); confirmSaved(saved); });
  const archive = button(controls, "Recover signed funding from selected relays", "swap-reverse-recovery-archive");
  controls.append(node("small", "Archive lookup uses the original recipient key. It publishes nothing. Missing signed evidence cannot be inferred from a UTXO."));
  act(archive, async () => { current(); const relays = [...options.relays()], captured = relays.join("\n");
    const approve = (): void => { current(); if (options.relays().join("\n") !== captured) throw new Error("Relays changed"); };
    const file = await recoverBrowserReverseFunding(document, options.identity, network, relays, approve); approve();
    download(files, file, "rillswap-reverse-funded.age"); message.textContent = "Save and inspect this funded backup before continuing."; });
  if (report.fundingHistory.length) {
    const binding = report.fundingHistory.at(-1)!, selection = { fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision };
    const check = button(controls, "Check reverse funding with selected API", "swap-reverse-recovery-check");
    act(check, async () => { current(); const api = options.chainApi(), observation = await observeReverseRecoveryFunding(document, network, selection, api); current();
      if (options.chainApi() !== api) throw new Error("API changed"); message.textContent = `Trusted API: ${observation.confirmations} confirmations at block ${observation.tipHeight}. Required claim margin: ${report.claimConfirmationBlocks} blocks before first provider refund block ${report.refundLockHeight + 1}. This is not independent chain proof.`; });
    const feeLabel = node("label", "Claim network fee (sat)"), fee = node("input", "", "swap-reverse-recovery-fee"); fee.type = "number"; fee.min = "0";
    fee.value = report.fallbackFeeSat ?? String(BigInt(report.maxClaimFeeSat) < BigInt(report.claimFeeReserveSat) ? BigInt(report.maxClaimFeeSat) : BigInt(report.claimFeeReserveSat)); feeLabel.htmlFor = fee.id;
    const approved = node("input", "", "swap-reverse-recovery-approved"); approved.type = "checkbox";
    const label = node("label", "I recognize this file, control the fixed payout address and approve this fee. I saved the funded backup. Prior exposure may be UNKNOWN; exporting or broadcasting reveals my preimage."); label.htmlFor = approved.id;
    controls.append(feeLabel, fee, approved, label);
    const prepare = button(controls, "Approve and prepare recovery claim", "swap-reverse-recovery-prepare");
    const claimSaved = node("input", "", "swap-reverse-recovery-claim-saved"); claimSaved.type = "checkbox"; claimSaved.disabled = true;
    const claimSavedLabel = node("label", "First prepare a claim or inspect local execution state to obtain its exact encrypted backup."); claimSavedLabel.htmlFor = claimSaved.id;
    controls.append(claimSaved, claimSavedLabel); let savedClaimTxid = "";
    confirmSaved = (saved) => {
      claimSaved.checked = false; savedClaimTxid = saved.claimTxid ?? ""; claimSaved.disabled = !savedClaimTxid;
      if (saved.claimFeeSat !== null) fee.value = saved.claimFeeSat;
      claimSavedLabel.textContent = savedClaimTxid ? `I saved the exact encrypted backup for claim ${savedClaimTxid} and approve revealing its preimage by export or broadcast.` : "No exact claim backup is prepared yet.";
      if (saved.stage === "claim-unknown" || saved.stage === "accepted") { broadcast.dataset.locked = "true"; broadcast.disabled = true; }
    };
    fee.oninput = approved.onchange = () => { claimSaved.checked = false; };
    const capturedApproval = (): { feeSat: bigint; api: string; broadcastApi: string; check: () => void } => {
      const value = fee.value, api = options.chainApi(), broadcastApi = options.broadcastApi();
      if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) throw new Error("Invalid fee");
      const check = (): void => { current(); if (!approved.checked || fee.value !== value || options.chainApi() !== api || options.broadcastApi() !== broadcastApi) throw new Error("Approval changed"); };
      check(); return { feeSat: BigInt(value), api, broadcastApi, check };
    };
    act(prepare, async () => { const approval = capturedApproval();
      const file = await prepareRecoveredReverseClaim(document, options.identity, network, approval.api, approval.feeSat, approval.check); approval.check();
      download(files, file, "rillswap-reverse-claim.age");
      const saved = await loadBrowserReverseRecovery(document, options.identity, network); approval.check(); confirmSaved(saved);
      message.textContent = "Exact claim bytes are saved, not yet exposed. Save the claim backup and acknowledge it separately before exporting or broadcasting."; });
    const exportClaim = button(controls, "Approve and download exact saved claim", "swap-reverse-recovery-export"), broadcast = button(controls, "Approve and broadcast saved claim once", "swap-reverse-recovery-broadcast");
    const expose = async (action: "download" | "broadcast"): Promise<void> => { const approval = capturedApproval(), claimTxid = savedClaimTxid;
      const exposureApproved = (): void => { approval.check(); if (!claimSaved.checked || !claimTxid || savedClaimTxid !== claimTxid) throw new Error("Exact claim backup not acknowledged"); };
      exposureApproved(); broadcast.dataset.locked = "true"; broadcast.disabled = true;
      const result = await exposeRecoveredReverseClaim(document, options.identity, network, approval.api, approval.broadcastApi, approval.feeSat, claimTxid, action, exposureApproved); exposureApproved();
      if (result.transactionHex) download(files, new TextEncoder().encode(result.transactionHex), "rillswap-recovered-claim.hex");
      broadcast.disabled = true; message.textContent = `Claim ${result.outcome}: ${result.txid}. Exposure remains UNKNOWN; only identical manual export is available afterward.`;
    };
    act(exportClaim, () => expose("download")); act(broadcast, () => expose("broadcast"));
  }
  return () => { disposed = true; document.fill(0); };
}
