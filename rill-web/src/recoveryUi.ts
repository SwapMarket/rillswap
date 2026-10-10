/** Explicit local recovery import. Never uploads, stores imports, signs, or broadcasts. */
import { MAX_RECOVERY_CIPHERTEXT_BYTES } from "./recoveryAgeContainer";
import { decryptRecoveryContainer } from "./recoveryKeys";
import { inspectRecoveryPlaintext, type RecoveryInspection } from "./recoveryInspection";
import { observeRecoveryFunding } from "./recoveryFunding";
import type { NetworkName } from "./swap/config";

interface RecoveryUiOptions {
  /** Chosen by the user outside the file, including the complete chain identity. */
  readonly selectedNetwork: () => { readonly name: string; readonly identity: unknown };
  readonly browserIdentity: () => Promise<string>;
  readonly selectedChainApi: () => string;
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = text;
  if (id) node.id = id;
  return node;
}

/** Public controls needed by the owning Settings UI, without exposing imported state. */
interface RecoveryPanel {
  readonly element: HTMLElement;
  clearFundingObservation(): void;
}

/** A collapsed panel with local imports and explicitly requested, report-only chain reads. */
export function recoveryPanel(options: RecoveryUiOptions): RecoveryPanel {
  const details = element("details", "", "swap-recovery");
  details.append(element("summary", "Recover a swap"), element("p",
    "Open an encrypted BTC to Lightning recovery file using your saved browser key. " +
    "Choose the original swap's network in Settings. Files and keys stay on this device."));
  const fileLabel = element("label", "Encrypted swap recovery file (.age)");
  const file = element("input", "", "swap-recovery-file");
  file.type = "file";
  file.accept = ".age";
  fileLabel.htmlFor = file.id;
  details.append(fileLabel, file);
  const olderKey = element("details");
  olderKey.append(element("summary", "Use an older recovery key (optional)"), element("p",
    "For an older or externally encrypted swap, select its original age key file. " +
    "This does not replace your browser's saved key."));
  const keyLabel = element("label", "Original age key file (.key or .age-key)");
  const keyFile = element("input", "", "swap-recovery-key-file");
  keyFile.type = "file";
  keyFile.accept = ".key,.age-key,.txt";
  keyLabel.htmlFor = keyFile.id;
  olderKey.append(keyLabel, keyFile);
  const inspect = element("button", "Inspect recovery file", "swap-recovery-inspect");
  inspect.type = "button";
  const result = element("section", "", "swap-recovery-result");
  result.setAttribute("aria-live", "polite");
  const fundingControls = element("section", "", "swap-recovery-funding-controls");
  fundingControls.hidden = true;
  const revisionLabel = element("label", "Recorded funding revision");
  const revision = element("select", "", "swap-recovery-revision");
  revisionLabel.htmlFor = revision.id;
  const check = element("button", "Check funding", "swap-recovery-check-funding");
  check.type = "button";
  const fundingResult = element("section", "", "swap-recovery-funding-result");
  fundingResult.setAttribute("aria-live", "polite");
  fundingControls.append(revisionLabel, revision, element("p",
    "Check funding connects to the API selected in Settings for this attempt. It sends the selected public transaction ID, never your recovery file or key."), check, fundingResult);
  details.append(olderKey, inspect, result, fundingControls);
  let busy = false;
  let inspected: RecoveryInspection | undefined;
  let pendingInvalidated = false;

  const clear = (): void => {
    if (!busy) { result.replaceChildren(); fundingResult.replaceChildren(); fundingControls.hidden = true; inspected = undefined; }
  };
  file.onchange = keyFile.onchange = clear;
  const show = (report: RecoveryInspection): void => {
    inspected = report;
    revision.replaceChildren(...report.fundingHistory.map((binding) => Object.assign(element("option",
      `Revision ${binding.binding_revision} · ${binding.funding_txid.slice(0, 12)}...`), { value: String(binding.binding_revision) })));
    revision.value = String(report.fundingHistory.at(-1)?.binding_revision ?? "");
    revisionLabel.hidden = revision.hidden = report.fundingHistory.length <= 1;
    fundingControls.hidden = report.fundingHistory.length === 0;
    fundingResult.replaceChildren();
    result.replaceChildren(element("h3", "Recovery record verified"),
      element("p", `${report.networkName} · BTC to Lightning · ${report.recordedBindingCount} recorded funding revision${report.recordedBindingCount === 1 ? "" : "s"}.`),
      element("p", `The signed refund lock is block ${report.refundLockHeight}. The first eligible block is ${report.firstRefundEligibleHeight}.`),
      element("p", "This verifies consistency with the file's embedded signers, not its provenance or your ownership of the refund address. " +
        "Funding, unspent state, and refund maturity have not been checked."),
      element("p", "Browser refund signing and broadcasting are not available yet. Local inspection did not connect, sign, or broadcast."));
  };
  inspect.onclick = () => {
    if (busy) return;
    // Snapshot file objects and the independent network before the first await.
    const selectedFile = file.files?.[0], selectedKey = keyFile.files?.[0];
    const selected = options.selectedNetwork();
    const expectedNetwork = structuredClone(selected.identity);
    if (!selectedFile || selectedFile.size === 0 || selectedFile.size > MAX_RECOVERY_CIPHERTEXT_BYTES ||
      (selectedKey && (selectedKey.size === 0 || selectedKey.size > 4096))) {
      result.replaceChildren(element("p", "Choose a nonempty encrypted recovery file (at most 256 KiB) and, if needed, an age key file (at most 4 KiB)."));
      return;
    }
    busy = true;
    inspected = undefined; fundingControls.hidden = true; fundingResult.replaceChildren();
    file.disabled = keyFile.disabled = inspect.disabled = true;
    result.replaceChildren(element("p", "Opening and verifying locally..."));
    void (async () => {
      let plaintext: Uint8Array | undefined;
      try {
        const identity = selectedKey ? await selectedKey.text() : await options.browserIdentity();
        plaintext = await decryptRecoveryContainer(new Uint8Array(await selectedFile.arrayBuffer()), identity);
        const report = inspectRecoveryPlaintext(plaintext, expectedNetwork);
        if (options.selectedNetwork().name !== selected.name || file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey) throw new Error("Selection changed");
        show(report);
      } catch {
        // No parser/crypto/wallet error, raw input, path, filename, or secret becomes a UI diagnostic.
        result.replaceChildren(element("p", "Could not verify this recovery file. Check the selected network and original recovery key. " +
          "Keep your original backups; nothing was changed or uploaded."));
      } finally {
        // Best-effort byte clearing, not a guarantee for immutable strings or decrypter copies.
        plaintext?.fill(0);
        busy = false;
        file.disabled = keyFile.disabled = inspect.disabled = false;
      }
    })();
  };
  revision.onchange = () => fundingResult.replaceChildren();
  check.onclick = () => {
    if (busy || !inspected) return;
    const selectedFile = file.files?.[0], selectedKey = keyFile.files?.[0];
    const selected = options.selectedNetwork(), expectedNetwork = structuredClone(selected.identity);
    const selectedRevision = revision.value;
    const binding = inspected.fundingHistory.find((item) => String(item.binding_revision) === selectedRevision);
    if (!selectedFile || !binding || selectedFile.size === 0 || selectedFile.size > MAX_RECOVERY_CIPHERTEXT_BYTES ||
      (selectedKey && (selectedKey.size === 0 || selectedKey.size > 4096))) return;
    let api: string;
    try { api = options.selectedChainApi(); }
    catch { fundingResult.replaceChildren(element("p", "Check the chain API in Settings. No connection was made.")); return; }
    busy = true;
    pendingInvalidated = false;
    file.disabled = keyFile.disabled = inspect.disabled = check.disabled = revision.disabled = true;
    fundingResult.replaceChildren(element("p", "Checking funding with your selected API..."));
    void (async () => {
      let plaintext: Uint8Array | undefined;
      try {
        const identity = selectedKey ? await selectedKey.text() : await options.browserIdentity();
        plaintext = await decryptRecoveryContainer(new Uint8Array(await selectedFile.arrayBuffer()), identity);
        const observation = await observeRecoveryFunding(plaintext, expectedNetwork as { name: NetworkName; genesis_hash: string },
          { fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision }, api);
        if (pendingInvalidated || options.selectedNetwork().name !== selected.name || options.selectedChainApi() !== api || revision.value !== selectedRevision ||
          file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey) throw new Error("Selection changed");
        fundingResult.replaceChildren(element("h3", "Funding observed by your API"),
          element("p", `${observation.confirmations} confirmation${observation.confirmations === 1 ? "" : "s"} · observed tip ${observation.tipHeight}.`),
          element("p", observation.refundMatureAtObservedTip ? "The refund lock has passed at this observed tip." :
            `Waiting for a tip above block ${observation.refundLockHeight}. The refund lock has not passed yet.`),
          element("p", "Repeated API responses agree on confirmed, unspent funding. These are trusted observations, not independent chain proof or permission to sign."),
          element("p", "Nothing was signed or broadcast. Browser refund actions are not available yet."));
      } catch {
        fundingResult.replaceChildren(element("p", "Funding could not be verified for the current selection. Check the file, key, network, API, and revision, then try again. Nothing was signed or broadcast."));
      } finally {
        plaintext?.fill(0); busy = false;
        file.disabled = keyFile.disabled = inspect.disabled = check.disabled = revision.disabled = false;
      }
    })();
  };
  return { element: details, clearFundingObservation() { pendingInvalidated = true; fundingResult.replaceChildren(); } };
}
