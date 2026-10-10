/** Explicit local recovery import. Never uploads, stores imports, signs, or broadcasts. */
import { MAX_RECOVERY_CIPHERTEXT_BYTES } from "./recoveryAgeContainer";
import { decryptRecoveryContainer } from "./recoveryKeys";
import { inspectRecoveryPlaintext, type RecoveryInspection } from "./recoveryInspection";

interface RecoveryUiOptions {
  /** Chosen by the user outside the file, including the complete chain identity. */
  readonly selectedNetwork: () => { readonly name: string; readonly identity: unknown };
  readonly browserIdentity: () => Promise<string>;
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = text;
  if (id) node.id = id;
  return node;
}

/** A collapsed panel with a local-only, report-only boundary. */
export function recoveryPanel(options: RecoveryUiOptions): HTMLElement {
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
  details.append(olderKey, inspect, result);
  let busy = false;

  const clear = (): void => { if (!busy) result.replaceChildren(); };
  file.onchange = keyFile.onchange = clear;
  const show = (report: RecoveryInspection): void => {
    result.replaceChildren(element("h3", "Recovery record verified"),
      element("p", `${report.networkName} · BTC to Lightning · ${report.recordedBindingCount} recorded funding revision${report.recordedBindingCount === 1 ? "" : "s"}.`),
      element("p", `The signed refund lock is block ${report.refundLockHeight}. The first eligible block is ${report.firstRefundEligibleHeight}.`),
      element("p", "This verifies consistency with the file's embedded signers, not its provenance or your ownership of the refund address. " +
        "Funding, unspent state, and refund maturity have not been checked."),
      element("p", "Browser refund signing and broadcasting are not available yet. Nothing was scanned, signed, or sent."));
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
    file.disabled = keyFile.disabled = inspect.disabled = true;
    result.replaceChildren(element("p", "Opening and verifying locally..."));
    void (async () => {
      let plaintext: Uint8Array | undefined;
      try {
        const identity = selectedKey ? await selectedKey.text() : await options.browserIdentity();
        plaintext = await decryptRecoveryContainer(new Uint8Array(await selectedFile.arrayBuffer()), identity);
        const report = inspectRecoveryPlaintext(plaintext, expectedNetwork);
        if (options.selectedNetwork().name !== selected.name) throw new Error("Network changed");
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
  return details;
}
