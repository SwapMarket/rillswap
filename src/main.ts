import "./style.css";
import { mountManualProviderImport } from "./manualProviderImportUi";
import { testBrowserStorage, type ProbeResult } from "./storageProbe";

const BUILD_ID = "0.1.0-dev.0";
const MAX_DESCRIPTION_LENGTH = 2000;

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = text;
  return node;
}

function storageMessage(result: ProbeResult): string {
  if (!result.roundTrip) return "Storage round-trip failed. " +
    `Diagnostic cleanup: ${result.cleanup ? "complete" : "unconfirmed"}. ` +
    "No financial actions are available.";
  const persistence = result.persistence === "granted" ? "yes" :
    result.persistence === "denied" ? "no" : "unavailable";
  return `Storage round-trip succeeded. Persistence granted: ${persistence}. ` +
    `Cleanup: ${result.cleanup ? "complete" : "unconfirmed"}. ` +
    "This does not guarantee survival of clearing, eviction, crashes, or device loss.";
}

function mount(root: HTMLElement): void {
  root.replaceChildren();
  root.append(
    element("h1", "RillSwap"),
    element("p", "Local-only development preview. Swaps, signing, payments, and recovery are not implemented. Do not enter secrets or send funds."),
    element("p", `Build: ${BUILD_ID}. This preview does not check for updates. Reloading a mutable website could still change its code.`),
  );

  const modeLabel = element("label", "Chain mode (preview only)");
  const mode = document.createElement("select");
  mode.id = "chain-mode";
  for (const [value, label] of [
    ["unselected", "Choose a mode"],
    ["own-node", "Own node (restricted local agent required)"],
    ["remote-chain-source", "Remote chain source (trust disclosed)"],
  ] as const) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    mode.append(option);
  }
  modeLabel.htmlFor = mode.id;
  const modeNotice = element("p", "Selecting a chain mode does not connect to or verify a chain source.");
  mode.addEventListener("change", () => {
    modeNotice.textContent = mode.value === "remote-chain-source"
      ? "Remote chain sources require disclosed trust and do not provide full consensus verification. No connection is made."
      : "Selecting a chain mode does not connect to or verify a chain source.";
  });
  root.append(modeLabel, mode, modeNotice);

  const descriptionLabel = element("label", "Untrusted provider description preview (no network access)");
  const description = document.createElement("textarea");
  description.id = "provider-description";
  description.maxLength = MAX_DESCRIPTION_LENGTH;
  description.placeholder = "Paste public test text only. Never paste secrets.";
  descriptionLabel.htmlFor = description.id;
  const rendered = element("pre", "");
  rendered.id = "provider-text";
  description.addEventListener("input", () => {
    rendered.textContent = description.value.slice(0, MAX_DESCRIPTION_LENGTH);
  });
  root.append(descriptionLabel, description, rendered);

  const probe = element("button", "Test browser storage");
  probe.type = "button";
  const status = element("p", "Storage not tested. A missing record proves nothing about durability or past swaps.");
  status.id = "storage-status";
  const explanation = element("p", "This explicit test writes and deletes synthetic diagnostic data and may request persistent browser storage. It never tests encrypted swap records or authorizes commitment.");
  probe.addEventListener("click", () => {
    probe.disabled = true;
    status.textContent = "Testing synthetic browser storage…";
    void testBrowserStorage().then((result) => {
      status.textContent = storageMessage(result);
    }).catch(() => {
      status.textContent = "Storage diagnostic failed. No financial actions are available.";
    }).finally(() => {
      probe.disabled = false;
    });
  });
  root.append(probe, status, explanation);
  mountManualProviderImport(root);
}

const root = document.getElementById("app");
if (!root) throw new Error("Static application root missing");
mount(root);
