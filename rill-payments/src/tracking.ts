import type { createCheckout } from "./sdk";

const LABELS = {
  ready: "Payment ready", observing: "Payment sent, waiting for merchant receipt", action_required: "Action required, keep tracking this attempt",
  merchant_paid: "Merchant receipt verified", reconciliation: "Receipt requires merchant review",
};
/** Hostable native checkout status component; no HTML injection or automatic signing. */
export function mountTracking(root: HTMLElement, checkout: ReturnType<typeof createCheckout>): () => void {
  const status = document.createElement("p"); status.setAttribute("role", "status"); status.textContent = "Loading payment status";
  const refresh = document.createElement("button"); refresh.type = "button"; refresh.textContent = "Refresh payment status";
  const update = async (): Promise<void> => { refresh.disabled = true;
    try { await checkout.open(); } catch { status.textContent = "Status unavailable, retry without sending another payment"; }
    finally { refresh.disabled = false; }
  };
  const unsubscribe = checkout.on("progress", (progress) => { status.textContent = LABELS[progress.state]; });
  refresh.addEventListener("click", update); root.replaceChildren(status, refresh); void update();
  return () => { unsubscribe(); refresh.removeEventListener("click", update); root.replaceChildren(); };
}
