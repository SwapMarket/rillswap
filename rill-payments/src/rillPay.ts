/** Reusable RillPay presentation. Merchant policy and order creation stay with the host. */
export interface RillPayMethod {
  readonly id: string;
  readonly label: string;
  readonly network: string;
  readonly available: boolean;
  readonly unavailableReason: string | null;
  readonly price: string | null;
  readonly merchantFee: string | null;
  readonly providerFee: string | null;
  readonly walletFee: string | null;
  readonly confirmationTime: string | null;
  /** Estimated total cost in USD cents including merchant and provider/swap fees, or null when unknown. Drives the cheapest highlight. */
  readonly usdCents: number | null;
  /** Approximate minutes until the merchant can confirm the payment, or null when unknown. 0 means under a minute. */
  readonly minutesToConfirmation: number | null;
}

export interface RillPayCheckout {
  readonly merchant: string;
  readonly item: string;
  readonly total: string;
  readonly methods: readonly RillPayMethod[];
  /** Resolves when the host has created and displayed payment instructions, not when paid. */
  readonly onPay: (methodId: string) => Promise<void>;
  /** Called on Cancel, Escape, or a click outside the dialog. Without it the checkout cannot be dismissed by the buyer. */
  readonly onCancel?: () => void;
}

const STYLE = `
.rillpay-overlay{position:fixed;inset:0;z-index:2147483000;display:grid;place-items:center;padding:16px;overflow:auto;background:#0f2a2180;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
.rillpay{font:15px/1.5 system-ui,sans-serif;color:#17372f;background:#f8fcfa;border:1px solid #cfe1d8;border-radius:24px;padding:24px;width:100%;max-width:640px;max-height:calc(100vh - 32px);overflow:auto;box-shadow:0 24px 70px #0b241a40;outline:0}
.rillpay *{box-sizing:border-box}.rillpay [hidden]{display:none}.rillpay h2,.rillpay p{margin:0}.rillpay-brand{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:-.04em;font-size:24px}.rillpay-mark{display:grid;place-items:center;width:36px;height:36px;border-radius:12px;background:#174b3b;color:white;font-size:23px}
.rillpay-header{display:flex;justify-content:space-between;align-items:center;gap:20px;padding-bottom:20px;border-bottom:1px solid #deebe5}.rillpay-total{font-size:24px;font-weight:700;text-align:right}.rillpay-muted{color:#526e62;font-size:13px}.rillpay-item{padding:18px 0;font-size:17px;font-weight:600}
.rillpay-methods{border:0;margin:0;padding:0}.rillpay-methods legend{padding:0 0 10px;font-weight:650}.rillpay-method{display:block;position:relative;background:white;border:1px solid #dbe7e0;border-radius:14px;padding:14px;margin:0 0 10px;cursor:pointer}.rillpay-method:has(input:checked){border-color:#147c55;box-shadow:0 0 0 1px #147c55}.rillpay-method:has(input:disabled){background:#eef2ef;color:#69776e;cursor:not-allowed}
.rillpay-method-head{display:flex;align-items:center;gap:10px;font-weight:650}.rillpay input[type=radio]{accent-color:#147c55;width:16px;height:16px;margin:0}.rillpay-price{margin-left:auto;text-align:right}.rillpay-usd{display:block;font-size:12px;font-weight:500;color:#526e62}.rillpay-cheapest{font-size:11px;font-weight:700;letter-spacing:.02em;text-transform:uppercase;color:#0f6b47;background:#dff5ea;border-radius:999px;padding:2px 8px}
.rillpay-details{display:grid;grid-template-columns:1fr 1fr;gap:5px 16px;margin:10px 0 0 26px;font-size:12px;color:#526e62}.rillpay-reason{margin:8px 0 0 26px;font-size:13px}
.rillpay button{font:inherit;border:0;border-radius:12px;padding:12px 16px;cursor:pointer}.rillpay-pay{width:100%;background:#174b3b;color:white;font-weight:650;margin-top:8px}.rillpay button:disabled{opacity:.55;cursor:not-allowed}.rillpay-cancel{display:block;margin:8px auto;background:transparent;color:#526e62}.rillpay-error{padding-top:12px;color:#a43720}.rillpay-foot{padding-top:14px;text-align:center;font-size:12px;color:#526e62}
@media(max-width:440px){.rillpay-overlay{padding:8px}.rillpay{padding:18px;border-radius:18px;max-height:calc(100vh - 16px)}.rillpay-details{grid-template-columns:1fr}.rillpay-total{font-size:20px}}
@media(prefers-reduced-motion:no-preference){.rillpay{animation:rillpay-in .18s ease-out}@keyframes rillpay-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}}
`;

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", className = ""): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
}

const usd = (cents: number): string => `$${(cents / 100).toFixed(2)}`;

function timeText(method: RillPayMethod): string {
  const minutes = method.minutesToConfirmation;
  if (minutes === null) return method.confirmationTime ?? "unknown until payment is quoted";
  const approx = minutes === 0 ? "under a minute" : `about ${minutes} min`;
  return method.confirmationTime ? `${approx}, ${method.confirmationTime}` : approx;
}

/** Ids of the available methods sharing the lowest known USD cost; empty when no available method has a known cost. */
export function cheapestMethods(methods: readonly RillPayMethod[]): string[] {
  const known = methods.filter((method) => method.available && method.usdCents !== null);
  if (!known.length) return [];
  const lowest = Math.min(...known.map((method) => method.usdCents!));
  return known.filter((method) => method.usdCents === lowest).map((method) => method.id);
}

/**
 * Mounts a modal checkout into `root`: a fixed overlay that blurs the host page behind a labeled dialog.
 * No HTML interpolation, automatic payment, wallet access, fetch, storage, or global styles. The host's own
 * elements are left untouched; Escape and clicks outside the dialog call `onCancel` when one is supplied.
 */
export function mountRillPay(root: HTMLElement, options: RillPayCheckout): { destroy(): void } {
  const methods = options.methods.map((method) => ({ ...method }));
  const cents = (value: unknown) => value === null || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);
  if (!methods.length || methods.length > 20 || new Set(methods.map((method) => method.id)).size !== methods.length ||
      methods.some((method) => typeof method.id !== "string" || method.id.length === 0 || method.id.length > 80 || typeof method.available !== "boolean" ||
        [method.label, method.network].some((value) => typeof value !== "string" || value.length > 2048) ||
        [method.unavailableReason, method.price, method.merchantFee, method.providerFee, method.walletFee, method.confirmationTime].some((value) => value !== null && (typeof value !== "string" || value.length > 2048)) ||
        !cents(method.usdCents) || !cents(method.minutesToConfirmation) ||
        (!method.available && !method.unavailableReason))) throw new Error("Invalid checkout methods");
  const cheapest = new Set(cheapestMethods(methods));
  const style = node("style", STYLE), overlay = node("div", "", "rillpay-overlay"), panel = node("section", "", "rillpay");
  overlay.setAttribute("role", "dialog"); overlay.setAttribute("aria-modal", "true"); overlay.setAttribute("aria-label", "RillPay checkout"); panel.tabIndex = -1;
  const header = node("div", "", "rillpay-header"), brand = node("div", "", "rillpay-brand");
  const mark = node("span", "r", "rillpay-mark"); mark.setAttribute("aria-hidden", "true"); brand.append(mark, node("span", "RillPay"));
  const total = node("div"); total.append(node("p", options.total, "rillpay-total"), node("p", options.merchant, "rillpay-muted"));
  header.append(brand, total); panel.append(header, node("h2", options.item, "rillpay-item"));
  const fieldset = node("fieldset", "", "rillpay-methods"); fieldset.append(node("legend", "Choose how to pay"));
  const group = `rillpay-${crypto.randomUUID()}`, inputs: HTMLInputElement[] = [];
  let selected = (methods.find((method) => cheapest.has(method.id)) ?? methods.find((method) => method.available))?.id ?? null, busy = false, alive = true;
  const pay = node("button", "Continue to payment", "rillpay-pay"), error = node("p", "", "rillpay-error");
  pay.type = "button"; pay.disabled = selected === null; error.setAttribute("role", "status");
  for (const method of methods) {
    const label = node("label", "", "rillpay-method"), head = node("div", "", "rillpay-method-head");
    const input = node("input"); input.type = "radio"; input.name = group; input.value = method.id; input.disabled = !method.available; input.checked = method.id === selected;
    input.onchange = () => { if (!busy && method.available) { selected = method.id; error.textContent = ""; pay.disabled = false; } };
    inputs.push(input); head.append(input, node("span", method.label));
    if (cheapest.has(method.id)) head.append(node("span", "Cheapest", "rillpay-cheapest"));
    const price = node("span", method.price ?? "Quote required", "rillpay-price");
    price.append(node("span", method.usdCents === null ? "USD cost unknown" : `${usd(method.usdCents)} est. total`, "rillpay-usd"));
    head.append(price);
    const detail = node("div", "", "rillpay-details");
    detail.append(node("span", method.network), node("span", `Time: ${timeText(method)}`),
      node("span", `Merchant fee: ${method.merchantFee ?? "unknown"}`), node("span", `Provider fee: ${method.providerFee ?? "unknown until quoted"}`),
      node("span", `Wallet/network fee: ${method.walletFee ?? "unknown, set by your wallet"}`));
    label.append(head, detail);
    if (!method.available) label.append(node("p", method.unavailableReason!, "rillpay-reason"));
    fieldset.append(label);
  }
  const cancel = node("button", "Cancel", "rillpay-cancel"); cancel.type = "button"; cancel.hidden = !options.onCancel;
  const dismiss = () => { if (!busy && alive) options.onCancel?.(); };
  cancel.onclick = dismiss;
  overlay.onmousedown = (event) => { if (event.target === overlay) dismiss(); };
  const onKey = (event: KeyboardEvent) => {
    if (event.key === "Escape") { event.preventDefault(); dismiss(); return; }
    if (event.key !== "Tab") return;
    const focusable = [...panel.querySelectorAll<HTMLElement>("input:not(:disabled),button:not(:disabled):not([hidden])")];
    if (!focusable.length) return;
    const first = focusable[0]!, last = focusable[focusable.length - 1]!, active = document.activeElement;
    if (event.shiftKey && (active === first || active === panel)) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && active === last) { event.preventDefault(); first.focus(); }
  };
  pay.onclick = () => {
    if (busy || selected === null || !alive) return;
    const chosen = selected; busy = true; pay.disabled = cancel.disabled = true; inputs.forEach((input) => { input.disabled = true; }); pay.textContent = "Preparing payment...";
    void Promise.resolve().then(() => options.onPay(chosen)).catch(() => { if (alive) error.textContent = "Could not prepare payment. No payment was confirmed. Try again or choose another method."; }).finally(() => {
      busy = false; if (!alive) return;
      pay.textContent = "Continue to payment"; pay.disabled = false; cancel.disabled = false;
      inputs.forEach((input, index) => { input.disabled = !methods[index]!.available; });
    });
  };
  panel.append(fieldset, pay, cancel, error, node("p", "Payment is complete only after the merchant verifies acceptance.", "rillpay-foot"));
  overlay.append(panel); document.addEventListener("keydown", onKey);
  const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  root.replaceChildren(style, overlay); (inputs.find((input) => input.checked) ?? panel).focus();
  return { destroy() {
    if (!alive) return;
    alive = false; document.removeEventListener("keydown", onKey); pay.onclick = cancel.onclick = overlay.onmousedown = null; inputs.forEach((input) => { input.onchange = null; });
    root.replaceChildren(); previousFocus?.focus();
  } };
}
