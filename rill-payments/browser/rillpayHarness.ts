import { mountRillPay } from "../src/rillPay";

declare global { interface Window { rillPayReady: boolean; rillPayCalls: string[]; rillPayCancels: number; rillPayRelease: () => void } }
window.rillPayCalls = []; window.rillPayCancels = 0;
const base = { network: "Test network", merchantFee: "0", providerFee: null, walletFee: null, confirmationTime: null, usdCents: null, minutesToConfirmation: null };
const query = new URLSearchParams(location.search);
mountRillPay(document.getElementById("checkout")!, { merchant: '<img src=x onerror="window.bad=true">', item: "Test item", total: "$2.00", methods: [
  { ...base, id: "offline", label: "Unavailable method", available: false, unavailableReason: "Below the merchant minimum of 5,000 sat", price: "2,000 sat", usdCents: 150, minutesToConfirmation: 0 },
  { ...base, id: "ln", label: "Lightning", available: query.get("all-unavailable") !== "1", unavailableReason: "Disabled for this amount", price: "2,000 sat", usdCents: 205, minutesToConfirmation: 0 },
  { ...base, id: "swap", label: "Bitcoin swap", available: query.get("all-unavailable") !== "1", unavailableReason: "Disabled for this amount", price: "2,052 sat incl. swap fee", providerFee: "52 sat swap fee", usdCents: 200, minutesToConfirmation: 10 },
  { ...base, id: "btc", label: "Bitcoin", available: false, unavailableReason: "Provider quote unavailable", price: null },
], onPay: async (id) => {
  window.rillPayCalls.push(id);
  if (query.get("hold") === "1") await new Promise<void>((resolve) => { window.rillPayRelease = resolve; });
  if (query.get("error") === "1") throw new Error("private-error-not-for-UI");
}, onCancel: query.get("cancel") === "1" ? () => { window.rillPayCancels += 1; } : undefined });
window.rillPayReady = true;
