import { createCheckout, indexedDbCheckoutStore } from "../src/sdk";
import { mountTracking } from "../src/tracking";
import { invoiceBinding } from "../src/bolt11";
import { receiver, testInvoice } from "../tests/helpers";

declare global { interface Window { checkoutPay(): Promise<string>; checkoutCalls(): number; checkoutReady: boolean } }

const invoice = testInvoice("browser_fixture"); const binding = invoiceBinding(invoice, "regtest");
const terms = { version: "checkout/0.1" as const, policyVersion: "native-lightning/1" as const, merchantOrigin: "https://merchant.example",
  intentId: "browser_intent_0001", attemptId: "browser_attempt_001", receiver, network: "regtest" as const,
  amountMsat: binding.amount_msat, paymentHash: binding.payment_hash, expiresAt: 2000, buyerExtraMsat: "0" };
let calls = 0;
const checkout = createCheckout({ intentUrl: "https://merchant.example/v1/intents/" + terms.intentId, statusToken: "s".repeat(43),
  policy: { version: "native-lightning/1", merchantOrigin: terms.merchantOrigin, receiver, network: "regtest", maxBuyerExtraMsat: "100000", maxBuyerExtraBps: 1000 },
  wallet: { canLimitFees: true, payInvoice: async () => { calls++; } },
  recoveryStore: indexedDbCheckoutStore("checkout_fixture_" + new URL(location.href).searchParams.get("case")), now: () => 1200,
  fetch: async () => Response.json({ version: "checkout-view/1", id: terms.intentId, status: "waiting", attempt: { terms, invoice } }) });
mountTracking(document.getElementById("tracking")!, checkout);
Object.assign(window, { checkoutPay: async () => { try { await checkout.pay(); return "sent"; } catch { return "refused"; } }, checkoutCalls: () => calls, checkoutReady: true });
