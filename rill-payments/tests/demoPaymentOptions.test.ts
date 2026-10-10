import { expect, test } from "bun:test";
import { demoPaymentMethods } from "../examples/demo-shop/paymentOptions";

test("demo prices and eligibility are complete while quote and wallet costs remain unknown", () => {
  const methods = demoPaymentMethods(200, { lightning: true, "btc-swap": true, fusdc: true, fusdt: false, monero: false });
  expect(methods.map((method) => method.id)).toEqual(["lightning", "btc-swap", "fusdc", "fusdt", "monero"]);
  expect(methods[0]!.price).toBe("2,000 sat"); expect(methods[2]!.price).toBe("2.00 fUSDC");
  expect(methods[1]!.providerFee).toBeNull(); expect(methods.every((method) => method.walletFee === null)).toBe(true);
  expect(methods[3]!.available).toBe(false); expect(methods[3]!.unavailableReason).toContain("unavailable");
});
test("unrepresentable amounts disable every option without conversion errors", () => {
  for (const cents of [0, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 0.5]) {
    const methods = demoPaymentMethods(cents, { lightning: true });
    expect(methods.every((method) => !method.available && method.price === null && method.unavailableReason?.includes("amount"))).toBe(true);
  }
});
