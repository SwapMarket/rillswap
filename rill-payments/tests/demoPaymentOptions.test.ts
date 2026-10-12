import { expect, test } from "bun:test";
import { demoPaymentMethods, demoSwapFeeSat } from "../examples/demo-shop/paymentOptions";
import { cheapestMethods } from "../src/rillPay";

test("demo prices, USD estimates and times are complete while wallet costs remain unknown", () => {
  const methods = demoPaymentMethods(200, { lightning: true, "btc-swap": true, fusdc: true, fusdt: false, monero: false });
  expect(methods.map((method) => method.id)).toEqual(["lightning", "btc-swap", "fusdc", "fusdt", "monero"]);
  expect(methods[0]!.price).toBe("2,000 sat"); expect(methods[2]!.price).toBe("2.00 fUSDC");
  expect(methods.every((method) => method.walletFee === null)).toBe(true);
  expect(methods.map((method) => method.usdCents)).toEqual([200, 205, 200, 200, 200]);
  expect(methods.map((method) => method.minutesToConfirmation)).toEqual([0, 10, 1, 1, 1]);
  expect(methods[3]!.available).toBe(false); expect(methods[3]!.unavailableReason).toContain("unavailable");
});
test("the Bitcoin swap option prefills the dev provider swap fee and stays more expensive than Lightning", () => {
  expect(demoSwapFeeSat(2000)).toBe(52); expect(demoSwapFeeSat(1)).toBe(51); expect(demoSwapFeeSat(1_000_000)).toBe(1050);
  const swap = demoPaymentMethods(200, { "btc-swap": true })[1]!;
  expect(swap.price).toBe("2,052 sat incl. swap fee"); expect(swap.providerFee).toContain("52 sat swap fee");
  expect(cheapestMethods(demoPaymentMethods(200, { lightning: true, "btc-swap": true }))).toEqual(["lightning"]);
  expect(cheapestMethods(demoPaymentMethods(200, { "btc-swap": true }))).toEqual(["btc-swap"]);
  expect(cheapestMethods(demoPaymentMethods(200, { lightning: true, fusdc: true }))).toEqual(["lightning", "fusdc"]);
});
test("unrepresentable amounts disable every option without conversion errors", () => {
  for (const cents of [0, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 0.5]) {
    const methods = demoPaymentMethods(cents, { lightning: true });
    expect(methods.every((method) => !method.available && method.price === null && method.usdCents === null && method.unavailableReason?.includes("amount"))).toBe(true);
  }
});
