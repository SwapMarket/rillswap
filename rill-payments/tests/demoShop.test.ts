import { describe, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { findAcceptance, priceSat } from "../examples/demo-shop/checkout";
import { tokenBaseUnits } from "../examples/demo-shop/native";
import { signAcceptance } from "../src/server";
import type { AcceptanceEvent } from "../src/merchant";

const merchantKey = new Uint8Array(32).fill(7);
const pinned = bytesToHex(ed25519.getPublicKey(merchantKey));
const event: AcceptanceEvent = {
  version: "checkout-event/1",
  id: "event_0123456789abcdef",
  merchantOrigin: "https://shop.rillswap.test",
  type: "payment.accepted",
  intentId: "intent_0123456789abcd",
  attemptId: "attempt_0123456789abc",
  paymentHash: "ab".repeat(32),
  amountMsat: "2000000",
  acceptedAt: 1_791_371_626,
};

describe("demo shop", () => {
  test("prices USD at the fixed demo rate in whole sats", () => {
    expect(priceSat(200)).toBe(2_000);
    expect(priceSat(12_000)).toBe(120_000);
  });

  test("prices fake stablecoins at 1 USD in 6-decimal base units", () => {
    expect(tokenBaseUnits(200)).toBe("2000000");
    expect(tokenBaseUnits(12_000)).toBe("120000000");
  });

  test("accepts only a pinned-key signature for this intent and amount", () => {
    const good = signAcceptance(event, merchantKey);
    expect(findAcceptance([good], pinned, event.intentId, 2_000)).toBe(good);
    expect(findAcceptance([good], pinned, "intent_other_12345678", 2_000)).toBeUndefined();
    expect(findAcceptance([good], pinned, event.intentId, 2_001)).toBeUndefined();
    const forged = signAcceptance(event, new Uint8Array(32).fill(9));
    expect(findAcceptance([forged], pinned, event.intentId, 2_000)).toBeUndefined();
    const tampered = { ...good, event: { ...good.event, amountMsat: "1000" } };
    expect(findAcceptance([tampered], pinned, event.intentId, 1)).toBeUndefined();
  });
});
