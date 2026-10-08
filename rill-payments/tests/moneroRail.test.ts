import { expect, test } from "bun:test";
import { parseJsonLossless, parseMoneroTransfer } from "../src/moneroRpc";
import { classifyMoneroPayment } from "../src/moneroLedger";
import { NETWORK, subaddress, transfer, txid } from "./moneroFake";

const terms = { address: subaddress(3), subaddressIndex: 3, amountAtomic: "3000000000000", createdAt: 1000, expiresAt: 2000 };
const decide = (entries: Parameters<typeof classifyMoneroPayment>[2], now = 1999) => classifyMoneroPayment(terms, NETWORK, entries, now);

test("lossless JSON keeps unsafe integers exact and leaves strings and floats alone", () => {
  const parsed = parseJsonLossless('{"amount": 18446744073709551615, "neg": -5, "f": 1.5, "e": 2e3, "s": "a \\"9\\" 10", "list": [9007199254740993]}') as Record<string, unknown>;
  expect(parsed).toEqual({ amount: "18446744073709551615", neg: "-5", f: 1.5, e: 2000, s: 'a "9" 10', list: ["9007199254740993"] });
  expect(String(JSON.parse("9007199254740993"))).not.toBe("9007199254740993");
});

test("transfer parsing reads amounts as bigint and refuses malformed entries", () => {
  const raw = parseJsonLossless(`{"address":"${subaddress(1)}","amount":4608576963437982123,"confirmations":2,"double_spend_seen":false,"height":143,"locked":true,
    "subaddr_index":{"major":0,"minor":1},"timestamp":1791439928,"txid":"${txid(7)}","type":"in","unlock_time":0}`);
  const parsed = parseMoneroTransfer(raw);
  expect(parsed.amountAtomic).toBe(4608576963437982123n);
  expect([parsed.minor, parsed.confirmations, parsed.unlockTime, parsed.locked]).toEqual([1, 2, "0", true]);
  const pool = parseMoneroTransfer({ ...(raw as object), type: "pool", confirmations: undefined, height: "0" });
  expect(pool.confirmations).toBe(0);
  expect(() => parseMoneroTransfer({ ...(raw as object), amount: 5 })).toThrow("amount");
  expect(() => parseMoneroTransfer({ ...(raw as object), amount: "18446744073709551616" })).toThrow("amount");
});

test("exact timely sum across transactions is paid with one receipt per (txid, subaddress)", () => {
  const { decision, progress } = decide([transfer(3, 1_000_000_000_000n, { txid: txid(1) }), transfer(3, 2_000_000_000_000n, { txid: txid(2), timestamp: 1999 }),
    transfer(4, 9n, { txid: txid(1) })]);
  expect(decision.kind).toBe("paid");
  if (decision.kind !== "paid") return;
  expect(decision.receipts.map((receipt) => receipt.key)).toEqual([`monero-regtest:test:${NETWORK.anchorHash}:0/3:${txid(1)}`, `monero-regtest:test:${NETWORK.anchorHash}:0/3:${txid(2)}`]);
  expect(progress).toEqual({ seenAtomic: "3000000000000", confirmedAtomic: "3000000000000", observedAt: 1999 });
});

test("unconfirmed, locked, timelocked, double spent, pool and coinbase entries never count", () => {
  const amount = 3_000_000_000_000n;
  for (const entry of [transfer(3, amount, { confirmations: 9 }), transfer(3, amount, { locked: true }), transfer(3, amount, { unlockTime: "500" }),
    transfer(3, amount, { doubleSpendSeen: true }), transfer(3, amount, { type: "pool", confirmations: 0 }), transfer(3, amount, { type: "block" }), transfer(3, amount, { major: 1 })]) {
    expect(decide([entry]).decision.kind).toBe("waiting");
  }
});

test("late, early, overpaid and dust-overpaid payments go to reconciliation", () => {
  const amount = 3_000_000_000_000n;
  expect(decide([transfer(3, amount, { timestamp: 2000 })], 2500).decision).toMatchObject({ kind: "reconciliation", reason: "late" });
  expect(decide([transfer(3, amount, { timestamp: 999 })]).decision).toMatchObject({ kind: "reconciliation", reason: "late" });
  expect(decide([transfer(3, amount + 1n)]).decision).toMatchObject({ kind: "reconciliation", reason: "overpaid" });
  // Anyone who knows the address can push an order to reconciliation with dust.
  expect(decide([transfer(3, amount, { txid: txid(1) }), transfer(3, 1n, { txid: txid(2) })]).decision).toMatchObject({ kind: "reconciliation", reason: "overpaid" });
});

test("expiry alone decides nothing: on-time funds confirming after expiry are paid", () => {
  expect(decide([transfer(3, 3_000_000_000_000n, { timestamp: 1900, confirmations: 3 })], 2100).decision.kind).toBe("waiting");
  expect(decide([transfer(3, 3_000_000_000_000n, { timestamp: 1900 })], 2600).decision.kind).toBe("paid");
  expect(decide([], 5000).decision.kind).toBe("waiting");
});

test("underpayment is reconciled only after expiry and with nothing pending", () => {
  const part = transfer(3, 1_000_000_000_000n);
  expect(decide([part]).decision.kind).toBe("waiting");
  expect(decide([part, transfer(3, 2_000_000_000_000n, { txid: txid(9), type: "pool", confirmations: 0 })], 2100).decision.kind).toBe("waiting");
  expect(decide([part], 2100).decision).toMatchObject({ kind: "reconciliation", reason: "underpaid" });
});

test("a subaddress reported with another address or duplicated entries is refused", () => {
  expect(() => decide([transfer(3, 1n, { address: subaddress(5) })])).toThrow("mismatch");
  expect(() => decide([transfer(3, 1n), transfer(3, 1n)])).toThrow("Duplicate");
});

test("evidence timestamped after the observation defers the decision", () => {
  const entry = transfer(3, 3_000_000_000_000n, { timestamp: 1600 });
  expect(decide([entry], 1500).decision.kind).toBe("waiting");
  expect(decide([entry], 1600).decision.kind).toBe("paid");
});

test("an exact confirmed sum is paid even with another transfer still pending", () => {
  // Policy boundary: the extra pending funds are not recorded (handled out of band).
  const extra = transfer(3, 1n, { txid: txid(9), type: "pool", confirmations: 0 });
  expect(decide([transfer(3, 3_000_000_000_000n), extra]).decision.kind).toBe("paid");
});
