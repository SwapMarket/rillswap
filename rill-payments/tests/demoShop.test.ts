import { describe, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { findAcceptance, priceSat, readOrderHistory } from "../examples/demo-shop/checkout";
import { tokenBaseUnits } from "../examples/demo-shop/native";
import { formatXmr, startMonero, xmrAtomic } from "../examples/demo-shop/monero";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
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

test("Monero prices are exact piconero at the demo rate and format without trailing zeros", () => {
  expect(xmrAtomic(200)).toBe("10000000000"); // $2 at 200 USD/XMR = 0.01 XMR
  expect(xmrAtomic(12_000)).toBe("600000000000");
  expect(formatXmr("10000000000")).toBe("0.01");
  expect(formatXmr("1000000000000")).toBe("1");
  expect(formatXmr("18446744073709551615")).toBe("18446744.073709551615");
});

test("the Monero rail initializes only from an empty directory with a known order history free of Monero orders", async () => {
  mkdirSync("tmp", { recursive: true });
  const state = mkdtempSync(resolve("tmp/shop-")), home = `${state}/shop/monero`;
  // Unreachable RPC: every case below must refuse before touching the wallet.
  const start = (priorOrders: "none" | "some" | "unknown") =>
    startMonero(state, { walletUrl: "http://127.0.0.1:9", daemonUrl: "http://127.0.0.1:9", origin: "https://shop.example", priorOrders });
  try {
    await expect(start("unknown")).rejects.toThrow("unreadable");
    await expect(start("some")).rejects.toThrow("Monero orders exist");
    writeFileSync(`${home}/ledger.sqlite-wal`, "");
    await expect(start("none")).rejects.toThrow("incomplete");
    rmSync(`${home}/ledger.sqlite-wal`);
    for (const name of ["admin.token", "capability.key", "event.key"]) writeFileSync(`${home}/${name}`, "x");
    await expect(start("none")).rejects.toThrow("missing config.json, ledger.sqlite");
    rmSync(home, { recursive: true });
    await expect(start("none")).rejects.toThrow(); // fresh: reaches the (unreachable) wallet
    expect(Bun.spawnSync(["ls", "-A", home]).stdout.toString()).toBe(""); // and wrote nothing
  } finally { rmSync(state, { recursive: true, force: true }); }
});

test("unreadable order history is kept aside and stays unknown across restarts and later saves", () => {
  mkdirSync("tmp", { recursive: true });
  const dir = mkdtempSync(resolve("tmp/orders-")), file = `${dir}/orders.json`;
  try {
    expect(readOrderHistory(file)).toEqual({ orders: [], known: true }); // no history yet
    writeFileSync(file, JSON.stringify([{ id: "a" }]));
    expect(readOrderHistory(file)).toEqual({ orders: [{ id: "a" }], known: true });
    writeFileSync(file, "{ truncated");
    expect(readOrderHistory(file)).toEqual({ orders: [], known: false }); // first start
    expect(readOrderHistory(file).known).toBe(false); // restart without a save
    writeFileSync(file, JSON.stringify([{ id: "b" }])); // the shop saved a new order
    expect(readOrderHistory(file)).toEqual({ orders: [{ id: "b" }], known: false });
    const aside = Bun.spawnSync(["sh", "-c", `ls ${dir} | grep unreadable`]).stdout.toString().trim();
    expect(Bun.file(`${dir}/${aside}`).size).toBeGreaterThan(0); // original bytes kept
    rmSync(`${dir}/${aside}`); // explicit recovery
    expect(readOrderHistory(file).known).toBe(true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
