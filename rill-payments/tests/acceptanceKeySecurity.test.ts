import { afterEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { LightningAcceptanceConsumer, type AcceptanceConsumerIdentity } from "../src/acceptanceConsumer";
import type { AcceptanceEvent } from "../src/merchant";
import { hasNontrivialAcceptanceKey, signAcceptance, verifyAcceptance, type SignedAcceptance } from "../src/server";
import type { NativeLightningTerms } from "../src/contract";
import { receiver } from "./helpers";

const origin = "https://merchant.example", key = new Uint8Array(32).fill(17), publicKey = bytesToHex(ed25519.getPublicKey(key));
const identity: AcceptanceConsumerIdentity = { merchantOrigin: origin, merchantPublicKey: publicKey, receiver, network: "regtest" };
const terms: NativeLightningTerms = { version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: origin,
  intentId: "security_intent_001", attemptId: "security_attempt_001", network: "regtest", amountMsat: "1000000", paymentHash: "11".repeat(32), receiver, expiresAt: 1100, buyerExtraMsat: "0" };
const event: AcceptanceEvent = { version: "checkout-event/1", id: "security_event_001", merchantOrigin: origin, type: "payment.accepted",
  intentId: terms.intentId, attemptId: terms.attemptId, paymentHash: terms.paymentHash, amountMsat: terms.amountMsat, acceptedAt: 1200 };
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function path() { mkdirSync("tmp", { recursive: true }); const root = mkdtempSync("tmp/acceptance-key-security-"); chmodSync(root, 0o700); roots.push(root); return join(root, "consumer.sqlite"); }
function littleEndian(value: bigint): string { const bytes = new Uint8Array(32); for (let i = 0; i < 32; i++) { bytes[i] = Number(value & 255n); value >>= 8n; } return bytesToHex(bytes); }
const p = (1n << 255n) - 19n;
const weakKeys = ["00".repeat(32), "01" + "00".repeat(31), littleEndian(1n << 255n), littleEndian(p), littleEndian(p + 1n), littleEndian((1n << 255n) + 1n)];
const forged = (publicKey: string): SignedAcceptance => ({ algorithm: "Ed25519", publicKey, event, signature: "00".repeat(64) });

test("small-order pins cannot verify an unsigned matching acceptance event", () => {
  for (const publicKey of weakKeys) {
    const point = ed25519.Point.fromBytes(hexToBytes(publicKey), true); expect(point.isSmallOrder()).toBe(true);
    // The dependency's consensus-oriented ZIP-215 policy alone accepts this
    // unsigned envelope. Dedicated merchant acceptance adds a key restriction.
    expect(ed25519.verify(new Uint8Array(64), new Uint8Array([1, 2]), hexToBytes(publicKey))).toBe(true);
    expect(verifyAcceptance(forged(publicKey), publicKey)).toBe(false);
  }
});

test("small-order consumer identities refuse before creation, including absent or existing legacy state", () => {
  for (const merchantPublicKey of weakKeys) {
    const absent = path(), weak = { ...identity, merchantPublicKey };
    expect(() => LightningAcceptanceConsumer.provision(absent, weak)).toThrow("identity"); expect(existsSync(absent)).toBe(false);
    expect(() => LightningAcceptanceConsumer.open(absent, weak)).toThrow("identity"); expect(existsSync(absent)).toBe(false);
  }
});

test("a previous-format weak-key acceptance store is refused without blessing or repairing its history", () => {
  const existing = path(), consumer = LightningAcceptanceConsumer.provision(existing, identity);
  consumer.bindOrder("historical-weak-order", terms.amountMsat, terms); consumer.consume(signAcceptance(event, key), 1200); consumer.close();
  const weak = { ...identity, merchantPublicKey: "00".repeat(32) }, envelope = forged(weak.merchantPublicKey);
  const db = new Database(existing, { readwrite: true, create: false });
  try {
    // Explicit test-only reconstruction of the older admitted identity and
    // forged row, never a migration or recovery path offered to installations.
    db.query("UPDATE metadata SET value=? WHERE key='identity'").run(JSON.stringify(weak));
    db.query("UPDATE acceptances SET envelope=? WHERE event_id=?").run(JSON.stringify(envelope), event.id);
  } finally { db.close(); }
  const bytes = readFileSync(existing), inode = lstatSync(existing).ino;
  expect(() => LightningAcceptanceConsumer.open(existing, weak)).toThrow("identity");
  expect(() => LightningAcceptanceConsumer.provision(existing, weak)).toThrow("identity");
  expect(() => LightningAcceptanceConsumer.open(existing, identity)).toThrow("identity mismatch");
  expect(readFileSync(existing)).toEqual(bytes); expect(lstatSync(existing).ino).toBe(inode);
  expect(verifyAcceptance(envelope, weak.merchantPublicKey)).toBe(false);
});

test("legacy mixed-order and noncanonical ZIP-215 consumer keys retain their original admission contract", () => {
  for (const merchantPublicKey of ["22".repeat(32), littleEndian(p + 3n)]) {
    const point = ed25519.Point.fromBytes(hexToBytes(merchantPublicKey), true);
    expect(point.isSmallOrder()).toBe(false); expect(point.isTorsionFree()).toBe(false); expect(hasNontrivialAcceptanceKey(merchantPublicKey)).toBe(true);
    if (merchantPublicKey === littleEndian(p + 3n)) expect(() => ed25519.Point.fromBytes(hexToBytes(merchantPublicKey))).toThrow();
    const existing = path(), mixed = { ...identity, merchantPublicKey };
    const consumer = LightningAcceptanceConsumer.provision(existing, mixed); consumer.bindOrder("mixed-order", terms.amountMsat, terms);
    expect(() => consumer.consume(forged(merchantPublicKey), 1200)).toThrow("Acceptance event refused"); expect(consumer.getOrder("mixed-order").state).toBe("waiting"); consumer.close();
    const reopened = LightningAcceptanceConsumer.open(existing, mixed);
    try { expect(reopened.getOrder("mixed-order").state).toBe("waiting"); }
    finally { reopened.close(); }
  }
});

test("normally generated keys, including an all-zero private seed, retain exact signatures and durable replay", () => {
  for (const privateKey of [key, new Uint8Array(32)]) {
    const merchantPublicKey = bytesToHex(ed25519.getPublicKey(privateKey)), ordinary = { ...identity, merchantPublicKey }, envelope = signAcceptance(event, privateKey);
    expect(hasNontrivialAcceptanceKey(merchantPublicKey)).toBe(true); expect(verifyAcceptance(envelope, merchantPublicKey)).toBe(true);
    expect(verifyAcceptance({ ...envelope, publicKey: merchantPublicKey.toUpperCase() }, merchantPublicKey.toUpperCase())).toBe(true);
    const existing = path(), consumer = LightningAcceptanceConsumer.provision(existing, ordinary);
    consumer.bindOrder("ordinary-order", terms.amountMsat, terms); const accepted = consumer.consume(envelope, 1200); consumer.close();
    const original = readFileSync(existing), reopened = LightningAcceptanceConsumer.open(existing, ordinary);
    try { expect(reopened.consume(envelope, 1300)).toEqual(accepted); expect(reopened.getOrder("ordinary-order")).toEqual(accepted); }
    finally { reopened.close(); }
    expect(readFileSync(existing)).toEqual(original);
  }
});

test("invalid keys are rejected without widening textual verifier policy or creating consumer state", () => {
  for (const publicKey of [null, 1, {}, "", "not-hex", "ff".repeat(31), "ff".repeat(33)]) expect(hasNontrivialAcceptanceKey(publicKey)).toBe(false);
  const absent = path(); expect(() => LightningAcceptanceConsumer.provision(absent, { ...identity, merchantPublicKey: publicKey.toUpperCase() })).toThrow("identity");
  expect(existsSync(absent)).toBe(false);
});
