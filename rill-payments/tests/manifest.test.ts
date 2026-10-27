import { afterEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import validate from "../src/generated/native-lightning-manifest.js";
import { createNativeLightningMerchantManifest, parseNativeLightningMerchantManifest } from "../src/manifest";
import { MerchantLedger, type MerchantIdentity, type ReceiptObserver } from "../src/merchant";
import { createMerchantService, verifyAcceptance } from "../src/server";
import { receiver, testInvoice } from "./helpers";
import publishedFixture from "../../rill-docs/fixtures/checkout/native-lightning-manifest.json";
import { NETWORKS, type Network } from "../src/contract";

const origin = "https://merchant.example", key = Buffer.alloc(32, 17), publicKey = bytesToHex(ed25519.getPublicKey(key));
const manifest = (network: Network = "regtest") => createNativeLightningMerchantManifest(origin, receiver, publicKey, network);
const clone = () => JSON.parse(JSON.stringify(manifest()));
function refused(input: unknown, expectedOrigin = origin, expectedKey = publicKey) {
  expect(() => parseNativeLightningMerchantManifest(input, expectedOrigin, expectedKey)).toThrow("Native Lightning merchant manifest refused");
}
const cleanups: (() => void)[] = [];
afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });
function fixture(network: MerchantIdentity["network"] = "regtest") {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync("tmp/manifest-"); chmodSync(directory, 0o700);
  const path = join(directory, "merchant.sqlite"), identity = { origin, receiver, network, issuerId: "manifest_fixture" };
  const ledger = MerchantLedger.provision(path, identity); cleanups.push(() => { ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  const calls = { identity: 0, create: 0, lookup: 0 }, eventKey = Buffer.from(key);
  const issuer = { identity: async () => { calls.identity++; return identity; }, create: async () => { calls.create++; return testInvoice("manifest"); } };
  const observer: ReceiptObserver = { identity: async () => { calls.identity++; return identity; }, lookup: async (hash) => {
    calls.lookup++; return { receiver, network, paymentHash: hash, invoiceAmountMsat: "1000000", paidMsat: "1000000", state: "SETTLED", settledAt: 1090 };
  } };
  const options = { ledger, issuer, observer, adminToken: "fixture_manifest_admin_token_000000", statusKey: new Uint8Array(32).fill(2), eventSigningKey: eventKey, now: () => 1200 };
  const stored = () => { const db = new Database(path, { readonly: true }); try { return ["metadata", "intents", "attempts", "receipts", "outbox", "idempotency"].map((table) => db.query(`SELECT * FROM ${table}`).all()); } finally { db.close(); } };
  return { ledger, calls, options, eventKey, stored };
}

test("fixed manifest and canonical schema agree on native regtest denomination and capabilities", () => {
  const value = manifest(); expect(validate(value)).toBe(true);
  expect(value).toEqual(parseNativeLightningMerchantManifest(publishedFixture, origin, publicKey));
  expect(value.allowedPayerAssets).toEqual(value.acceptedReceiptAssets);
  expect(value.allowedPayerAssets[0]).toMatchObject({ network: "regtest", amountUnit: "msat", decimals: 11, quantum: "1000", tokenBehavior: "not_applicable" });
  expect(value.intentApi).toBe(origin + "/v1/intents"); expect(Object.hasOwn(value, "productionEnabled")).toBe(false);
  expect(value.receiptVerification.eventPathTemplate).toBe("/v1/intents/{id}/events");
  expect(parseNativeLightningMerchantManifest(JSON.parse(JSON.stringify(value)), origin, publicKey)).toEqual(value);
  for (const field of Object.keys(value)) { const invalid = clone(); delete invalid[field]; expect(validate(invalid)).toBe(false); refused(invalid); }
});

test("all nested structures refuse unknown fields or unsupported capability constants", () => {
  const mutations = [
    (m: ReturnType<typeof clone>) => { m.extra = "PRIVATE_EXTENSION"; },
    (m: ReturnType<typeof clone>) => { m.receiptVerification.extra = "PRIVATE_EXTENSION"; },
    (m: ReturnType<typeof clone>) => { m.publicPolicy.extra = true; },
    (m: ReturnType<typeof clone>) => { m.allowedPayerAssets[0].contract = "0xFake"; },
    (m: ReturnType<typeof clone>) => { m.acceptedReceiptAssets[0].extra = true; },
    (m: ReturnType<typeof clone>) => { m.approvedAdapters[0].extra = true; },
    (m: ReturnType<typeof clone>) => { m.routingProfiles[0].extra = true; },
    (m: ReturnType<typeof clone>) => { m.productionEnabled = true; },
    (m: ReturnType<typeof clone>) => { m.allowedPayerAssets[0].decimals = 8; },
    (m: ReturnType<typeof clone>) => { m.acceptedReceiptAssets[0].quantum = "1"; },
    (m: ReturnType<typeof clone>) => { m.publicPolicy.maxBuyerExtraMsat = "1"; },
    (m: ReturnType<typeof clone>) => { m.approvedAdapters.push(m.approvedAdapters[0]); },
    (m: ReturnType<typeof clone>) => { m.routingProfiles[0].routeClass = "atomic"; },
    (m: ReturnType<typeof clone>) => { m.receiptVerification.algorithm = "unverified"; },
    (m: ReturnType<typeof clone>) => { m.version = "merchant-manifest/native-lightning/2"; },
  ];
  for (const mutate of mutations) { const value = clone(); mutate(value); expect(validate(value)).toBe(false); refused(value); }
});

test("origin and key pins and exact intent endpoint are independent required expectations", () => {
  for (const expectedOrigin of ["http://merchant.example", origin + "/", "https://foreign.example", "https://secret@merchant.example"]) refused(clone(), expectedOrigin);
  for (const expectedKey of ["", "22".repeat(32), publicKey.toUpperCase()]) refused(clone(), origin, expectedKey);
  const changed = clone(); changed.intentApi = "https://foreign.example/v1/intents"; expect(validate(changed)).toBe(true); refused(changed);
  for (const receiver of ["bad", "02" + "AB".repeat(32)]) expect(() => createNativeLightningMerchantManifest(origin, receiver, publicKey, "regtest")).toThrow();
});

for (const network of NETWORKS) {
  test(`manifest pins ${network} policy and asset identities together`, () => {
    const value = manifest(network); expect(validate(value)).toBe(true);
    expect(value.publicPolicy.network).toBe(network);
    expect(String(value.allowedPayerAssets[0]!.id)).toBe(`LN_BTC_${network.toUpperCase()}`);
    for (const field of ["allowedPayerAssets", "acceptedReceiptAssets"] as const) {
      const changed = JSON.parse(JSON.stringify(value));
      changed[field][0].network = network === "mainnet" ? "regtest" : "mainnet";
      expect(validate(changed)).toBe(true); refused(changed);
      changed[field][0].network = network;
      changed[field][0].id = network === "mainnet" ? "LN_BTC_REGTEST" : "LN_BTC_MAINNET";
      expect(validate(changed)).toBe(true); refused(changed);
    }
  });
}

test("parser snapshots only bounded plain data and rejects accessors without invoking them", () => {
  const raw = clone(), result = parseNativeLightningMerchantManifest(raw, origin, publicKey);
  raw.publicPolicy.receiver = "03" + "ab".repeat(32); raw.receiptVerification.publicKey = "22".repeat(32);
  expect(result.publicPolicy.receiver).toBe(receiver); expect(result.receiptVerification.publicKey).toBe(publicKey);
  for (const value of [result, result.publicPolicy, result.receiptVerification, result.allowedPayerAssets, result.allowedPayerAssets[0], result.routingProfiles, result.routingProfiles[0], result.approvedAdapters[0]]) expect(Object.isFrozen(value)).toBe(true);
  let getterCalls = 0; const accessor = clone(); Object.defineProperty(accessor.publicPolicy, "receiver", { enumerable: true, get() { getterCalls++; return receiver; } });
  refused(accessor); expect(getterCalls).toBe(0);
  for (const alter of [
    (value: ReturnType<typeof clone>) => Object.defineProperty(value, "hidden", { value: true }),
    (value: ReturnType<typeof clone>) => { value[Symbol("hidden")] = true; },
    (value: ReturnType<typeof clone>) => { value.toJSON = () => { throw new Error("PRIVATE_TOJSON"); }; },
    (value: ReturnType<typeof clone>) => { value.allowedPayerAssets = new Array(8); },
    (value: ReturnType<typeof clone>) => { value.extra = "x".repeat(1025); },
  ]) { const value = clone(); alter(value); refused(value); }
});

test("pin comparisons are not signatures and cannot authenticate an advertised receiver", () => {
  const impersonated = clone(); impersonated.publicPolicy.receiver = "03" + "ab".repeat(32);
  expect(parseNativeLightningMerchantManifest(impersonated, origin, publicKey).publicPolicy.receiver).toBe(impersonated.publicPolicy.receiver);
  // Origin-authenticated delivery and independent checkout receiver pins remain
  // caller requirements, not assertions that this unsigned parser can prove.
});

for (const network of NETWORKS) {
test(`explicit ${network} manifest publication is public, immutable, read-only and causes no backend calls`, async () => {
  const f = fixture(network), before = f.stored(), options = { ...f.options, publishManifest: true };
  const service = createMerchantService(options); options.publishManifest = false;
  const response = await service.fetch(new Request(origin + "/v1/manifest")); expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("no-store"); expect(response.headers.get("content-type")?.split(";")[0]).toBe("application/json");
  expect(parseNativeLightningMerchantManifest(await response.json(), origin, publicKey)).toEqual(manifest(network));
  expect(f.calls).toEqual({ identity: 0, create: 0, lookup: 0 }); expect(f.stored()).toEqual(before);
  expect((await service.fetch(new Request(origin + "/v1/manifest", { method: "POST" }))).status).toBe(405);
  for (const url of [origin + "/v1/manifest?secret=private", origin + "/v1/manifest#fragment"]) expect((await service.fetch(new Request(url))).status).toBe(403);
  expect((await service.fetch(new Request(origin + "/v1/manifest", { headers: { Origin: "https://foreign.example" } }))).status).toBe(403);
  expect((await service.fetch(new Request(origin + "/v1/intents/unknown_intent_001/events"))).status).toBe(404);
  expect(f.calls).toEqual({ identity: 0, create: 0, lookup: 0 }); expect(f.stored()).toEqual(before);
});
}

test("absent and false options retain 404 and unsupported publication configuration is refused", async () => {
  const f = fixture();
  for (const publishManifest of [undefined, false]) {
    const service = createMerchantService({ ...f.options, publishManifest });
    expect((await service.fetch(new Request(origin + "/v1/manifest"))).status).toBe(404);
  }
  for (const publishManifest of ["true", null, 1]) expect(() => createMerchantService({ ...f.options, publishManifest } as unknown as Parameters<typeof createMerchantService>[0])).toThrow("publication option");
  const signet = fixture("signet");
  const previous = createMerchantService({ ...signet.options, publishManifest: false });
  expect((await previous.fetch(new Request(origin + "/v1/manifest"))).status).toBe(404);
});

test("publication policy is captured once, never upgraded by a changing option getter", async () => {
  const f = fixture(); let calls = 0;
  const options = { ...f.options, get publishManifest() { calls++; return calls === 1 ? false : true; } };
  const service = createMerchantService(options); expect(calls).toBe(1);
  expect((await service.fetch(new Request(origin + "/v1/manifest"))).status).toBe(404); expect(calls).toBe(1);
});

test("publishing pins a copied Buffer-backed event key for declared capability, history and delivery", async () => {
  const f = fixture(), service = createMerchantService({ ...f.options, publishManifest: true });
  f.eventKey.fill(19);
  const intent = f.ledger.createIntent("manifest-order", "1000000", 1100, "manifest_intent_request_001", 1000);
  const attempt = f.ledger.createAttempt(intent.id, "manifest_attempt_request_001", 1000);
  await f.ledger.issue(attempt.id, f.options.issuer, () => 1000); await f.ledger.observe(attempt.id, f.options.observer, () => 1200);
  const published = await (await service.fetch(new Request(origin + "/v1/manifest"))).json(); expect(published.receiptVerification.publicKey).toBe(publicKey);
  const history = await service.fetch(new Request(origin + "/v1/intents/" + intent.id + "/events", { headers: { Authorization: "Bearer " + f.options.adminToken } }));
  expect(verifyAcceptance((await history.json())[0], publicKey)).toBe(true);
  await service.deliverEvents(async (event) => { expect(verifyAcceptance(event, publicKey)).toBe(true); }); expect(f.ledger.pendingEvents().length).toBe(0);
});
