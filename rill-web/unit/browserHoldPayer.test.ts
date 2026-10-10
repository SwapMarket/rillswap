import { expect, test } from "bun:test";
import { hexToBytes } from "@noble/hashes/utils.js";
import { testInvoice, receiver } from "../../rill-payments/tests/helpers";
import { BrowserHoldPayer, BrowserHoldPaymentRefusedError } from "../src/swap/browserHoldPayer";
import { decodeBolt11, invoiceBinding } from "../src/swap/bolt11";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json";

const invoice = testInvoice("bounded-browser-hold");
const binding = invoiceBinding(invoice, "regtest"), decoded = decodeBolt11(invoice);
const base64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
const remote = { payment_hash: binding.payment_hash, destination: receiver, num_msat: binding.amount_msat,
  timestamp: String(binding.created_at), expiry: String(binding.expires_at - binding.created_at), cltv_expiry: String(binding.min_final_cltv_delta),
  payment_addr: base64(hexToBytes(decoded.paymentSecret!)), features: Object.fromEntries([...decoded.features].map((bit) => [bit, {}])), route_hints: [] };
const route = { total_time_lock: 121, total_fees_msat: "1000", total_amt_msat: "1001000", first_hop_amount_msat: "1001000", hops: [
  { chan_id: "18446744073709551615", pub_key: receiver, expiry: 121, amt_to_forward_msat: "1000000", fee_msat: "0", tlv_payload: false },
] };
const limits = { feeLimitSat: 2n, minFinalExpiryHeight: 120, maxExpiryHeight: 150, deadlineAt: 1900 };
function fixture() {
  const calls: { path: string; init?: RequestInit }[] = [];
  const info = { identity_pubkey: receiver, chains: [{ chain: "bitcoin", network: "regtest" }], synced_to_chain: true, block_height: 100 };
  let invoiceResponse: unknown = structuredClone(remote), routes: unknown = [structuredClone(route)], streamStatus = "IN_FLIGHT", now = 1000000, unknownPolling = false;
  const trackingTimes: number[] = [];
  const payer = new BrowserHoldPayer({ endpoint: "http://127.0.0.1:8093", macaroon: "00aa", nodeIdentity: receiver,
    network: { ...regtest, name: "regtest" }, clock: () => now, fetch: async (url, init) => {
      const path = new URL(String(url)).pathname; calls.push({ path, ...(init ? { init } : {}) });
      expect(init?.credentials).toBe("omit"); expect(init?.redirect).toBe("error");
      if (path === "/v1/getinfo") return Response.json(info);
      if (path.startsWith("/v1/payreq/")) return Response.json(invoiceResponse);
      if (path.startsWith("/v1/graph/routes/")) return Response.json({ routes });
      if (path === "/v2/router/route/send") return unknownPolling ? new Response("lost outcome", { status: 503 }) : new Promise<Response>(() => {}); // A hold stays pending until our claim.
      if (path.startsWith("/v2/router/track/")) {
        trackingTimes.push(Date.now()); if (unknownPolling) now += 5000;
        return new Response(JSON.stringify({ result: { payment_hash: binding.payment_hash, value_msat: binding.amount_msat, status: streamStatus } }) + "\n");
      }
      throw new Error("Unexpected request");
    } });
  return { payer, calls, info, setInvoice(value: unknown) { invoiceResponse = value; }, setRoutes(value: unknown) { routes = value; },
    setStatus(value: string) { streamStatus = value; }, setNow(value: number) { now = value; }, trackingTimes,
    setUnknownPolling() { unknownPolling = true; streamStatus = "UNKNOWN"; } };
}

test("construction is disconnected; a full-amount route is bounded and adds only the final MPP secret", async () => {
  const f = fixture(); expect(f.calls).toEqual([]);
  const plan = await f.payer.plan(invoice, binding, limits);
  expect(plan.feeMsat).toBe("1000"); expect(Object.isFrozen(plan.route)).toBe(true);
  const query = JSON.parse(String(f.calls.find((call) => call.path.startsWith("/v1/graph/routes"))!.init!.body));
  expect(query).toEqual({ final_cltv_delta: 21, fee_limit: { fixed_msat: "2000" }, cltv_limit: 50, route_hints: [], dest_features: [...decoded.features].sort((a, b) => a - b) });
  expect((plan.route.hops as Record<string, unknown>[])[0]!.mpp_record).toEqual({ payment_addr: remote.payment_addr, total_amt_msat: binding.amount_msat });
  let durable = false;
  expect(await f.payer.pay(plan, async () => { durable = true; }, () => {})).toBe("IN_FLIGHT");
  const sends = f.calls.filter((call) => call.path === "/v2/router/route/send");
  expect(durable).toBe(true); expect(sends).toHaveLength(1);
  const payload = JSON.parse(String(sends[0]!.init!.body));
  expect(payload).toEqual({ payment_hash: base64(hexToBytes(binding.payment_hash)), route: plan.route, skip_temp_err: false });
  await expect(f.payer.pay(plan, async () => {}, () => {})).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
  expect(f.calls.filter((call) => call.path === "/v2/router/route/send")).toHaveLength(1);
});
test("default browser fetch retains its Window/global receiver instead of the payer instance", async () => {
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = Object.assign(async function(this: unknown, url: string | URL | Request): Promise<Response> {
    expect(this).toBe(globalThis); calls++;
    if (String(url).endsWith("/v1/getinfo")) return Response.json({ identity_pubkey: receiver, chains: [{ chain: "bitcoin", network: "regtest" }], synced_to_chain: true, block_height: 100 });
    return new Response(JSON.stringify({ result: { payment_hash: binding.payment_hash, value_msat: binding.amount_msat, status: "IN_FLIGHT" } }) + "\n");
  }, { preconnect: () => {} }) as typeof globalThis.fetch;
  try {
    for (const explicit of [false, true]) {
      const before = calls, payer = new BrowserHoldPayer({ endpoint: "http://127.0.0.1:8093", macaroon: "00aa", nodeIdentity: receiver, network: { ...regtest, name: "regtest" }, ...(explicit ? { fetch: globalThis.fetch } : {}) });
      expect(calls).toBe(before); expect(await payer.status(binding.payment_hash, binding.amount_msat)).toBe("IN_FLIGHT"); expect(calls).toBe(before + 2);
    }
  } finally { globalThis.fetch = original; }
});

for (const patch of [{ payment_hash: "0".repeat(64) }, { num_msat: "999999" }, { destination: "02" + "66".repeat(32) },
  { payment_addr: "" }, { expiry: "9999" }, { cltv_expiry: "17" }, { blinded_paths: [{}] }, { features: { 8: {}, 14: {}, 100: {} } }]) {
  test(`node invoice disagreement refuses before route selection: ${Object.keys(patch)[0]}`, async () => {
    const f = fixture(); f.setInvoice({ ...remote, ...patch });
    await expect(f.payer.plan(invoice, binding, limits)).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
    expect(f.calls.some((call) => call.path.includes("/graph/routes") || call.path.includes("/route/send"))).toBe(false);
  });
}

for (const change of ["fee", "lock", "expiry", "destination", "amount", "custom", "secret", "empty", "multiple", "unsafe channel", "alias", "secret field"]) {
  test(`unsafe route refuses without dispatch: ${change}`, async () => {
    const f = fixture(), altered = structuredClone(route);
    if (change === "fee") altered.total_fees_msat = "3000";
    if (change === "lock") altered.total_time_lock = 151;
    if (change === "expiry") altered.hops[0]!.expiry = 119;
    if (change === "destination") altered.hops[0]!.pub_key = "02" + "66".repeat(32);
    if (change === "amount") altered.hops[0]!.amt_to_forward_msat = "1000001";
    if (change === "unsafe channel") altered.hops[0]!.chan_id = "18446744073709551616";
    if (change === "alias") Object.assign(altered.hops[0]!, { amtToForwardMsat: "1000001" });
    if (change === "secret field") Object.assign(altered, { recoverySecret: "not-public-metadata" });
    if (change === "custom") Object.assign(altered.hops[0]!, { custom_records: { 100000: "AA==" } });
    if (change === "secret") Object.assign(altered.hops[0]!, { mpp_record: { payment_addr: remote.payment_addr, total_amt_msat: binding.amount_msat } });
    if (change === "empty") altered.hops = [];
    f.setRoutes(change === "multiple" ? [altered, altered] : [altered]);
    await expect(f.payer.plan(invoice, binding, limits)).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
    expect(f.calls.some((call) => call.path.includes("/route/send"))).toBe(false);
  });
}

for (const change of ["identity", "network", "sync", "height", "expiry", "permission", "durability"]) {
  test(`fresh submission attestation and durable permission cannot be bypassed: ${change}`, async () => {
    const f = fixture(), plan = await f.payer.plan(invoice, binding, limits); let authorized = false;
    if (change === "identity") f.info.identity_pubkey = "02" + "66".repeat(32);
    if (change === "network") f.info.chains[0]!.network = "mainnet";
    if (change === "sync") f.info.synced_to_chain = false;
    if (change === "height") f.info.block_height = 110;
    if (change === "expiry") f.setNow(2000000);
    const authorize = async () => { authorized = true; if (change === "durability") throw new Error("commit failed"); };
    await expect(f.payer.pay(plan, authorize, () => { if (change === "permission") throw new Error("withdrawn"); })).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
    expect(f.calls.some((call) => call.path.includes("/route/send"))).toBe(false);
    expect(authorized).toBe(change === "durability");
  });
}

test("approval withdrawn across durable authorization prevents POST and never makes the plan repayable", async () => {
  const f = fixture(), plan = await f.payer.plan(invoice, binding, limits); let allowed = true;
  await expect(f.payer.pay(plan, async () => { allowed = false; }, () => { if (!allowed) throw new Error("withdrawn"); })).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
  await expect(f.payer.pay(plan, async () => {}, () => {})).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
  expect(f.calls.some((call) => call.path.includes("/route/send"))).toBe(false);
});

for (const change of ["height", "identity", "network", "deadline"]) {
  test(`authorization suspension cannot bypass refreshed node bounds: ${change}`, async () => {
    const f = fixture(), plan = await f.payer.plan(invoice, binding, limits);
    await expect(f.payer.pay(plan, async () => {
      if (change === "height") f.info.block_height = 110;
      if (change === "identity") f.info.identity_pubkey = "02" + "66".repeat(32);
      if (change === "network") f.info.chains[0]!.network = "mainnet";
      if (change === "deadline") f.setNow(2000000);
    }, () => {})).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
    await expect(f.payer.pay(plan, async () => {}, () => {})).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
    expect(f.calls.some((call) => call.path.includes("/route/send"))).toBe(false);
  });
}

test("an immediate unknown submission never removes the bounded polling delay or authorizes retry", async () => {
  const f = fixture(), plan = await f.payer.plan(invoice, binding, limits); f.setUnknownPolling();
  expect(await f.payer.pay(plan, async () => {}, () => {})).toBe("UNKNOWN");
  expect(f.calls.filter((call) => call.path.includes("/route/send"))).toHaveLength(1);
  expect(f.trackingTimes).toHaveLength(3);
  expect(f.trackingTimes[1]! - f.trackingTimes[0]!).toBeGreaterThanOrEqual(250);
  expect(f.trackingTimes[2]! - f.trackingTimes[1]!).toBeGreaterThanOrEqual(250);
  await expect(f.payer.pay(plan, async () => {}, () => {})).rejects.toBeInstanceOf(BrowserHoldPaymentRefusedError);
});
