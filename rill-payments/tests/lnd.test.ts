import { expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import { LndInvoiceBackend, LndNotFound, lndRestTransport, type LndTransport } from "../src/lnd";
import { receiver, testInvoice } from "./helpers";
import { invoiceBinding } from "../src/bolt11";
import { NETWORKS, type Network } from "../src/contract";

function fixture(network: Network = "regtest", currency = { regtest: "bcrt", signet: "tbs", mainnet: "bc" }[network]) {
  let stored: Record<string, unknown> | null = null, creations = 0, loseResponse = false;
  const transport: LndTransport = { async call(method, path, body) {
    if (path === "/v1/getinfo") return { identity_pubkey: receiver, chains: [{ chain: "bitcoin", network }], synced_to_chain: true };
    if (method === "GET") { if (!stored) throw new LndNotFound(); return stored; }
    creations++;
    const preimage = Buffer.from(body!.r_preimage as string, "base64"); const hash = createHash("sha256").update(preimage).digest("hex");
    // Use a real signed invoice whose payment hash is the deterministic HMAC hash.
    const invoice = testInvoice("lnd", body!.value_msat as string, 1000, 2000, currency, hash);
    stored = { payment_request: invoice, r_hash: Buffer.from(hash, "hex").toString("base64"), value_msat: body!.value_msat,
      amt_paid_msat: "0", state: "OPEN", settle_date: "0", r_preimage: body!.r_preimage };
    if (loseResponse) throw new Error("response lost"); return { payment_request: invoice };
  } };
  const backend = new LndInvoiceBackend(transport, { origin: "https://merchant.example", receiver, network }, new Uint8Array(32).fill(9), () => 1000);
  return { backend, transport, creations: () => creations, lose: () => { loseResponse = true; }, receipt: () => stored! };
}
for (const network of NETWORKS) {
test(`HMAC issuance on ${network} survives response loss and restart with the exact invoice`, async () => {
  const f = fixture(network); expect(f.creations()).toBe(0); f.lose(); const identity = await f.backend.identity();
  const op = { ...identity, operationId: "operation_fixture_001", amountMsat: "1000000", expiresAt: 2000 };
  const first = await f.backend.create(op); expect(await f.backend.create(op)).toBe(first); expect(f.creations()).toBe(1);
  const restarted = new LndInvoiceBackend(f.transport, identity, new Uint8Array(32).fill(9), () => 1000);
  expect(await restarted.create(op)).toBe(first); expect(f.creations()).toBe(1);
  const binding = invoiceBinding(first, network);
  const observed = await f.backend.lookup(binding.payment_hash);
  expect(observed.state).toBe("OPEN"); expect(JSON.stringify(observed)).not.toContain("preimage");
  Object.assign(f.receipt(), { state: "SETTLED", settle_date: "1100", amt_paid_msat: "1000000" });
  expect((await f.backend.lookup(binding.payment_hash)).settledAt).toBe(1100);
});
}
test("mainnet LND rejects another chain and invoice currency without issuing on identity mismatch", async () => {
  const f = fixture();
  const backend = new LndInvoiceBackend(f.transport, { ...f.backend.configuredIdentity, network: "mainnet" }, new Uint8Array(32).fill(9));
  await expect(backend.create({ ...backend.configuredIdentity, operationId: "operation_fixture_001", amountMsat: "1000000", expiresAt: 2000 })).rejects.toThrow("chain or freshness mismatch");
  expect(f.creations()).toBe(0);
  const wrongInvoice = fixture("mainnet", "bcrt"), identity = await wrongInvoice.backend.identity();
  await expect(wrongInvoice.backend.create({ ...identity, operationId: "operation_fixture_001", amountMsat: "1000000", expiresAt: 2000 })).rejects.toThrow("invoice is not for");
});
test("rotation, mismatched receiver and unsupported transport are refused", async () => {
  const f = fixture(), identity = await f.backend.identity();
  await expect(f.backend.create({ ...identity, issuerId: "rotated", operationId: "operation_fixture_001", amountMsat: "1000000", expiresAt: 2000 })).rejects.toThrow();
  const wrong = new LndInvoiceBackend(f.transport, { origin: identity.origin, receiver: "03" + "1".repeat(64), network: "regtest" }, new Uint8Array(32).fill(9));
  await expect(wrong.identity()).rejects.toThrow();
  for (const url of ["http://127.0.0.1:8080", "https://localhost:8080", "https://example.com", "https://127.0.0.1:8080/path"]) {
    expect(() => lndRestTransport(url, new Uint8Array([1]), new Uint8Array([1]))).toThrow();
  }
});

for (const reason of ["receiver_mismatch", "chain_mismatch", "not_synced"] as const) {
  test(`LND identity diagnostic exposes only the fixed ${reason} reason`, async () => {
    const log = spyOn(console, "error").mockImplementation(() => {});
    const secret = "private_backend_identity_do_not_log";
    const info = { identity_pubkey: reason === "receiver_mismatch" ? secret : receiver,
      chains: [{ chain: reason === "chain_mismatch" ? secret : "bitcoin", network: "regtest" }], synced_to_chain: reason !== "not_synced", private: secret };
    const backend = new LndInvoiceBackend({ call: async () => info },
      { origin: "https://merchant.example", receiver, network: "regtest" }, new Uint8Array(32).fill(9));
    try {
      await expect(backend.identity()).rejects.toThrow("LND receiver identity, chain or freshness mismatch");
      expect(log.mock.calls).toEqual([[JSON.stringify({ diagnostic: "lnd_identity_refused", reason })]]);
      expect(JSON.stringify(log.mock.calls)).not.toContain(secret);
    } finally { log.mockRestore(); }
  });
}

test.each([undefined, "true"])("missing or nonboolean LND freshness %p never admits identity", async (freshness) => {
  const log = spyOn(console, "error").mockImplementation(() => {}), calls: string[] = [];
  const backend = new LndInvoiceBackend({ call: async (_method, path) => {
    calls.push(path); return { identity_pubkey: receiver, chains: [{ chain: "bitcoin", network: "regtest" }], synced_to_chain: freshness };
  } }, { origin: "https://merchant.example", receiver, network: "regtest" }, new Uint8Array(32).fill(9));
  try {
    await expect(backend.identity()).rejects.toThrow("LND receiver identity, chain or freshness mismatch");
    expect(calls).toEqual(["/v1/getinfo"]);
    expect(log.mock.calls).toEqual([[JSON.stringify({ diagnostic: "lnd_identity_refused", reason: "not_synced" })]]);
  } finally { log.mockRestore(); }
});
