import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { LndInvoiceBackend, LndNotFound, lndRestTransport, type LndTransport } from "../src/lnd";
import { receiver, testInvoice } from "./helpers";
import { invoiceBinding } from "../src/bolt11";

function fixture() {
  let stored: Record<string, unknown> | null = null, creations = 0, loseResponse = false;
  const transport: LndTransport = { async call(method, path, body) {
    if (path === "/v1/getinfo") return { identity_pubkey: receiver, chains: [{ chain: "bitcoin", network: "regtest" }], synced_to_chain: true };
    if (method === "GET") { if (!stored) throw new LndNotFound(); return stored; }
    creations++;
    const preimage = Buffer.from(body!.r_preimage as string, "base64"); const hash = createHash("sha256").update(preimage).digest("hex");
    // Use a real signed invoice whose payment hash is the deterministic HMAC hash.
    const invoice = testInvoice("lnd", body!.value_msat as string, 1000, 2000, "bcrt", hash);
    stored = { payment_request: invoice, r_hash: Buffer.from(hash, "hex").toString("base64"), value_msat: body!.value_msat,
      amt_paid_msat: "0", state: "OPEN", settle_date: "0", r_preimage: body!.r_preimage };
    if (loseResponse) throw new Error("response lost"); return { payment_request: invoice };
  } };
  const backend = new LndInvoiceBackend(transport, { origin: "https://merchant.example", receiver, network: "regtest" }, new Uint8Array(32).fill(9), () => 1000);
  return { backend, transport, creations: () => creations, lose: () => { loseResponse = true; }, receipt: () => stored! };
}
test("HMAC issuance survives response loss and returns the exact invoice", async () => {
  const f = fixture(); f.lose(); const identity = await f.backend.identity();
  const op = { ...identity, operationId: "operation_fixture_001", amountMsat: "1000000", expiresAt: 2000 };
  const first = await f.backend.create(op); expect(await f.backend.create(op)).toBe(first); expect(f.creations()).toBe(1);
  const binding = invoiceBinding(first, "regtest");
  const observed = await f.backend.lookup(binding.payment_hash);
  expect(observed.state).toBe("OPEN"); expect(JSON.stringify(observed)).not.toContain("preimage");
  Object.assign(f.receipt(), { state: "SETTLED", settle_date: "1100", amt_paid_msat: "1000000" });
  expect((await f.backend.lookup(binding.payment_hash)).settledAt).toBe(1100);
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
