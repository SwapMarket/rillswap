import { afterEach, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { MerchantLedger, type ReceiptObserver } from "../src/merchant";
import { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import { createMerchantService, signAcceptance, verifyAcceptance, type AcceptanceSigner, type KeylessMerchantServiceOptions, type MerchantServiceOptions, type SignedAcceptance } from "../src/server";
import { receiver, testInvoice } from "./helpers";

const origin = "https://merchant.example", publicKey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const fixtureKey = () => new Uint8Array(32).fill(17);
const cleanups: (() => void)[] = [];
afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });
function fixture() {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync("tmp/acceptance-signer-"); chmodSync(directory, 0o700);
  const identity = { origin, receiver, network: "regtest" as const, issuerId: "fixture" }, ledgerPath = join(directory, "merchant.sqlite"), consumerPath = join(directory, "consumer.sqlite");
  const ledger = MerchantLedger.provision(ledgerPath, identity); cleanups.push(() => { try { ledger.close(); } catch {} finally { rmSync(directory, { recursive: true, force: true }); } });
  const consumerIdentity = { merchantOrigin: origin, receiver, network: "regtest" as const, merchantPublicKey: publicKey };
  const consumer = LightningAcceptanceConsumer.provision(consumerPath, consumerIdentity); cleanups.unshift(() => { try { consumer.close(); } catch {} });
  const issuer = { identity: async () => identity, create: async () => testInvoice("keyless") };
  const observer: ReceiptObserver = { identity: async () => identity, lookup: async (hash) => ({ receiver, network: "regtest", paymentHash: hash,
    invoiceAmountMsat: "1000000", paidMsat: "1000000", state: "SETTLED", settledAt: 1090 }) };
  const options = { ledger, issuer, observer, adminToken: "fixture_keyless_admin_token_0000000", statusKey: new Uint8Array(32).fill(2), now: () => 1200 };
  async function paid() {
    const intent = ledger.createIntent("signer-order", "1000000", 1100, "signer_intent_request_001", 1000);
    const attempt = ledger.createAttempt(intent.id, "signer_attempt_request_001", 1000); await ledger.issue(attempt.id, issuer, () => 1000);
    consumer.bindOrder(intent.order_ref, intent.amount_msat, ledger.terms(attempt.id)); await ledger.observe(attempt.id, observer, () => 1200);
    return { intent, event: ledger.pendingEvents()[0]! };
  }
  const events = (service: ReturnType<typeof createMerchantService>, id: string, authenticated = true) => service.fetch(new Request(origin + "/v1/intents/" + id + "/events", { headers: authenticated ? { Authorization: "Bearer " + options.adminToken } : {} }));
  return { directory, identity, ledgerPath, consumerPath, ledger, consumer, consumerIdentity, options, paid, events };
}
async function bounded<T>(promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  try { return await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Owned signer deadline expired")), 5000); })]); }
  finally { clearTimeout(timer!); }
}
async function startSigner(directory: string) {
  const path = resolve(directory, "signer.key"); writeFileSync(path, fixtureKey(), { mode: 0o600 });
  const child = Bun.spawn([process.execPath, "tests/fixtures/acceptanceSigner.ts", path], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  const errors = new Response(child.stderr).text(), reader = child.stdout.getReader(); let pending = "", nextId = 0;
  async function line() {
    while (!pending.includes("\n")) { const chunk = await bounded(reader.read()); if (chunk.done || pending.length > 8192) throw new Error("Owned signer pipe refused"); pending += new TextDecoder().decode(chunk.value); }
    const end = pending.indexOf("\n"); if (end > 4096) throw new Error("Owned signer reply exceeds bounds");
    const result = JSON.parse(pending.slice(0, end)); pending = pending.slice(end + 1); return result;
  }
  let queue: Promise<unknown> = Promise.resolve();
  let closed = false;
  const close = async () => {
    if (closed) return; closed = true;
    try { await child.stdin.end(); await bounded(child.exited); }
    finally { if (child.exitCode === null) { child.kill("SIGKILL"); await bounded(child.exited); } void reader.cancel().catch(() => {}); reader.releaseLock(); }
    expect(await errors).toBe(""); expect(child.exitCode).toBe(0);
  };
  try {
    expect(await line()).toEqual({ publicKey });
    const signer: AcceptanceSigner = { publicKey, sign(bytes) {
      const work = queue.then(async () => {
        const id = ++nextId; await child.stdin.write(JSON.stringify({ id, bytes: Buffer.from(bytes).toString("base64") }) + "\n"); await child.stdin.flush();
        const reply = await line(); expect(Object.keys(reply).sort()).toEqual(["id", "signature"]); expect(reply.id).toBe(id);
        return new Uint8Array(Buffer.from(reply.signature, "base64"));
      }); queue = work.catch(() => {}); return work;
    } };
    return { signer, close, child };
  } catch (error) { await close(); throw error; }
}

test("keyless signer uses canonical bytes and exact original envelope interoperability", async () => {
  const f = fixture(), { intent, event } = await f.paid(); let calls = 0, message = "";
  const signer: AcceptanceSigner = { publicKey, sign: async (bytes) => { calls++; message = new TextDecoder().decode(bytes); return ed25519.sign(bytes, fixtureKey()); } };
  const options: KeylessMerchantServiceOptions = { ...f.options, acceptanceSigner: signer, acceptanceConsumer: f.consumer, publishManifest: true };
  expect(Object.hasOwn(options, "eventSigningKey")).toBe(false); const service = createMerchantService(options);
  const manifest = await (await service.fetch(new Request(origin + "/v1/manifest"))).json(); expect(manifest.receiptVerification.publicKey).toBe(publicKey); expect(calls).toBe(0);
  expect((await f.events(service, intent.id, false)).status).toBe(404); expect(calls).toBe(0);
  const response = await f.events(service, intent.id), envelope = (await response.json())[0] as SignedAcceptance;
  expect(envelope).toEqual(signAcceptance(event, fixtureKey())); expect(verifyAcceptance(envelope, publicKey)).toBe(true); expect(calls).toBe(1);
  expect(JSON.parse(message)[0]).toBe("rillswap-payment-event/1"); expect(message).not.toContain(f.options.adminToken); expect(message).not.toContain(testInvoice("keyless"));
});

test("invalid signing sources refuse without fallback or remote signing", () => {
  const f = fixture(); let calls = 0;
  const signer = { publicKey, sign: async (bytes: Uint8Array) => { calls++; return ed25519.sign(bytes, fixtureKey()); } };
  for (const invalid of [{ ...f.options }, { ...f.options, eventSigningKey: fixtureKey(), acceptanceSigner: signer },
    { ...f.options, eventSigningKey: fixtureKey(), acceptanceSigner: undefined }, { ...f.options, acceptanceSigner: null },
    { ...f.options, acceptanceSigner: { ...signer, publicKey: "invalid" } }, { ...f.options, acceptanceSigner: { publicKey, sign: undefined } }]) {
    expect(() => createMerchantService(invalid as unknown as KeylessMerchantServiceOptions)).toThrow();
  }
  expect(() => createMerchantService({ ...f.options, acceptanceSigner: { ...signer, publicKey: bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(19))) }, acceptanceConsumer: f.consumer })).toThrow("identity");
  expect(calls).toBe(0);
});

test("keyless configuration rejects small-order public keys before a trivial signature can be accepted", () => {
  const f = fixture(); let calls = 0;
  for (const publicKey of ["00".repeat(32), "01" + "00".repeat(31)]) {
    expect(() => createMerchantService({ ...f.options, acceptanceSigner: { publicKey, sign: async () => { calls++; return new Uint8Array(64); } } })).toThrow("Invalid acceptance signer");
  }
  expect(calls).toBe(0);
});

test("malformed, wrong-key, tampered-message and failed signatures never expose or acknowledge events", async () => {
  const signers = [
    async () => new Uint8Array(63), async () => new Uint8Array(64),
    async (bytes: Uint8Array) => ed25519.sign(bytes, new Uint8Array(32).fill(19)),
    async (bytes: Uint8Array) => { bytes.fill(0); return ed25519.sign(bytes, fixtureKey()); },
    async () => { throw new Error("PRIVATE_SIGNER_REASON"); },
  ];
  for (const sign of signers) {
    const f = fixture(), { intent } = await f.paid(); const service = createMerchantService({ ...f.options, acceptanceSigner: { publicKey, sign } });
    const response = await f.events(service, intent.id); expect(response.status).toBe(400); expect(JSON.stringify(await response.json())).not.toContain("PRIVATE_SIGNER_REASON");
    let delivered = false;
    await expect(service.deliverEvents(async () => { delivered = true; })).rejects.toThrow("Acceptance signing refused");
    expect(delivered).toBe(false); expect(f.ledger.pendingEvents().length).toBe(1); expect(f.ledger.getIntent(intent.id).status).toBe("paid");
    expect(f.consumer.getOrder("signer-order").state).toBe("waiting");
  }
});

test("custom public key and method are captured once while canonical bytes remain isolated across await", async () => {
  const f = fixture(), { intent, event } = await f.paid(); let keyReads = 0, methodReads = 0;
  const signer = { get publicKey() { keyReads++; return keyReads === 1 ? publicKey : "22".repeat(32); },
    get sign() { methodReads++; return async (bytes: Uint8Array) => {
      const signature = ed25519.sign(bytes, fixtureKey()); await Promise.resolve(); bytes.fill(0); return signature;
    }; } };
  const service = createMerchantService({ ...f.options, acceptanceSigner: signer, acceptanceConsumer: f.consumer, publishManifest: true });
  const envelope = (await (await f.events(service, intent.id)).json())[0]; expect(envelope).toEqual(signAcceptance(event, fixtureKey())); expect(keyReads).toBe(1); expect(methodReads).toBe(1);
  await service.deliverEvents(async (signed) => { expect(Object.isFrozen(signed) && Object.isFrozen(signed.event)).toBe(true); expect(f.consumer.consume(signed, 1200).state).toBe("accepted"); });
  expect(keyReads).toBe(1); expect(methodReads).toBe(1);
});

test("separate key-holder process signs concurrent reads and stable delivery after acknowledgment loss and reopen", async () => {
  const f = fixture(), { intent, event } = await f.paid(); const child = await startSigner(f.directory);
  let active = child;
  try {
    const service = createMerchantService({ ...f.options, acceptanceSigner: child.signer, acceptanceConsumer: f.consumer, publishManifest: true });
    const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: service.fetch });
    try {
      const responses = await Promise.all([0, 1].map(() => fetch("http://127.0.0.1:" + server.port + "/v1/intents/" + intent.id + "/events", { headers: { Authorization: "Bearer " + f.options.adminToken } })));
      for (const response of responses) expect((await response.json())[0]).toEqual(signAcceptance(event, fixtureKey()));
      await expect(service.deliverEvents(async (signed) => { f.consumer.consume(signed, 1200); throw new Error("Owned acknowledgment loss"); })).rejects.toThrow("acknowledgment loss");
      expect(f.ledger.pendingEvents().length).toBe(1);
    } finally { await server.stop(true); }
    const accepted = f.consumer.getOrder("signer-order"); f.consumer.close(); f.ledger.close(); await child.close();
    active = await startSigner(f.directory);
    const ledger = MerchantLedger.open(f.ledgerPath, f.identity), consumer = LightningAcceptanceConsumer.open(f.consumerPath, f.consumerIdentity);
    try {
      const reopened = createMerchantService({ ...f.options, ledger, acceptanceSigner: active.signer, acceptanceConsumer: consumer });
      await reopened.deliverEvents(async (signed) => { expect(signed).toEqual(signAcceptance(event, fixtureKey())); expect(consumer.consume(signed, 1300)).toEqual(accepted); });
      expect(ledger.pendingEvents().length).toBe(0); expect(consumer.getOrder("signer-order")).toEqual(accepted);
    } finally { consumer.close(); ledger.close(); }
  } finally { await active.close(); }
}, 20000);

test("legacy options type, mutable key default and pinned Buffer modes remain compatible", async () => {
  const f = fixture(), { intent } = await f.paid(); const key = Buffer.from(fixtureKey());
  const options: MerchantServiceOptions = { ...f.options, eventSigningKey: key };
  const legacy = createMerchantService(options); key.fill(19);
  const changed = (await (await f.events(legacy, intent.id)).json())[0]; expect(verifyAcceptance(changed, publicKey)).toBe(false);
  const originalBuffer = Buffer.from(fixtureKey());
  const pinned = createMerchantService({ ...options, eventSigningKey: originalBuffer, publishManifest: true }); originalBuffer.fill(19);
  expect(verifyAcceptance((await (await f.events(pinned, intent.id)).json())[0], publicKey)).toBe(true);
});
