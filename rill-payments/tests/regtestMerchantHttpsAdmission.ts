// Owned actual regtest runner, bundled only by the explicit provider fixture.
import { readFileSync } from "node:fs";
import { request } from "node:https";
import { LndInvoiceBackend, lndRestTransport } from "../src/lnd";
import { MerchantLedger } from "../src/merchant";
import { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import { createMerchantService } from "../src/server";
import { createCheckout, type CheckoutCheckpoint, type CheckoutStore } from "../src/sdk";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";

function requireProof(value: unknown): asserts value { if (!value) throw new Error("Admission proof refused"); }
function emit(value: object): void { console.log(JSON.stringify(value)); }
async function main() {
  requireProof(process.env.RILLSWAP_MERCHANT_ADMISSION === "1" && process.argv.length === 3);
  const config = JSON.parse(readFileSync(process.argv[2]!, "utf8"));
  const certificate = readFileSync(config.listenerCertificatePath), listenerKey = readFileSync(config.listenerKeyPath);
  const eventKey = readFileSync(config.eventKeyPath), statusKey = readFileSync(config.statusKeyPath), adminToken = readFileSync(config.adminTokenPath, "utf8");
  const backend = new LndInvoiceBackend(lndRestTransport(config.endpoint, readFileSync(config.certificatePath), readFileSync(config.macaroonPath)),
    { origin: config.origin, receiver: config.receiver, network: "regtest" }, readFileSync(config.issuanceKeyPath));
  const identity = await backend.identity();
  const consumerIdentity = { merchantOrigin: config.origin, receiver: config.receiver, network: "regtest" as const, merchantPublicKey: bytesToHex(ed25519.getPublicKey(eventKey)) };
  let ledger = MerchantLedger.provision(config.ledgerPath, identity), consumer = LightningAcceptanceConsumer.provision(config.consumerPath, consumerIdentity);
  let service = createMerchantService({ ledger, issuer: backend, observer: backend, adminToken, statusKey, eventSigningKey: eventKey, acceptanceConsumer: consumer });
  const listen = () => Bun.serve({ hostname: "127.0.0.1", port: Number(config.listenerPort), tls: { cert: certificate, key: listenerKey }, fetch: service.fetch });
  let server = listen();
  const reader = Bun.stdin.stream().getReader();
  let pending = "";
  async function line(seconds: number): Promise<Record<string, unknown>> {
    const deadline = performance.now() + seconds * 1000;
    while (!pending.includes("\n")) {
      requireProof(pending.length <= 8192 && performance.now() < deadline);
      let timer: ReturnType<typeof setTimeout>;
      try {
        const part = await Promise.race([reader.read(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Admission pipe expired")), deadline - performance.now()); })]);
        requireProof(!part.done); pending += new TextDecoder("utf-8", { fatal: true }).decode(part.value);
      } finally { clearTimeout(timer!); }
    }
    const end = pending.indexOf("\n"); requireProof(end <= 8192);
    const text = pending.slice(0, end); pending = pending.slice(end + 1);
    const value = JSON.parse(text); requireProof(value && typeof value === "object" && !Array.isArray(value)); return value;
  }
  const transport: typeof fetch = new Proxy(globalThis.fetch, { apply: async (_target, _this, args: [RequestInfo | URL, RequestInit?]) => {
    const [input, init] = args, url = new URL(String(input)); requireProof(url.origin === config.origin);
    return new Promise<Response>((resolve, reject) => {
      const outgoing = request(url, { method: init?.method ?? "GET", headers: Object.fromEntries(new Headers(init?.headers).entries()),
        ca: certificate, rejectUnauthorized: true, agent: false, timeout: 5000 }, (incoming) => {
        const chunks: Buffer[] = []; let size = 0;
        incoming.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 8192) outgoing.destroy(new Error("Admission response too large")); else chunks.push(chunk); });
        incoming.on("error", () => reject(new Error("Admission HTTPS failed")));
        incoming.on("end", () => resolve(new Response(Buffer.concat(chunks), { status: incoming.statusCode!, headers: { "Content-Type": "application/json" } })));
      });
      outgoing.on("error", () => reject(new Error("Admission HTTPS failed"))); outgoing.on("timeout", () => outgoing.destroy()); outgoing.end();
    });
  } });
  try {
    emit({ kind: "server-ready", port: server.port, publicKey: consumerIdentity.merchantPublicKey });
    const start = await line(30); requireProof(Object.keys(start).sort().join(",") === "intentId,kind,statusToken" && start.kind === "exercise-withheld");
    requireProof(typeof start.intentId === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(start.intentId) && typeof start.statusToken === "string");
    const rows = new Map<string, CheckoutCheckpoint>();
    const store: CheckoutStore = { load: async (id) => rows.get(id) ?? null,
      begin: async (record) => { if (rows.has(record.attemptId)) return false; rows.set(record.attemptId, structuredClone(record)); return true; },
      update: async (record) => { rows.set(record.attemptId, structuredClone(record)); } };
    let walletCalls = 0, authorized = false;
    const checkout = createCheckout({ intentUrl: config.origin + "/v1/intents/" + start.intentId, statusToken: start.statusToken,
      policy: { version: "native-lightning/1", merchantOrigin: config.origin, receiver: config.receiver, network: "regtest", maxBuyerExtraMsat: "0", maxBuyerExtraBps: 0 },
      recoveryStore: store, now: () => Math.floor(Date.now() / 1000), fetch: transport,
      wallet: { canLimitFees: true, payInvoice: async (invoice, fee) => {
        requireProof(authorized && walletCalls === 0 && fee === "0"); walletCalls++;
        emit({ kind: "pay", invoice, feeMsat: fee });
        const ack = await line(90); requireProof(Object.keys(ack).join(",") === "paid" && ack.paid === true);
      } } });
    requireProof((await checkout.open()).attempt === null);
    let withheld = false; try { await checkout.pay(); } catch { withheld = true; }
    requireProof(withheld && walletCalls === 0 && rows.size === 0);
    emit({ kind: "withheld", walletCalls, checkpointCount: rows.size });
    const release = await line(40); requireProof(Object.keys(release).join(",") === "kind" && release.kind === "authorized"); authorized = true;
    const original = await checkout.open(); requireProof(original.attempt !== null);
    await checkout.pay(); requireProof(Number(walletCalls) === 1 && Number(rows.size) === 1 && (await checkout.open()).status === "waiting");
    let refused = false; try { await checkout.pay(); } catch { refused = true; } requireProof(refused && Number(walletCalls) === 1);
    const until = performance.now() + 10000;
    while (true) {
      requireProof((await service.tick()).failedAttemptIds.length === 0);
      const status = (await checkout.open()).status; requireProof(performance.now() < until);
      if (status === "paid") break;
      await Bun.sleep(100);
    }
    requireProof(consumer.getOrder("owned-admission-order").state === "waiting");
    let deliveries = 0, lostAck = false;
    try { await service.deliverEvents(async (envelope) => {
      deliveries++; requireProof(consumer.consume(envelope, Math.floor(Date.now() / 1000)).state === "accepted"); throw new Error("Owned acknowledgment loss");
    }); } catch { lostAck = true; }
    requireProof(lostAck && deliveries === 1 && ledger.pendingEvents().length === 1);
    const accepted = consumer.getOrder("owned-admission-order"), invoice = ledger.attemptForIntent(start.intentId)!.invoice;
    await server.stop(true); ledger.close(); consumer.close();
    ledger = MerchantLedger.open(config.ledgerPath, identity); consumer = LightningAcceptanceConsumer.open(config.consumerPath, consumerIdentity);
    service = createMerchantService({ ledger, issuer: backend, observer: backend, adminToken, statusKey, eventSigningKey: eventKey, acceptanceConsumer: consumer }); server = listen();
    requireProof((await checkout.open()).status === "paid" && ledger.attemptForIntent(start.intentId)!.invoice === invoice);
    await service.deliverEvents(async (envelope) => { deliveries++; requireProof(consumer.consume(envelope, Math.floor(Date.now() / 1000)).eventId === accepted.eventId); });
    requireProof(Number(deliveries) === 2 && ledger.pendingEvents().length === 0 && consumer.getOrder("owned-admission-order").eventId === accepted.eventId && Number(walletCalls) === 1);
    emit({ kind: "complete", invoiceWithheld: true, singleDispatch: true, receiverAccepted: true, durableAcceptance: true, replayDeduplicated: true, noExternalFulfillment: true });
  } finally {
    try { void reader.cancel().catch(() => {}); reader.releaseLock(); }
    finally { try { await server.stop(true); } finally { try { ledger.close(); } finally { consumer.close(); } } }
  }
}
try { await main(); } catch { console.error("Owned merchant admission proof refused"); process.exitCode = 1; }
