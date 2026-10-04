// Disposable conformance controller only. No production entrypoint or automatic provisioning.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { Database } from "bun:sqlite";
import { LndInvoiceBackend, lndRestTransport } from "../../src/lnd";
import { MerchantLedger } from "../../src/merchant";
import { createMerchantService, verifyAcceptance, type SignedAcceptance } from "../../src/server";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";

if (process.env.RILLSWAP_DISPOSABLE_BUN_LND !== "1" || Bun.version !== "1.3.11" || Bun.revision !== "af24e281ebacd6ac77c0f14b4206599cf4ae1c9f") throw new Error("Pinned disposable harness only");
const root = "/tmp/bun-merchant";
const config = JSON.parse(readFileSync(root + "/config.json", "utf8")) as { receiver: string; origin: string };
const issuanceKey = readFileSync(root + "/issuance.key"), statusKey = readFileSync(root + "/status.key"), eventKey = readFileSync(root + "/event.key");
const macaroon = readFileSync(root + "/macaroon"), adminToken = readFileSync(root + "/admin.token", "utf8");
const journalPath = root + "/journal.json", journal = JSON.parse(readFileSync(journalPath, "utf8")) as { addCalls: number };
const transport = lndRestTransport("https://127.0.0.1:8081/", readFileSync("/work/public/b.cert"), macaroon);
const backend = new LndInvoiceBackend({ call: async (method, path, body) => {
  if (method === "POST") {
    journal.addCalls++;
    writeFileSync(journalPath, JSON.stringify(journal), { mode: 0o600 });
    // Secret audit material stays separate from the invocation counter, inside private tmpfs only.
    writeFileSync(root + "/audit.preimage", Buffer.from(String(body!.r_preimage), "base64"), { mode: 0o600 });
  }
  return transport.call(method, path, body);
} }, { origin: config.origin, receiver: config.receiver, network: "regtest" }, issuanceKey);
const identity = await backend.identity();
const mode = process.argv[2];
if (mode === "provision") { MerchantLedger.provision(root + "/merchant.sqlite", identity).close(); console.log(JSON.stringify({ provisioned: true })); process.exit(0); }
if (!["issue_fault", "observe_fault", "normal"].includes(mode!)) throw new Error("Explicit harness mode required");
const ledger = MerchantLedger.open(root + "/merchant.sqlite", identity);
let issueFault = mode === "issue_fault", observeFault = mode === "observe_fault";
const service = createMerchantService({ ledger, adminToken, statusKey, eventSigningKey: eventKey,
  issuer: { identity: () => backend.identity(), create: async (operation) => {
    const invoice = await backend.create(operation);
    if (issueFault) { issueFault = false; throw new Error("Injected loss before invoice commit"); } return invoice;
  } }, observer: { identity: () => backend.identity(), lookup: async (hash) => {
    const receipt = await backend.lookup(hash);
    if (observeFault && receipt.state === "SETTLED") { observeFault = false; throw new Error("Injected loss before receipt commit"); } return receipt;
  } },
});
const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: service.fetch });
const publicKey = bytesToHex(ed25519.getPublicKey(eventKey));
const secrets = (): Buffer[] => [issuanceKey, statusKey, eventKey, macaroon,
  ...(existsSync(root + "/audit.preimage") ? [readFileSync(root + "/audit.preimage")] : [])];
const secretEncodings = (): string[] => secrets().flatMap((value) => [value.toString("hex"), value.toString("base64")]);
console.log(JSON.stringify({ ready: true, publicKey }));
try {
  for await (const line of createInterface({ input: process.stdin })) {
    try {
      const command = JSON.parse(line) as { action: string; path?: string; method?: string; token?: string; key?: string; body?: unknown; intentId?: string; fail?: boolean };
      let result: unknown;
      if (command.action === "http") {
        const response = await fetch(`http://127.0.0.1:${server.port}` + command.path, { method: command.method ?? "GET", redirect: "error", signal: AbortSignal.timeout(10000),
          headers: { Authorization: "Bearer " + (command.token ?? adminToken), ...(command.body === undefined ? {} : { "Content-Type": "application/json" }), ...(command.key ? { "Idempotency-Key": command.key } : {}) },
          body: command.body === undefined ? undefined : JSON.stringify(command.body) });
        result = { status: response.status, body: await response.json() };
        if (secretEncodings().some((value) => JSON.stringify(result).includes(value)) || JSON.stringify(result).includes(adminToken)) throw new Error("Public secret projection");
      } else if (command.action === "tick") result = await service.tick();
      else if (command.action === "attempt") {
        const attempt = ledger.attemptForIntent(command.intentId!); result = { id: attempt?.id, operationId: attempt?.operation_id, state: attempt?.state };
      } else if (command.action === "deliver") {
        const delivered: SignedAcceptance[] = [];
        try { await service.deliverEvents(async (event) => { delivered.push(event); if (command.fail) throw new Error("Injected delivery loss"); }); }
        catch { if (!command.fail) throw new Error("Unexpected delivery failure"); }
        result = { delivered, pending: ledger.pendingEvents().length };
      } else if (command.action === "audit") {
        const db = new Database(root + "/merchant.sqlite", { readonly: true });
        let projection: string;
        try { projection = JSON.stringify(["metadata", "intents", "attempts", "receipts", "outbox"].map((table) => db.query(`SELECT * FROM ${table}`).all())); } finally { db.close(); }
        const sensitive = secretEncodings();
        if (sensitive.some((value) => projection.includes(value)) || projection.includes(adminToken)) throw new Error("Secret projection");
        for (const suffix of ["", "-wal", "-shm"]) {
          const path = root + "/merchant.sqlite" + suffix;
          if (existsSync(path)) { const bytes = readFileSync(path);
            if (secrets().some((value) => bytes.includes(value)) || sensitive.some((value) => bytes.includes(Buffer.from(value))) || bytes.includes(Buffer.from(adminToken))) throw new Error("Database side-file secret projection");
          }
        }
        const receipts = ledger.eventsForIntent(command.intentId!);
        result = { addCalls: journal.addCalls, pending: ledger.pendingEvents().length, events: receipts.length, secretFree: true,
          identityStable: identity.issuerId === "lnd_" + createHash("sha256").update(issuanceKey).digest("hex") };
      } else if (command.action === "verify") {
        const events = command.body as SignedAcceptance[];
        result = { valid: events.length === 1 && verifyAcceptance(events[0]!, publicKey) };
      } else if (command.action === "stop") { console.log(JSON.stringify({ ok: true })); break; }
      else throw new Error("Unknown harness command");
      console.log(JSON.stringify({ ok: true, result }));
    } catch { console.log(JSON.stringify({ ok: false })); }
  }
} finally { server.stop(true); ledger.close(); }
