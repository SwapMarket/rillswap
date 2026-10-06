// Synthetic LND identity/invoice fixtures, actual Bun/HTTPS/SQLite. No funding.
import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash, X509Certificate } from "node:crypto";
import { request } from "node:https";
import { dirname, join, resolve } from "node:path";
import { receiver, testInvoice } from "./helpers";
import { LndInvoiceBackend, lndRestTransport } from "../src/lnd";
import { MerchantLedger } from "../src/merchant";
import { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { parseNativeLightningMerchantManifest } from "../src/manifest";

const root = resolve("../tmp");
const fixtureCredential = Buffer.from("synthetic-lnd-read-credential");
const admin = "synthetic_https_admin_credential_0001";
type Child = Bun.Subprocess<"ignore" | "pipe", "pipe", "pipe">;

async function bounded<T>(promise: Promise<T>, milliseconds = 5000): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  try { return await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Owned diagnostic timed out")), milliseconds); })]); }
  finally { clearTimeout(timer!); }
}
function certificates(directory: string, name: string, ip = "127.0.0.1") {
  const cert = join(directory, `${name}.cert`), key = join(directory, `${name}.key`);
  const generated = Bun.spawnSync(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=synthetic-diagnostic", "-addext", `subjectAltName=IP:${ip}`, "-batch"],
    { stdout: "pipe", stderr: "pipe" });
  if (generated.exitCode !== 0) throw new Error("Synthetic certificate generation refused");
  chmodSync(cert, 0o600); chmodSync(key, 0o600); return { cert, key };
}
async function http(url: string, ca: Buffer, options: { method?: string; headers?: Record<string, string>; body?: string; servername?: string } = {}) {
  return bounded(new Promise<{ status: number; headers: Record<string, unknown>; body: string }>((resolve, reject) => {
    const outgoing = request(url, { method: options.method ?? "GET", headers: options.headers, ca, rejectUnauthorized: true, agent: false,
      ...(options.servername ? { servername: options.servername } : {}), timeout: 2000 }, (incoming) => {
      let body = ""; incoming.setEncoding("utf8");
      incoming.on("data", (chunk: string) => { body += chunk; if (body.length > 8192) outgoing.destroy(new Error("Synthetic response exceeds bound")); });
      incoming.on("end", () => resolve({ status: incoming.statusCode!, headers: incoming.headers, body }));
      incoming.on("error", reject);
    });
    outgoing.on("timeout", () => outgoing.destroy(new Error("Synthetic HTTPS request expired")));
    outgoing.on("error", reject); outgoing.end(options.body);
  }));
}
async function fixture() {
  mkdirSync(root, { recursive: true });
  const directory = mkdtempSync(join(root, "merchant-https-")); chmodSync(directory, 0o700);
  let setupListener: ReturnType<typeof Bun.serve> | undefined;
  let portReservation: ReturnType<typeof Bun.serve> | undefined;
  try {
  const lndTls = certificates(directory, "lnd"), listener = certificates(directory, "merchant");
   let forbiddenRequests = 0, identityRequests = 0;
  const lnd = setupListener = Bun.serve({ hostname: "127.0.0.1", port: 0, tls: { cert: readFileSync(lndTls.cert), key: readFileSync(lndTls.key) }, fetch(input) {
    if (input.headers.get("Grpc-Metadata-macaroon") !== fixtureCredential.toString("hex")) return new Response("", { status: 403 });
     if (input.method !== "GET" || new URL(input.url).pathname !== "/v1/getinfo") { forbiddenRequests++; return new Response("", { status: 501 }); }
     identityRequests++;
    return Response.json({ identity_pubkey: receiver, chains: [{ chain: "bitcoin", network: "regtest" }], synced_to_chain: true });
  } });
  // Release a test-owned port; occupation between selection and bind is refusal,
  // never a fallback port or rewritten origin.
  portReservation = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() });
  const port = portReservation.port!; portReservation.stop(true); portReservation = undefined;
  const config: Record<string, string> = { origin: `https://127.0.0.1:${port}`, receiver, endpoint: `https://127.0.0.1:${lnd.port}`,
    ledgerPath: join(directory, "merchant.sqlite"), certificatePath: lndTls.cert,
    profile: "regtest-merchant-https/1", listenerCertificatePath: listener.cert, listenerKeyPath: listener.key, listenerPort: String(port) };
  for (const [field, contents] of Object.entries({ issuanceKeyPath: Buffer.alloc(32, 1), statusKeyPath: Buffer.alloc(32, 2), eventKeyPath: Buffer.alloc(32, 3),
    macaroonPath: fixtureCredential, adminTokenPath: Buffer.from(admin) })) {
    config[field] = join(directory, field); writeFileSync(config[field]!, contents, { mode: 0o600 });
  }
  const path = join(directory, "config.json");
  const save = () => writeFileSync(path, JSON.stringify(config), { mode: 0o600 }); save();
  const children = new Set<Child>();
  const track = <T extends Child>(child: T): T => { children.add(child); return child; };
  const launch = (command: string, fault?: string) => {
    const child = Bun.spawn([process.execPath, "scripts/regtest-merchant.ts", command, path, ...(fault ? [fault] : [])], {
      env: { ...process.env, RILLSWAP_REGTEST_MERCHANT: "1" }, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    children.add(child); return child;
  };
  const end = async (child: Child) => {
    if (child.exitCode === null) child.kill("SIGTERM");
    try { await bounded(child.exited); } catch { child.kill("SIGKILL"); await bounded(child.exited); }
    children.delete(child);
  };
  const command = async (verb: string) => {
    const child = launch(verb);
    return bounded(Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]));
  };
  const start = async (verb = "serve-https") => {
    const child = launch(verb), reader = child.stdout.getReader(); let output = "";
    try {
      while (!output.includes("\n")) { const next = await bounded(reader.read()); if (next.done || output.length > 1024) throw new Error("Owned diagnostic did not become ready"); output += new TextDecoder().decode(next.value); }
    } finally { reader.releaseLock(); }
    const ready = JSON.parse(output.trim());
    expect(Object.keys(ready).sort()).toEqual(["port", "publicKey", "ready"]); expect(ready.ready).toBe(true);
    return { child, ready, errors: new Response(child.stderr).text() };
  };
  const cleanup = async () => {
    try { for (const child of children) await end(child); }
    finally { lnd.stop(true); rmSync(directory, { recursive: true, force: true }); }
  };
   return { directory, config, path, listener, lndTls, port, save, launch, end, command, start, cleanup, track, forbidden: () => forbiddenRequests, identities: () => identityRequests };
  } catch {
    portReservation?.stop(true); setupListener?.stop(true); rmSync(directory, { recursive: true, force: true });
    throw new Error("Synthetic HTTPS fixture setup refused");
  }
}
function immutable(paths: string[]) {
  return paths.map((path) => { const info = lstatSync(path); return { inode: info.ino, device: info.dev, mode: info.mode,
    digest: createHash("sha256").update(readFileSync(path)).digest("hex") }; });
}
function history(path: string) {
  const db = new Database(path, { readonly: true });
  try { return ["metadata", "intents", "idempotency"].map((table) => db.query(`SELECT * FROM ${table} ORDER BY rowid`).all()); }
  finally { db.close(); }
}

test("explicit HTTPS factory validates TLS and preserves original store/inputs across reopen", async () => {
  const f = await fixture();
  try {
    expect(await f.command("provision-https")).toEqual(['{"provisioned":true}\n', "", 0]);
    const inputs = [f.path, ...Object.entries(f.config).filter(([field]) => field.endsWith("Path") && field !== "ledgerPath").map(([, value]) => value)];
    const before = immutable(inputs), store = lstatSync(f.config.ledgerPath!);
    let serving = await f.start(); expect(serving.ready.port).toBe(f.port);
    const created = await http(`${f.config.origin}/v1/intents`, readFileSync(f.listener.cert), { method: "POST",
      headers: { Authorization: `Bearer ${admin}`, Origin: f.config.origin!, "Content-Type": "application/json", "Idempotency-Key": "synthetic_https_intent_01" },
      body: JSON.stringify({ orderRef: "synthetic-unfunded-order", amountMsat: "1000000", expiresAt: Math.floor(Date.now() / 1000) + 3600 }) });
    expect(created.status).toBe(201); expect(created.headers["cache-control"]).toBe("no-store");
    const view = JSON.parse(created.body); expect(view.status).toBe("waiting"); expect(view.attempt).toBe(null);
    await expect(http(`${f.config.origin}/`, readFileSync(f.lndTls.cert))).rejects.toThrow();
    await expect(http(`${f.config.origin}/`, readFileSync(f.listener.cert), { servername: "wrong.invalid" })).rejects.toThrow();
    await f.end(serving.child); expect(await serving.errors).toBe(""); const rows = history(f.config.ledgerPath!);
    serving = await f.start();
    const observed = await http(`${f.config.origin}/v1/intents/${view.id}`, readFileSync(f.listener.cert), { headers: { Authorization: `Bearer ${view.statusToken}`, Origin: f.config.origin! } });
    expect(observed.status).toBe(200); expect(JSON.parse(observed.body)).toEqual({ version: view.version, id: view.id, status: view.status, attempt: null });
    expect((await http(`${f.config.origin}/listenerKeyPath`, readFileSync(f.listener.cert))).status).toBe(404);
    await f.end(serving.child); expect(await serving.errors).toBe("");
    expect(history(f.config.ledgerPath!)).toEqual(rows); expect(immutable(inputs)).toEqual(before);
    expect(lstatSync(f.config.ledgerPath!).ino).toBe(store.ino); expect(f.forbidden()).toBe(0);
  } finally { await f.cleanup(); }
}, 20000);

for (const fault of ["missing_key", "public_key", "mismatched_key", "wrong_san", "malformed_cert", "expired_cert", "invalid_admin", "origin_mismatch", "partial_config", "legacy_config", "fault_option"] as const) {
  test(`HTTPS provisioning refuses ${fault} before creating state`, async () => {
    const f = await fixture();
    try {
      if (fault === "missing_key") rmSync(f.listener.key);
      else if (fault === "public_key") chmodSync(f.listener.key, 0o644);
      else if (fault === "mismatched_key") writeFileSync(f.listener.key, readFileSync(f.lndTls.key));
      else if (fault === "wrong_san") { const other = certificates(f.directory, "wrong-ip", "127.0.0.2"); f.config.listenerCertificatePath = other.cert; f.config.listenerKeyPath = other.key; }
      else if (fault === "malformed_cert") writeFileSync(f.listener.cert, "not a certificate");
      else if (fault === "expired_cert") {
        const expired = join(f.directory, "expired.cert");
        const signed = Bun.spawnSync(["openssl", "x509", "-in", f.listener.cert, "-signkey", f.listener.key, "-days", "0", "-out", expired], { stdout: "pipe", stderr: "pipe" });
        expect(signed.exitCode).toBe(0); chmodSync(expired, 0o600); f.config.listenerCertificatePath = expired;
      }
      else if (fault === "invalid_admin") writeFileSync(f.config.adminTokenPath!, "SECRET_CANARY");
      else if (fault === "origin_mismatch") f.config.origin = "https://merchant.invalid";
      else if (fault === "partial_config") delete f.config.listenerPort;
      else if (fault === "legacy_config") { for (const field of ["profile", "listenerPort", "listenerCertificatePath", "listenerKeyPath"]) delete f.config[field]; f.config.origin = "https://merchant.invalid"; }
      f.save();
      const result = fault === "fault_option" ? (() => { const child = f.launch("serve-https", "crash-after-settled"); return bounded(Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited])); })() : f.command("provision-https");
      expect(await result).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
      for (const suffix of ["", "-wal", "-shm"]) expect(existsSync(f.config.ledgerPath + suffix)).toBe(false);
      expect(f.forbidden()).toBe(0);
    } finally { await f.cleanup(); }
  }, 10000);
}

test("occupied HTTPS port refuses without fallback, mutation or an observation timer", async () => {
  const f = await fixture(); let blocker: ReturnType<typeof Bun.serve> | undefined;
  try {
    expect((await f.command("provision-https"))[2]).toBe(0); const rows = history(f.config.ledgerPath!);
    blocker = Bun.serve({ hostname: "127.0.0.1", port: f.port, fetch: () => new Response("test-owned") });
    expect(await f.command("serve-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(history(f.config.ledgerPath!)).toEqual(rows); expect(f.forbidden()).toBe(0);
  } finally { blocker?.stop(true); await f.cleanup(); }
}, 10000);

test("ordinary HTTPS open refuses missing ledger or mismatched TLS key without repairing history", async () => {
  const f = await fixture();
  try {
    expect(await f.command("serve-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(existsSync(f.config.ledgerPath!)).toBe(false);
    expect((await f.command("provision-https"))[2]).toBe(0); const rows = history(f.config.ledgerPath!);
    writeFileSync(f.listener.key, readFileSync(f.lndTls.key));
    expect(await f.command("serve-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(history(f.config.ledgerPath!)).toEqual(rows); expect(f.forbidden()).toBe(0);
  } finally { await f.cleanup(); }
}, 10000);

test("legacy HTTP commands retain their original configuration and serving behavior", async () => {
  const f = await fixture();
  try {
    for (const field of ["profile", "listenerPort", "listenerCertificatePath", "listenerKeyPath"]) delete f.config[field];
    f.config.origin = "https://merchant.invalid"; f.save();
    expect((await f.command("provision"))[2]).toBe(0); const running = await f.start("serve");
    expect((await fetch(`http://127.0.0.1:${running.ready.port}/not-found`, { redirect: "error" })).status).toBe(404);
    await f.end(running.child); expect(await running.errors).toBe(""); expect(f.forbidden()).toBe(0);
  } finally { await f.cleanup(); }
}, 10000);

function configureConsumer(f: Awaited<ReturnType<typeof fixture>>): string {
  const path = join(f.directory, "acceptance.sqlite"); f.config.acceptanceConsumerPath = path; f.save(); return path;
}
function consumerIdentity(f: Awaited<ReturnType<typeof fixture>>) {
  return { merchantOrigin: f.config.origin!, receiver, network: "regtest" as const,
    merchantPublicKey: bytesToHex(ed25519.getPublicKey(readFileSync(f.config.eventKeyPath!))) };
}
function consumerHistory(path: string) {
  const db = new Database(path, { readonly: true });
  try { return ["metadata", "orders", "acceptances"].map((table) => db.query(`SELECT * FROM ${table} ORDER BY rowid`).all()); }
  finally { db.close(); }
}

test("configured HTTPS consumer is explicitly provisioned and suppresses an original invoice until admin binding", async () => {
  const f = await fixture();
  try {
    expect((await f.command("provision-https"))[2]).toBe(0);
    const backend = new LndInvoiceBackend(lndRestTransport(f.config.endpoint!, readFileSync(f.lndTls.cert), fixtureCredential),
      { origin: f.config.origin!, receiver, network: "regtest" }, readFileSync(f.config.issuanceKeyPath!));
    const identity = await backend.identity(), ledger = MerchantLedger.open(f.config.ledgerPath!, identity), now = Math.floor(Date.now() / 1000);
    let intentId: string, invoice: string;
    try {
      const intent = ledger.createIntent("original-https-order", "1000000", now + 600, "https_binding_intent_01", now);
      const attempt = ledger.createAttempt(intent.id, "https_binding_attempt_01", now);
      invoice = testInvoice("synthetic-https", "1000000", now, now + 600); intentId = intent.id;
      await ledger.issue(attempt.id, { identity: async () => identity, create: async () => invoice }, () => now);
    } finally { ledger.close(); }
    const path = configureConsumer(f), originalHistory = history(f.config.ledgerPath!);
    expect(await f.command("serve-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(existsSync(path)).toBe(false); expect(history(f.config.ledgerPath!)).toEqual(originalHistory);
    expect(await f.command("provision-acceptance-https")).toEqual(['{"acceptanceProvisioned":true}\n', "", 0]);
    const before = consumerHistory(path), inode = lstatSync(path).ino;
    expect(await f.command("provision-acceptance-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(consumerHistory(path)).toEqual(before);
    let serving = await f.start(); const headers = { Authorization: `Bearer ${admin}`, Origin: f.config.origin! };
    const url = f.config.origin + "/v1/intents/" + intentId!;
    const hidden = await http(url, readFileSync(f.listener.cert), { headers }); expect(hidden.status).toBe(200); expect(JSON.parse(hidden.body).attempt).toBeNull();
    expect(consumerHistory(path)).toEqual(before);
    const registered = await http(url + "/order-binding", readFileSync(f.listener.cert), { method: "PUT", headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ orderRef: "original-https-order", amountMsat: "1000000" }) });
    expect(registered.status).toBe(200); expect(JSON.parse(registered.body).attempt.invoice).toBe(invoice!);
    await f.end(serving.child); expect(await serving.errors).toBe(""); const bound = consumerHistory(path);
    serving = await f.start(); const admitted = await http(url, readFileSync(f.listener.cert), { headers });
    expect(JSON.parse(admitted.body).attempt.invoice).toBe(invoice!);
    await f.end(serving.child); expect(await serving.errors).toBe(""); expect(consumerHistory(path)).toEqual(bound); expect(lstatSync(path).ino).toBe(inode);
    expect(history(f.config.ledgerPath!)).toEqual(originalHistory);
  } finally { await f.cleanup(); }
}, 20000);

test("consumer provisioning is a distinct explicit command against an existing merchant, never a bundled migration", async () => {
  const f = await fixture();
  try {
    expect(await f.command("provision-acceptance-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    const path = configureConsumer(f);
    for (const command of ["provision-https", "provision-acceptance-https", "serve-https"]) expect(await f.command(command)).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(existsSync(path)).toBe(false); expect(existsSync(f.config.ledgerPath!)).toBe(false);
    for (const field of ["profile", "listenerPort", "listenerCertificatePath", "listenerKeyPath"]) delete f.config[field];
    f.config.origin = "https://merchant.invalid"; f.save();
    expect(await f.command("provision")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(existsSync(f.config.ledgerPath!)).toBe(false); expect(f.forbidden()).toBe(0);
  } finally { await f.cleanup(); }
}, 10000);

for (const fault of ["partial", "older", "newer", "foreign_key", "schema", "symlink", "public"] as const) {
  test(`configured HTTPS startup refuses ${fault} consumer state without repair or downgrade`, async () => {
    const f = await fixture();
    try {
      expect((await f.command("provision-https"))[2]).toBe(0); const original = history(f.config.ledgerPath!), path = configureConsumer(f);
      if (fault === "partial") writeFileSync(path, "", { mode: 0o600 });
      else {
        const identity = consumerIdentity(f);
        LightningAcceptanceConsumer.provision(path, fault === "foreign_key" ? { ...identity, merchantPublicKey: "22".repeat(32) } : identity).close();
        if (fault === "older" || fault === "newer" || fault === "schema") {
          const db = new Database(path, { readwrite: true });
          try { if (fault === "schema") db.exec("CREATE TABLE unknown_format (id TEXT)");
            else db.query("UPDATE metadata SET value=? WHERE key='format'").run("lightning-acceptance-consumer/" + (fault === "older" ? "0" : "2"));
          } finally { db.close(); }
        } else if (fault === "symlink") { const alias = join(f.directory, "symlink.sqlite"); symlinkSync(path, alias); f.config.acceptanceConsumerPath = alias; f.save(); }
        else if (fault === "public") chmodSync(path, 0o644);
      }
      const bytes = readFileSync(path), inode = lstatSync(path).ino;
      expect(await f.command("serve-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
      await expect(http(f.config.origin!, readFileSync(f.listener.cert))).rejects.toThrow();
      expect(readFileSync(path)).toEqual(bytes); expect(lstatSync(path).ino).toBe(inode); expect(history(f.config.ledgerPath!)).toEqual(original); expect(f.forbidden()).toBe(0);
    } finally { await f.cleanup(); }
  }, 10000);
}

test("consumer paths and SQLite sidecar namespaces cannot collide with stores, configuration or credentials", async () => {
  const f = await fixture();
  try {
    expect((await f.command("provision-https"))[2]).toBe(0);
    const credential = f.config.eventKeyPath!, originalLedger = f.config.ledgerPath!, originalMacaroon = f.config.macaroonPath!;
    const inputs = [originalLedger, credential, originalMacaroon], before = immutable(inputs);
    const invalidPaths = [f.path, originalLedger, originalLedger + "-wal", originalLedger + "-shm", originalLedger + "-journal",
      credential, credential + "/../consumer.sqlite", "relative.sqlite", join(dirname(f.directory), "foreign.sqlite")];
    for (const path of invalidPaths) {
      f.config.acceptanceConsumerPath = path; f.save();
      expect(await f.command("provision-acceptance-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
      expect(immutable(inputs)).toEqual(before);
    }
    f.config.acceptanceConsumerPath = join(f.directory, "sidecar.sqlite");
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      f.config.macaroonPath = f.config.acceptanceConsumerPath + suffix; f.save();
      expect(await f.command("provision-acceptance-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
      expect(existsSync(f.config.acceptanceConsumerPath)).toBe(false); expect(immutable(inputs)).toEqual(before);
    }
  } finally { await f.cleanup(); }
}, 15000);

test("occupied configured HTTPS listener closes both opened stores without starting observation", async () => {
  const f = await fixture(); let blocker: ReturnType<typeof Bun.serve> | undefined;
  try {
    expect((await f.command("provision-https"))[2]).toBe(0); const path = configureConsumer(f);
    expect((await f.command("provision-acceptance-https"))[2]).toBe(0);
    const original = history(f.config.ledgerPath!), before = consumerHistory(path);
    blocker = Bun.serve({ hostname: "127.0.0.1", port: f.port, fetch: () => new Response() });
    expect(await f.command("serve-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(history(f.config.ledgerPath!)).toEqual(original); expect(consumerHistory(path)).toEqual(before); expect(f.forbidden()).toBe(0);
    const reopened = LightningAcceptanceConsumer.open(path, consumerIdentity(f)); reopened.close();
  } finally { blocker?.stop(true); await f.cleanup(); }
}, 10000);

test("explicit consumer provisioning refuses a foreign merchant ledger without creating its file", async () => {
  const f = await fixture();
  try {
    expect((await f.command("provision-https"))[2]).toBe(0); const path = configureConsumer(f);
    const db = new Database(f.config.ledgerPath!, { readwrite: true });
    try {
      const row = db.query("SELECT value FROM metadata WHERE key='identity'").get() as { value: string };
      db.query("UPDATE metadata SET value=? WHERE key='identity'").run(JSON.stringify({ ...JSON.parse(row.value), origin: "https://foreign.invalid" }));
    } finally { db.close(); }
    const original = history(f.config.ledgerPath!);
    expect(await f.command("provision-acceptance-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(existsSync(path)).toBe(false); expect(history(f.config.ledgerPath!)).toEqual(original);
  } finally { await f.cleanup(); }
}, 10000);

test("HTTPS manifest profile publishes only fixed advisory data through independently trusted TLS", async () => {
  const f = await fixture();
  try {
    f.config.manifestProfile = "merchant-manifest/native-lightning/1"; f.save();
    const expectedKey = consumerIdentity(f).merchantPublicKey;
    expect((await f.command("provision-https"))[2]).toBe(0);
    const original = history(f.config.ledgerPath!), inputs = immutable([f.path, f.config.eventKeyPath!]);
    let serving = await f.start(); const before = f.identities();
    const published = await http(f.config.origin + "/v1/manifest", readFileSync(f.listener.cert));
    expect(published.status).toBe(200); expect(published.headers["cache-control"]).toBe("no-store");
    const raw = JSON.parse(published.body), manifest = parseNativeLightningMerchantManifest(raw, f.config.origin!, expectedKey);
    expect(manifest.publicPolicy.receiver).toBe(receiver); expect(manifest.productionEnabled).toBe(false); expect(serving.ready.publicKey).toBe(expectedKey);
    expect(f.identities()).toBe(before); expect(f.forbidden()).toBe(0); expect(history(f.config.ledgerPath!)).toEqual(original);
    expect(published.body).not.toContain(admin); expect(published.body).not.toContain(f.directory);
    expect((await http(f.config.origin + "/v1/manifest", readFileSync(f.listener.cert), { method: "POST" })).status).toBe(405);
    expect((await http(f.config.origin + "/v1/manifest", readFileSync(f.listener.cert), { headers: { Origin: "https://foreign.example" } })).status).toBe(403);
    expect((await http(f.config.origin + "/v1/intents/unknown_intent_01/events", readFileSync(f.listener.cert))).status).toBe(404);
    await expect(http(f.config.origin + "/v1/manifest", readFileSync(f.lndTls.cert))).rejects.toThrow();
    await f.end(serving.child); expect(await serving.errors).toBe("");
    serving = await f.start();
    expect(JSON.parse((await http(f.config.origin + "/v1/manifest", readFileSync(f.listener.cert))).body)).toEqual(raw);
    await f.end(serving.child); expect(await serving.errors).toBe(""); expect(history(f.config.ledgerPath!)).toEqual(original); expect(immutable([f.path, f.config.eventKeyPath!])).toEqual(inputs);
    delete f.config.manifestProfile; f.save(); serving = await f.start();
    expect((await http(f.config.origin + "/v1/manifest", readFileSync(f.listener.cert))).status).toBe(404);
    await f.end(serving.child); expect(await serving.errors).toBe("");
  } finally { await f.cleanup(); }
}, 15000);

test("invalid manifest profiles and nonstring flags fail before backend calls or state creation", async () => {
  const f = await fixture();
  try {
    for (const profile of ["", "true", "false", "merchant-manifest/native-lightning/0", "merchant-manifest/native-lightning/2", true, false, null, 1, {}]) {
      Object.assign(f.config, { manifestProfile: profile }); f.save();
      expect(await f.command("provision-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
      expect(f.identities()).toBe(0); expect(existsSync(f.config.ledgerPath!)).toBe(false);
    }
    f.config.manifestProfile = "merchant-manifest/native-lightning/1";
    for (const field of ["profile", "listenerPort", "listenerCertificatePath", "listenerKeyPath"]) delete f.config[field];
    f.config.origin = "https://merchant.invalid"; f.save();
    expect(await f.command("provision")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]);
    expect(f.identities()).toBe(0); expect(existsSync(f.config.ledgerPath!)).toBe(false);
  } finally { await f.cleanup(); }
}, 15000);

test("manifest publication cannot downgrade configured missing consumer state or expose an unbound invoice", async () => {
  const f = await fixture();
  try {
    f.config.manifestProfile = "merchant-manifest/native-lightning/1"; f.save(); expect((await f.command("provision-https"))[2]).toBe(0);
    const backend = new LndInvoiceBackend(lndRestTransport(f.config.endpoint!, readFileSync(f.lndTls.cert), fixtureCredential),
      { origin: f.config.origin!, receiver, network: "regtest" }, readFileSync(f.config.issuanceKeyPath!));
    const identity = await backend.identity(), ledger = MerchantLedger.open(f.config.ledgerPath!, identity), now = Math.floor(Date.now() / 1000);
    let intentId: string;
    try {
      const intent = ledger.createIntent("manifest-bound-order", "1000000", now + 600, "manifest_https_intent_001", now);
      const attempt = ledger.createAttempt(intent.id, "manifest_https_attempt_001", now); intentId = intent.id;
      await ledger.issue(attempt.id, { identity: async () => identity, create: async () => testInvoice("manifest-https", "1000000", now, now + 600) }, () => now);
    } finally { ledger.close(); }
    const path = configureConsumer(f), original = history(f.config.ledgerPath!);
    expect(await f.command("serve-https")).toEqual(["", "Regtest merchant diagnostic refused\n", 1]); expect(existsSync(path)).toBe(false);
    await expect(http(f.config.origin + "/v1/manifest", readFileSync(f.listener.cert))).rejects.toThrow();
    expect((await f.command("provision-acceptance-https"))[2]).toBe(0); const before = consumerHistory(path);
    const serving = await f.start(); const published = await http(f.config.origin + "/v1/manifest", readFileSync(f.listener.cert));
    expect(parseNativeLightningMerchantManifest(JSON.parse(published.body), f.config.origin!, consumerIdentity(f).merchantPublicKey).productionEnabled).toBe(false);
    const status = await http(f.config.origin + "/v1/intents/" + intentId!, readFileSync(f.listener.cert), { headers: { Authorization: `Bearer ${admin}` } });
    expect(status.status).toBe(200); expect(JSON.parse(status.body).attempt).toBeNull();
    const eventsUrl = f.config.origin + "/v1/intents/" + intentId! + "/events";
    expect((await http(eventsUrl, readFileSync(f.listener.cert))).status).toBe(404);
    const authorizedEvents = await http(eventsUrl, readFileSync(f.listener.cert), { headers: { Authorization: `Bearer ${admin}` } });
    expect(authorizedEvents.status).toBe(200); expect(JSON.parse(authorizedEvents.body)).toEqual([]);
    await f.end(serving.child); expect(await serving.errors).toBe(""); expect(consumerHistory(path)).toEqual(before); expect(history(f.config.ledgerPath!)).toEqual(original);
  } finally { await f.cleanup(); }
}, 15000);

const readerPython = process.env.RILLSWAP_MERCHANT_READER_PYTHON;
test.skipIf(!readerPython)("leaf-pinned Python reader acquires actual Bun HTTPS view and events without issuing invoices", async () => {
  const f = await fixture();
  try {
    expect((await f.command("provision-https"))[2]).toBe(0); const serving = await f.start();
    const created = await http(`${f.config.origin}/v1/intents`, readFileSync(f.listener.cert), { method: "POST",
      headers: { Authorization: `Bearer ${admin}`, Origin: f.config.origin!, "Content-Type": "application/json", "Idempotency-Key": "synthetic_python_intent_01" },
      body: JSON.stringify({ orderRef: "synthetic-python-reader", amountMsat: "1000000", expiresAt: Math.floor(Date.now() / 1000) + 3600 }) });
    expect(created.status).toBe(201); const intent = JSON.parse(created.body);
    const leaf = createHash("sha256").update(new X509Certificate(readFileSync(f.listener.cert)).raw).digest("hex");
    // Capabilities travel through a private pipe, not process arguments, files,
    // environment variables or public diagnostic output.
    const program = `
import json, sys
from rill_cli.merchant_https import MerchantHttpsReader
from rill_cli.merchant_credit import MerchantSourcePin
from rill_core.wire.types import NetworkIdentity
from rill_core.networks import REGTEST_CONSENSUS_PROFILE
from pathlib import Path
source = json.load(sys.stdin)
network = NetworkIdentity(family="bitcoin", name="regtest",
    genesis_hash="0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    signet_challenge=None, consensus_profile=REGTEST_CONSENSUS_PROFILE,
    deployment_namespace="merchant-https-test")
pin = MerchantSourcePin(merchant_origin=source["origin"], event_public_key=source["key"],
    source_node=source["node"], network=network)
batch = MerchantHttpsReader(pin, source["leaf"], Path(source["ca"])).read(source["id"], source["token"])
view = json.loads(batch.view.document)
assert view == {"version":"checkout-view/1", "id":source["id"], "status":"waiting", "attempt":None}
assert json.loads(batch.events_document) == []
assert batch.view.acquisition == batch.events_acquisition
print("Authenticated unsigned view and unverified events acquired")
`;
    const child = f.track(Bun.spawn([readerPython!, "-c", program], { stdin: "pipe", stdout: "pipe", stderr: "pipe",
      env: { ...process.env, PYTHONPATH: ["../rill-cli/src", "../rill-core/packages/core/src", "../rill-crypto/python/src", "../rill-provider/src"].map((p) => resolve(p)).join(":") } }));
    child.stdin.write(JSON.stringify({ origin: f.config.origin, key: serving.ready.publicKey, node: receiver, leaf,
      ca: f.listener.cert, id: intent.id, token: intent.statusToken })); child.stdin.end();
    const [output, errors, code] = await bounded(Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]), 15000);
    expect(code).toBe(0); expect(errors).toBe(""); expect(output).toBe("Authenticated unsigned view and unverified events acquired\n");
    await f.end(serving.child); expect(await serving.errors).toBe(""); expect(f.forbidden()).toBe(0);
  } finally { await f.cleanup(); }
}, 20000);
