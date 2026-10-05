// Synthetic LND REST identity, actual Bun/HTTPS/SQLite. No invoices or funding.
import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { request } from "node:https";
import { join, resolve } from "node:path";
import { receiver } from "./helpers";

const root = resolve("../tmp");
const fixtureCredential = Buffer.from("synthetic-lnd-read-credential");
const admin = "synthetic_https_admin_credential_0001";
type Child = Bun.Subprocess<"ignore", "pipe", "pipe">;

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
  let forbiddenRequests = 0;
  const lnd = setupListener = Bun.serve({ hostname: "127.0.0.1", port: 0, tls: { cert: readFileSync(lndTls.cert), key: readFileSync(lndTls.key) }, fetch(input) {
    if (input.headers.get("Grpc-Metadata-macaroon") !== fixtureCredential.toString("hex")) return new Response("", { status: 403 });
    if (input.method !== "GET" || new URL(input.url).pathname !== "/v1/getinfo") { forbiddenRequests++; return new Response("", { status: 501 }); }
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
  return { directory, config, path, listener, lndTls, port, save, launch, end, command, start, cleanup, forbidden: () => forbiddenRequests };
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
