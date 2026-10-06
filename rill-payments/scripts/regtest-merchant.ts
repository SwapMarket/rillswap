// Trusted disposable diagnostic, not a production service or credential sandbox.
import { closeSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { LndInvoiceBackend, lndRestTransport } from "../src/lnd";
import { MerchantLedger, type ReceiptObserver } from "../src/merchant";
import type { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import { createMerchantService } from "../src/server";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";

async function main(): Promise<void> {
  if (process.env.RILLSWAP_REGTEST_MERCHANT !== "1" || Bun.version !== "1.3.11" || Bun.revision !== "af24e281ebacd6ac77c0f14b4206599cf4ae1c9f") throw new Error();
  const [command, configPath, fault, ...extra] = process.argv.slice(2);
  const provisionConsumer = command === "provision-acceptance-https";
  const https = command === "provision-https" || command === "serve-https" || provisionConsumer;
  if (!configPath || !isAbsolute(configPath) || !["provision", "serve", "provision-https", "serve-https", "provision-acceptance-https"].includes(command!) || extra.length ||
      (fault !== undefined && (command !== "serve" || fault !== "crash-after-settled"))) throw new Error();
  const directory = dirname(configPath), root = lstatSync(directory);
  if (!root.isDirectory() || root.isSymbolicLink() || (root.mode & 0o077) !== 0) throw new Error();
  if (https && (root.uid !== process.getuid?.() || realpathSync(directory) !== directory)) throw new Error();
  const markerPath = join(directory, "settled-receipt-fault.json");
  if (fault) {
    try { lstatSync(markerPath); throw new Error(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  const privateBytes = (path: string): Buffer => {
    if (!isAbsolute(path) || dirname(path) !== directory) throw new Error();
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.size > 8192) throw new Error();
    if (https && (stat.uid !== root.uid || realpathSync(path) !== path)) throw new Error();
    return readFileSync(path);
  };
  const config = JSON.parse(privateBytes(configPath).toString("utf8")) as Record<string, string>;
  const configuredConsumer = Object.hasOwn(config, "acceptanceConsumerPath");
  const fields = ["adminTokenPath", "certificatePath", "endpoint", "eventKeyPath", "issuanceKeyPath", "ledgerPath", "macaroonPath", "origin", "receiver", "statusKeyPath"];
  if (https) fields.push("profile", "listenerCertificatePath", "listenerKeyPath", "listenerPort");
  if (https && configuredConsumer) fields.push("acceptanceConsumerPath");
  if (Object.keys(config).sort().join(",") !== fields.sort().join(",") ||
      Object.values(config).some((value) => typeof value !== "string") || (!https && config.origin !== "https://merchant.invalid") ||
      !isAbsolute(config.ledgerPath!) || dirname(config.ledgerPath!) !== directory) throw new Error();
  // Configuration opt-in is explicit, never a missing-state migration. Existing
  // merchant provisioning remains a one-store operation.
  if ((provisionConsumer && !configuredConsumer) || (command === "provision-https" && configuredConsumer)) throw new Error();
  const checkStore = (path: string) => {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.uid !== root.uid || realpathSync(path) !== path) throw new Error();
  };
  if (configuredConsumer) {
    const databases = [config.ledgerPath!, config.acceptanceConsumerPath!];
    if (databases.some((path) => !isAbsolute(path) || dirname(path) !== directory || resolve(path) !== path)) throw new Error();
    const namespaces = databases.flatMap((path) => [path, path + "-wal", path + "-shm", path + "-journal"]);
    const protectedPaths = [configPath, ...fields.filter((field) => field.endsWith("Path") && !["ledgerPath", "acceptanceConsumerPath"].includes(field)).map((field) => config[field]!)];
    if (new Set(namespaces).size !== namespaces.length || protectedPaths.some((path) => namespaces.includes(resolve(path)))) throw new Error();
    checkStore(config.ledgerPath!);
    if (provisionConsumer) {
      try { lstatSync(config.acceptanceConsumerPath!); throw new Error(); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    } else checkStore(config.acceptanceConsumerPath!);
  }
  const issuanceKey = privateBytes(config.issuanceKeyPath!), statusKey = privateBytes(config.statusKeyPath!), eventKey = privateBytes(config.eventKeyPath!);
  if ([issuanceKey, statusKey, eventKey].some((key) => key.length !== 32)) throw new Error();
  let listenerPort = 0;
  let tls: { cert: Buffer; key: Buffer } | undefined;
  let httpsAdminToken: string | undefined;
  if (https) {
    if (config.profile !== "regtest-merchant-https/1" || !/^[1-9][0-9]{3,4}$/.test(config.listenerPort!)) throw new Error();
    listenerPort = Number(config.listenerPort);
    if (listenerPort < 1024 || listenerPort > 65535 || config.origin !== `https://127.0.0.1:${listenerPort}`) throw new Error();
    httpsAdminToken = privateBytes(config.adminTokenPath!).toString("utf8");
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(httpsAdminToken)) throw new Error();
    tls = { cert: privateBytes(config.listenerCertificatePath!), key: privateBytes(config.listenerKeyPath!) };
    const certificate = new X509Certificate(tls.cert), key = createPrivateKey(tls.key);
    const now = Date.now(), from = Date.parse(certificate.validFrom), until = Date.parse(certificate.validTo);
    if (!Number.isFinite(from) || !Number.isFinite(until) || now < from || now >= until ||
        certificate.checkIP("127.0.0.1") !== "127.0.0.1" || !certificate.checkPrivateKey(key)) throw new Error();
    createSecureContext(tls);
  }
  const backend = new LndInvoiceBackend(lndRestTransport(config.endpoint!, privateBytes(config.certificatePath!), privateBytes(config.macaroonPath!)),
    { origin: config.origin!, receiver: config.receiver!, network: "regtest" }, issuanceKey);
  const identity = await backend.identity();
  // Unconfigured launchers retain their original dependency surface, including
  // receipt-fault fixtures that deliberately replace the service boundary.
  const Consumer = configuredConsumer ? (await import("../src/acceptanceConsumer")).LightningAcceptanceConsumer : undefined;
  const consumerIdentity = configuredConsumer ? { merchantOrigin: config.origin!, receiver: config.receiver!, network: "regtest" as const,
    merchantPublicKey: bytesToHex(ed25519.getPublicKey(eventKey)) } : undefined;
  if (provisionConsumer) {
    const original = MerchantLedger.open(config.ledgerPath!, identity);
    try { Consumer!.provision(config.acceptanceConsumerPath!, consumerIdentity!).close(); }
    finally { original.close(); }
    console.log(JSON.stringify({ acceptanceProvisioned: true })); return;
  }
  if (command === "provision" || command === "provision-https") {
    MerchantLedger.provision(config.ledgerPath!, identity).close(); console.log(JSON.stringify({ provisioned: true })); return;
  }
  // Ordinary open never reconstructs absent/partial state or keys.
  if (realpathSync(dirname(config.ledgerPath!)) !== realpathSync(directory)) throw new Error();
  const ledger = MerchantLedger.open(config.ledgerPath!, identity);
  const observer: ReceiptObserver = fault ? {
    identity: () => backend.identity(),
    async lookup(hash) {
      const receipt = await backend.lookup(hash);
      if (receipt.state !== "SETTLED") return receipt;
      // Test evidence only, never a recovery receipt. Exit before returning to
      // the ledger, so neither receipt allocation nor acceptance can occur.
      try {
        const marker = { version: "regtest-settled-receipt-loss/1", receiver: receipt.receiver, network: receipt.network,
          paymentHash: receipt.paymentHash, invoiceAmountMsat: receipt.invoiceAmountMsat,
          paidMsat: receipt.paidMsat, state: receipt.state, settledAt: receipt.settledAt };
        const fd = openSync(markerPath, "wx", 0o600);
        try { writeFileSync(fd, JSON.stringify(marker)); fsyncSync(fd); } finally { closeSync(fd); }
        const directoryFd = openSync(directory, "r");
        try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
      } catch {
        // tick catches exceptions: a throw or exitCode assignment would permit
        // another observation and accidental acceptance after a failed marker.
        console.error("Regtest receipt fault persistence refused"); process.exit(75);
      }
      process.exit(74);
    },
  } : backend;
  let service: ReturnType<typeof createMerchantService>;
  let server: ReturnType<typeof Bun.serve>;
  let consumer: LightningAcceptanceConsumer | undefined;
  try {
    if (configuredConsumer) consumer = Consumer!.open(config.acceptanceConsumerPath!, consumerIdentity!);
    service = createMerchantService({ ledger, issuer: backend, observer, adminToken: httpsAdminToken ?? privateBytes(config.adminTokenPath!).toString("utf8"), statusKey, eventSigningKey: eventKey,
      ...(consumer ? { acceptanceConsumer: consumer } : {}) });
    server = Bun.serve({ hostname: "127.0.0.1", port: listenerPort, fetch: service.fetch, ...(tls ? { tls } : {}) });
  } catch (error) {
    // HTTPS setup must not leave an opened store or observation timer behind.
    // Preserve the legacy path's error behavior and external configuration.
    if (https) { try { consumer?.close(); } finally { ledger.close(); } }
    throw error;
  }
  let tick: Promise<unknown> | null = null;
  const timer = setInterval(() => {
    if (tick === null) tick = service.tick().catch(() => undefined).finally(() => { tick = null; });
  }, 1000);
  let stopping = false;
  const stop = async () => {
    if (stopping) return; stopping = true; clearInterval(timer);
    if (consumer) await server.stop(true); else server.stop(true);
    if (tick) await tick;
    try { consumer?.close(); } finally { ledger.close(); }
    process.exit(0);
  };
  process.on("SIGTERM", () => { void stop(); }); process.on("SIGINT", () => { void stop(); });
  console.log(JSON.stringify({ ready: true, port: server.port, publicKey: bytesToHex(ed25519.getPublicKey(eventKey)) }));
}
try { await main(); } catch { console.error("Regtest merchant diagnostic refused"); process.exitCode = 1; }
