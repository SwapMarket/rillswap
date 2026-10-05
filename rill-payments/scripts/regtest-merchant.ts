// Trusted disposable diagnostic, not a production service or credential sandbox.
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { LndInvoiceBackend, lndRestTransport } from "../src/lnd";
import { MerchantLedger } from "../src/merchant";
import { createMerchantService } from "../src/server";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";

async function main(): Promise<void> {
  if (process.env.RILLSWAP_REGTEST_MERCHANT !== "1" || Bun.version !== "1.3.11" || Bun.revision !== "af24e281ebacd6ac77c0f14b4206599cf4ae1c9f") throw new Error();
  const [command, configPath] = process.argv.slice(2);
  if (!configPath || !isAbsolute(configPath) || !["provision", "serve"].includes(command!)) throw new Error();
  const directory = dirname(configPath), root = lstatSync(directory);
  if (!root.isDirectory() || root.isSymbolicLink() || (root.mode & 0o077) !== 0) throw new Error();
  const privateBytes = (path: string): Buffer => {
    if (!isAbsolute(path) || dirname(path) !== directory) throw new Error();
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.size > 8192) throw new Error();
    return readFileSync(path);
  };
  const config = JSON.parse(privateBytes(configPath).toString("utf8")) as Record<string, string>;
  if (Object.keys(config).sort().join(",") !== "adminTokenPath,certificatePath,endpoint,eventKeyPath,issuanceKeyPath,ledgerPath,macaroonPath,origin,receiver,statusKeyPath" ||
      Object.values(config).some((value) => typeof value !== "string") || config.origin !== "https://merchant.invalid" ||
      !isAbsolute(config.ledgerPath!) || dirname(config.ledgerPath!) !== directory) throw new Error();
  const issuanceKey = privateBytes(config.issuanceKeyPath!), statusKey = privateBytes(config.statusKeyPath!), eventKey = privateBytes(config.eventKeyPath!);
  if ([issuanceKey, statusKey, eventKey].some((key) => key.length !== 32)) throw new Error();
  const backend = new LndInvoiceBackend(lndRestTransport(config.endpoint!, privateBytes(config.certificatePath!), privateBytes(config.macaroonPath!)),
    { origin: config.origin!, receiver: config.receiver!, network: "regtest" }, issuanceKey);
  const identity = await backend.identity();
  if (command === "provision") {
    MerchantLedger.provision(config.ledgerPath!, identity).close(); console.log(JSON.stringify({ provisioned: true })); return;
  }
  // Ordinary open never reconstructs absent/partial state or keys.
  if (realpathSync(dirname(config.ledgerPath!)) !== realpathSync(directory)) throw new Error();
  const ledger = MerchantLedger.open(config.ledgerPath!, identity);
  const service = createMerchantService({ ledger, issuer: backend, observer: backend, adminToken: privateBytes(config.adminTokenPath!).toString("utf8"), statusKey, eventSigningKey: eventKey });
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: service.fetch });
  let tick: Promise<unknown> | null = null;
  const timer = setInterval(() => {
    if (tick === null) tick = service.tick().catch(() => undefined).finally(() => { tick = null; });
  }, 1000);
  let stopping = false;
  const stop = async () => {
    if (stopping) return; stopping = true; clearInterval(timer); server.stop(true);
    if (tick) await tick; ledger.close(); process.exit(0);
  };
  process.on("SIGTERM", () => { void stop(); }); process.on("SIGINT", () => { void stop(); });
  console.log(JSON.stringify({ ready: true, port: server.port, publicKey: bytesToHex(ed25519.getPublicKey(eventKey)) }));
}
try { await main(); } catch { console.error("Regtest merchant diagnostic refused"); process.exitCode = 1; }
