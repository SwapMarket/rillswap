import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import { MerchantLedger } from "./merchant";
import { LndInvoiceBackend, lndRestTransport } from "./lnd";
import { createMerchantService } from "./server";

interface Config {
  origin: string; receiver: string; endpoint: string; ledgerPath: string; certificatePath: string;
  macaroonPath: string; issuanceKeyPath: string; statusKeyPath: string; eventKeyPath: string; adminTokenPath: string;
}
function privateBytes(path: string): Buffer {
  if (!isAbsolute(path)) throw new Error("Absolute private file path required");
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.size > 8192) throw new Error("Private regular file required");
  return readFileSync(path);
}
export async function merchantCommand(command: string, configPath: string): Promise<void> {
  const config = JSON.parse(privateBytes(configPath).toString("utf8")) as Config;
  const keys = ["origin", "receiver", "endpoint", "ledgerPath", "certificatePath", "macaroonPath", "issuanceKeyPath", "statusKeyPath", "eventKeyPath", "adminTokenPath"];
  if (!config || Object.keys(config).sort().join(",") !== keys.sort().join(",") || keys.some((key) => typeof config[key as keyof Config] !== "string") || !isAbsolute(config.ledgerPath) || !isAbsolute(config.certificatePath)) throw new Error("Invalid merchant configuration");
  const backend = new LndInvoiceBackend(lndRestTransport(config.endpoint, readFileSync(config.certificatePath), privateBytes(config.macaroonPath)),
    { origin: config.origin, receiver: config.receiver, network: "regtest" }, privateBytes(config.issuanceKeyPath));
  const identity = await backend.identity();
  if (command === "provision") { MerchantLedger.provision(config.ledgerPath, identity).close(); console.log("Merchant ledger explicitly provisioned (regtest only)."); return; }
  if (command !== "serve") throw new Error("Expected provision or serve");
  const ledger = MerchantLedger.open(config.ledgerPath, identity);
  const service = createMerchantService({ ledger, issuer: backend, observer: backend, statusKey: privateBytes(config.statusKeyPath),
    eventSigningKey: privateBytes(config.eventKeyPath), adminToken: privateBytes(config.adminTokenPath).toString("utf8").trim() });
  const server = Bun.serve({ hostname: "127.0.0.1", port: 8787, fetch: service.fetch });
  let active = false;
  const timer = setInterval(async () => { if (active) return; active = true;
    try { const result = await service.tick(); if (result.failedAttemptIds.length) console.error("Merchant observation or issuance requires reconciliation."); }
    catch { console.error("Merchant worker paused after a ledger error."); }
    finally { active = false; }
  }, 5000);
  const stop = async (): Promise<void> => { clearInterval(timer); await server.stop(false);
    while (active) await Bun.sleep(25); ledger.close(); process.exit(0); };
  process.once("SIGINT", () => { void stop(); }); process.once("SIGTERM", () => { void stop(); });
  console.log("Regtest merchant API listening on 127.0.0.1:8787; configure an HTTPS reverse proxy.");
}
if (import.meta.main) {
  merchantCommand(process.argv[2] ?? "", process.argv[3] ?? "").catch(() => { console.error("Merchant command refused; verify configuration, credentials and existing ledger."); process.exitCode = 1; });
}
