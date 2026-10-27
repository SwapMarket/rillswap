import { afterEach, expect, spyOn, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { merchantCommand } from "../src/cli";
import { NETWORKS } from "../src/contract";
import { LndInvoiceBackend } from "../src/lnd";
import { MerchantLedger } from "../src/merchant";
import { receiver } from "./helpers";

const roots: string[] = [];
afterEach(() => { for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true }); });
function configuration(network: unknown) {
  mkdirSync("tmp", { recursive: true }); const root = mkdtempSync(resolve("tmp/merchant-cli-")); roots.push(root);
  const file = (name: string, bytes: string | Uint8Array) => { const path = join(root, name); writeFileSync(path, bytes, { mode: 0o600 }); return path; };
  const config: Record<string, unknown> = { network, origin: "https://merchant.example", receiver, endpoint: "https://127.0.0.1:8080",
    ledgerPath: join(root, "ledger.sqlite"), certificatePath: file("tls.cert", "fixture certificate"),
    macaroonPath: file("invoice.macaroon", new Uint8Array([1])), issuanceKeyPath: file("issuance.key", new Uint8Array(32).fill(9)),
    statusKeyPath: file("status.key", new Uint8Array(32).fill(10)), eventKeyPath: file("event.key", new Uint8Array(32).fill(11)),
    adminTokenPath: file("admin.token", "fixture_admin_token_00000000000000") };
  const path = file("config.json", JSON.stringify(config));
  return { path, config, write: () => writeFileSync(path, JSON.stringify(config), { mode: 0o600 }) };
}

for (const network of NETWORKS) {
  test(`explicit merchant CLI ${network} provisioning preserves the attested identity`, async () => {
    const f = configuration(network), log = spyOn(console, "log").mockImplementation(() => {});
    // No transport call is made: the attested backend identity is the only stub.
    const attestation = spyOn(LndInvoiceBackend.prototype, "identity").mockImplementation(async function(this: LndInvoiceBackend) {
      return this.configuredIdentity;
    });
    try {
      await merchantCommand("provision", f.path);
      expect(attestation).toHaveBeenCalledTimes(1);
      const identity = { origin: f.config.origin as string, receiver, network,
        issuerId: "lnd_" + new Bun.CryptoHasher("sha256").update(new Uint8Array(32).fill(9)).digest("hex") };
      const ledger = MerchantLedger.open(f.config.ledgerPath as string, identity);
      try { expect(ledger.identity.network).toBe(network); expect(ledger.pendingAttempts()).toEqual([]); expect(ledger.pendingEvents()).toEqual([]); }
      finally { ledger.close(); }
      expect(log.mock.calls[0]![0]).toContain(network);
    } finally { attestation.mockRestore(); log.mockRestore(); }
  });
}

for (const network of [undefined, "testnet4", "unknown", null]) {
  test(`missing or unsupported merchant CLI network ${network} fails before backend access`, async () => {
    const f = configuration(network);
    if (network === undefined) { delete f.config.network; f.write(); }
    const attestation = spyOn(LndInvoiceBackend.prototype, "identity");
    try {
      await expect(merchantCommand("provision", f.path)).rejects.toThrow("Invalid merchant configuration");
      expect(attestation).not.toHaveBeenCalled();
      expect(await Bun.file(f.config.ledgerPath as string).exists()).toBe(false);
    } finally { attestation.mockRestore(); }
  });
}
