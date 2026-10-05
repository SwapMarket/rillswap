// Isolated subprocess: exercise the real diagnostic fault boundary and filesystem.
import { mock } from "bun:test";
import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { receiver } from "../helpers";
const [scenario, configPath] = process.argv.slice(2);
if (!configPath) throw new Error("Fixture config required");
const directory = dirname(configPath), marker = join(directory, "settled-receipt-fault.json");
const original = { ...fs }, realWrite = fs.writeFileSync, realSync = fs.fsyncSync, realOpen = fs.openSync;
const audit: string[] = []; let markerFd = -1, syncs = 0;
mock.module("node:fs", () => ({ ...original,
  openSync: (path: fs.PathLike, flags: string, mode?: number) => {
    const fd = realOpen(path, flags, mode); if (path === marker && flags === "wx") markerFd = fd; return fd;
  },
  writeFileSync: (fd: number | fs.PathOrFileDescriptor, data: string | NodeJS.ArrayBufferView, options?: fs.WriteFileOptions) => {
    if (fd === markerFd) {
      audit.push("write"); realWrite(join(directory, "fault-audit.json"), JSON.stringify(audit));
      if (scenario === "write_failure") throw new Error("SECRET_CANARY");
    }
    return realWrite(fd, data, options);
  },
  fsyncSync: (fd: number) => {
    syncs++; audit.push(syncs === 1 ? "file_fsync" : "directory_fsync");
    realWrite(join(directory, "fault-audit.json"), JSON.stringify(audit));
    if ((scenario === "file_fsync_failure" && syncs === 1) || (scenario === "directory_fsync_failure" && syncs === 2)) throw new Error("SECRET_CANARY");
    return realSync(fd);
  },
}));
mock.module("../../src/lnd", () => ({ lndRestTransport: () => ({}), LndInvoiceBackend: class {
  async identity() { return { issuerId: "fixture", origin: "https://merchant.invalid", receiver, network: "regtest" }; }
  async lookup() { return { receiver, network: "regtest", paymentHash: "a".repeat(64), invoiceAmountMsat: "50000000", paidMsat: "50000000",
    state: scenario === "open" ? "OPEN" : "SETTLED", settledAt: scenario === "open" ? null : 1234, preimage: "SECRET_CANARY" }; }
} }));
mock.module("../../src/merchant", () => ({ MerchantLedger: {
  open: () => ({ close() {} }), provision: () => { throw new Error("Never provision during recovery"); },
} }));
mock.module("../../src/server", () => ({ createMerchantService: (options: { observer: { lookup(hash: string): Promise<unknown> } }) => ({
  fetch: () => new Response("fixture"),
  async tick() { const receipt = await options.observer.lookup("a".repeat(64));
    realWrite(join(directory, "observation-returned.json"), JSON.stringify(receipt)); process.exit(0); },
}) }));
process.env.RILLSWAP_REGTEST_MERCHANT = "1";
process.argv = [process.execPath, "regtest-merchant.ts", "serve", configPath,
  ...(scenario === "normal" ? [] : ["crash-after-settled"])];
await import("../../scripts/regtest-merchant");
