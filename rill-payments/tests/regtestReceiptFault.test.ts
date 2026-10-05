import { expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { receiver } from "./helpers";

function configuration(directory: string): string {
  const config: Record<string, string> = { origin: "https://merchant.invalid", receiver, endpoint: "https://127.0.0.1:1/", ledgerPath: join(directory, "merchant.sqlite") };
  for (const field of ["issuanceKeyPath", "statusKeyPath", "eventKeyPath", "certificatePath", "macaroonPath", "adminTokenPath"]) {
    config[field] = join(directory, field); writeFileSync(config[field]!, new Uint8Array(32), { mode: 0o600 });
  }
  const path = join(directory, "config.json"); writeFileSync(path, JSON.stringify(config), { mode: 0o600 }); return path;
}
async function invoke(scenario: string, path: string) {
  const child = Bun.spawn([process.execPath, "tests/fixtures/regtestReceiptFault.ts", scenario, path], { stdout: "pipe", stderr: "pipe" });
  const timeout = setTimeout(() => child.kill(), 5000);
  try {
    const [out, errors, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(out + errors).not.toContain("SECRET_CANARY"); return { out, errors, code };
  } finally { clearTimeout(timeout); }
}
for (const scenario of ["settled", "open", "write_failure", "file_fsync_failure", "directory_fsync_failure", "existing_marker"]) {
  test(`settled observation fault is durable, fail-closed and invocation-local: ${scenario}`, async () => {
    mkdirSync(resolve("../tmp"), { recursive: true });
    const directory = mkdtempSync(resolve("../tmp/receipt-fault-")); chmodSync(directory, 0o700);
    const marker = join(directory, "settled-receipt-fault.json");
    try {
      const path = configuration(directory);
      if (scenario === "existing_marker") writeFileSync(marker, "partial-marker", { mode: 0o600 });
      const { out, errors, code } = await invoke(scenario, path);
      if (scenario === "existing_marker") {
        expect(code).toBe(1); expect(out).toBe(""); expect(errors).toBe("Regtest merchant diagnostic refused\n");
        expect(readFileSync(marker, "utf8")).toBe("partial-marker");
      } else if (scenario === "open") {
        expect(code).toBe(0); expect(errors).toBe(""); expect(existsSync(marker)).toBe(false);
        expect(JSON.parse(readFileSync(join(directory, "observation-returned.json"), "utf8")).state).toBe("OPEN");
      } else {
        expect(JSON.parse(out).ready).toBe(true);
        expect(existsSync(join(directory, "observation-returned.json"))).toBe(false);
        if (scenario === "settled") {
          expect(code).toBe(74); expect(errors).toBe("");
          const contents = readFileSync(marker, "utf8"); expect(contents).not.toContain("SECRET_CANARY");
          expect(JSON.parse(contents)).toEqual({ version: "regtest-settled-receipt-loss/1", receiver, network: "regtest",
            paymentHash: "a".repeat(64), invoiceAmountMsat: "50000000", paidMsat: "50000000", state: "SETTLED", settledAt: 1234 });
          expect(statSync(marker).mode & 0o777).toBe(0o600);
          expect(JSON.parse(readFileSync(join(directory, "fault-audit.json"), "utf8"))).toEqual(["write", "file_fsync", "directory_fsync"]);
          const reopened = await invoke("normal", path);
          expect(reopened.code).toBe(0); expect(reopened.errors).toBe("");
          expect(existsSync(join(directory, "observation-returned.json"))).toBe(true);
          expect(readFileSync(marker, "utf8")).toBe(contents);
        } else {
          expect(code).toBe(75); expect(errors).toBe("Regtest receipt fault persistence refused\n");
        }
      }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }, 12000);
}
