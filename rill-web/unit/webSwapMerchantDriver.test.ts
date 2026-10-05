import { expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { resolve, join } from "node:path";

for (const scenario of ["success", "failure", "failure_equals"]) {
  test(`merchant driver wiring, durable files, and public redaction: ${scenario}`, async () => {
    mkdirSync(resolve("../tmp"), { recursive: true });
    const out = mkdtempSync(resolve("../tmp/merchant-driver-"));
    try {
      const child = Bun.spawn([process.execPath, "unit/fixtures/webSwapMerchantFixture.ts", scenario, out], { stdout: "pipe", stderr: "pipe" });
      const [output, errors, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(output + errors).not.toContain("SECRET_CANARY");
      expect(output + errors).not.toContain("PRIVATE_COOKIE_CANARY");
      expect(readFileSync(join(out, "closed"), "utf8")).toBe("yes");
      if (scenario.startsWith("failure")) {
        expect(code).toBe(1); expect(output).toBe(""); expect(errors).toBe("Merchant swap diagnostic refused\n");
      } else {
        expect(code).toBe(0); expect(errors).toBe("");
        expect(JSON.parse(output)).toEqual({ state: "awaiting_merchant_receipt", swapId: "a".repeat(64), fundingTxid: "b".repeat(64), recoveryRef: "web-recovery-paid.age" });
        for (const stage of ["terms", "funded", "paid"]) {
          const path = join(out, `web-recovery-${stage}.age`);
          expect([...readFileSync(path)]).toEqual([1, 2, 3]); expect(statSync(path).mode & 0o777).toBe(0o600);
        }
      }
    } finally { rmSync(out, { recursive: true, force: true }); }
  });
}
