import { expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

test("merchant diagnostic refuses without affirmative opt-in, with no raw errors", async () => {
  const child = Bun.spawn([process.execPath, "scripts/regtest-merchant.ts", "serve", "/nonexistent/config.json"], {
    env: { ...process.env, RILLSWAP_REGTEST_MERCHANT: "" }, stdout: "pipe", stderr: "pipe",
  });
  const [out, errors, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(code).toBe(1); expect(out).toBe(""); expect(errors).toBe("Regtest merchant diagnostic refused\n");
});

test("ordinary diagnostic startup refuses missing ledger without reconstructing state", async () => {
  mkdirSync(resolve("../tmp"), { recursive: true });
  const directory = mkdtempSync(resolve("../tmp/merchant-refusal-")); chmodSync(directory, 0o700);
  try {
    const config: Record<string, string> = { origin: "https://merchant.invalid", receiver: "fixture", endpoint: "https://127.0.0.1:1/", ledgerPath: join(directory, "merchant.sqlite") };
    for (const field of ["issuanceKeyPath", "statusKeyPath", "eventKeyPath", "certificatePath", "macaroonPath", "adminTokenPath"]) {
      config[field] = join(directory, field); writeFileSync(config[field]!, new Uint8Array(32), { mode: 0o600 });
    }
    const path = join(directory, "config.json"); writeFileSync(path, JSON.stringify(config), { mode: 0o600 });
    const child = Bun.spawn([process.execPath, "tests/fixtures/regtestMerchantRefusal.ts", path], { stdout: "pipe", stderr: "pipe" });
    const [out, errors, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(code).toBe(1); expect(out).toBe(""); expect(errors).toBe("Regtest merchant diagnostic refused\n");
    for (const suffix of ["", "-wal", "-shm"]) expect(existsSync(config.ledgerPath + suffix)).toBe(false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
