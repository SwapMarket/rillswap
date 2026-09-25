/** Opt-in Chromium-produced age file, independently consumed by Go age and CLI. */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { expect, test } from "@playwright/test";
import { generateIdentity, identityToRecipient } from "age-encryption";
import canonicalize from "canonicalize";

test("browser ciphertext is inspectable by independent Go age and native CLI for both profiles", async ({ page }) => {
  test.skip(process.env.RILLSWAP_RUN_WEB_CLI_AGE !== "1", "explicit native/Go age interop opt-in required");
  const cli = resolve("../rill-cli/.venv/bin/rill");
  const network = resolve("../rill-docs/networks/regtest-rillswap-e2e-v1.json");
  const native = process.env.RILL_CRYPTO_LIBRARY;
  const age = process.env.AGE_BINARY;
  expect(existsSync(cli)).toBe(true);
  expect(existsSync(network)).toBe(true);
  expect(native && existsSync(native)).toBe(true);
  expect(age && existsSync(age)).toBe(true);
  if (!native || !age) throw new Error("Explicit native and Go age test binaries required");
  const goVersion = spawnSync(age, ["--version"], { encoding: "utf8", timeout: 10_000 });
  expect(goVersion.status).toBe(0);
  expect(goVersion.stdout.trim()).toBe("v1.3.1");

  execFileSync("bun", [
    "build", "src/recoveryAgeContainer.ts", "--target=browser", "--format=esm",
    "--outfile=tmp/preview/recovery-age-test-only.js",
  ]);
  mkdirSync("tmp", { recursive: true });
  const directory = mkdtempSync(resolve("tmp/age-browser-interop-"));
  const offsite: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:18765/")) offsite.push(request.url());
  });
  try {
    await page.goto("http://127.0.0.1:18765/");
    for (const [name, profile] of [
      ["initial-btc-to-ln-v1.json", "btc-to-ln/v1"],
      ["initial-ln-to-btc-no-prepayment-v1.json", "ln-to-btc/v1"],
    ] as const) {
      const object = JSON.parse(readFileSync(resolve("unit/fixtures", name), "utf8"));
      const canonical = canonicalize(object);
      if (canonical === undefined) throw new Error("Synthetic recovery fixture invalid");
      const original = new TextEncoder().encode(canonical);
      const identity = await generateIdentity();
      const recipient = await identityToRecipient(identity);
      const encrypted = Uint8Array.from(await page.evaluate(async ({ bytes, selected }) => {
        const asset = "/recovery-age-test-only.js";
        const { encryptCanonicalRecoveryForRecipient } = await import(asset) as typeof import("../src/recoveryAgeContainer");
        return Array.from(await encryptCanonicalRecoveryForRecipient(
          Uint8Array.from(bytes), selected,
        ));
      }, { bytes: Array.from(original), selected: recipient }));
      const identityPath = join(directory, `${profile.replace("/", "-")}.key`);
      const ciphertextPath = join(directory, `${profile.replace("/", "-")}.age`);
      writeFileSync(identityPath, identity + "\n", { mode: 0o600, flag: "wx" });
      writeFileSync(ciphertextPath, encrypted, { mode: 0o600, flag: "wx" });
      expect(execFileSync(age, ["-d", "-i", identityPath, ciphertextPath], {
        timeout: 30_000, maxBuffer: 256 * 1024,
      })).toEqual(Buffer.from(original));
      const inspected = spawnSync(cli, [
        "recover", "inspect", "--network", network,
        "--crypto-library", native, "--identity", identityPath, ciphertextPath,
      ], { encoding: "utf8", timeout: 30_000, maxBuffer: 256 * 1024 });
      expect(inspected.status).toBe(0);
      const report = JSON.parse(inspected.stdout) as Record<string, unknown>;
      expect(report.profile).toBe(profile);
      expect(report.recorded_binding_count).toBe(0);
      expect(inspected.stdout).not.toContain(identity);
      const otherIdentity = await generateIdentity();
      const wrong = join(directory, `wrong-${profile.replace("/", "-")}.key`);
      writeFileSync(wrong, otherIdentity + "\n", { mode: 0o600, flag: "wx" });
      const wrongResult = spawnSync(cli, [
        "recover", "inspect", "--network", network,
        "--crypto-library", native, "--identity", wrong, ciphertextPath,
      ], { encoding: "utf8", timeout: 30_000 });
      expect(wrongResult.status).not.toBe(0);
      const tampered = Uint8Array.from(encrypted);
      tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
      const corruptPath = join(directory, `tampered-${profile.replace("/", "-")}.age`);
      writeFileSync(corruptPath, tampered, { mode: 0o600, flag: "wx" });
      const corruptResult = spawnSync(cli, [
        "recover", "inspect", "--network", network,
        "--crypto-library", native, "--identity", identityPath, corruptPath,
      ], { encoding: "utf8", timeout: 30_000 });
      expect(corruptResult.status).not.toBe(0);

      // The disconnected browser container intentionally performs only
      // canonical/version preflight. CLI import must still reject a decrypted
      // semantic-invalid file before producing a recovery report.
      expect(object.contract_hash).not.toBe("00".repeat(32));
      const semanticInvalid = [
        ["missing-user-secret", Object.fromEntries(
          Object.entries(object).filter(([field]) => field !== "user_secret"),
        )],
        ["wrong-contract-hash", { ...object, contract_hash: "00".repeat(32) }],
      ] as const;
      for (const [label, invalidObject] of semanticInvalid) {
        const invalidCanonical = canonicalize(invalidObject);
        if (invalidCanonical === undefined) throw new Error("invalid fixture did not canonicalize");
        const invalidPlaintext = new TextEncoder().encode(invalidCanonical);
        const invalidEncrypted = Uint8Array.from(await page.evaluate(async ({ bytes, selected }) => {
          const asset = "/recovery-age-test-only.js";
          const { encryptCanonicalRecoveryForRecipient } = await import(asset) as typeof import("../src/recoveryAgeContainer");
          return Array.from(await encryptCanonicalRecoveryForRecipient(
            Uint8Array.from(bytes), selected,
          ));
        }, { bytes: Array.from(invalidPlaintext), selected: recipient }));
        const invalidPath = join(directory, `${label}-${profile.replace("/", "-")}.age`);
        writeFileSync(invalidPath, invalidEncrypted, { mode: 0o600, flag: "wx" });
        expect(execFileSync(age, ["-d", "-i", identityPath, invalidPath], {
          timeout: 30_000, maxBuffer: 256 * 1024,
        })).toEqual(Buffer.from(invalidPlaintext));
        const refused = spawnSync(cli, [
          "recover", "inspect", "--network", network,
          "--crypto-library", native, "--identity", identityPath, invalidPath,
        ], { encoding: "utf8", timeout: 30_000, maxBuffer: 256 * 1024 });
        expect(refused.status).not.toBe(0);
        expect(refused.stdout).toBe("");
        expect(refused.stderr).toBe("Recovery operation failed; no payment or funding authority.\n");
        expect(refused.stderr).not.toContain(identity);
      }
    }
    expect(offsite).toEqual([]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
