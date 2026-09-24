import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { expect, test } from "@playwright/test";
import { Decrypter, generateIdentity, identityToRecipient } from "age-encryption";
import canonicalize from "canonicalize";

test("disconnected age container encrypts both profiles in Chromium under production CSP", async ({ page }) => {
  execFileSync("bun", [
    "build", "src/recoveryAgeContainer.ts", "--target=browser", "--format=esm",
    "--outfile=tmp/preview/recovery-age-test-only.js",
  ]);
  const offsite: string[] = [];
  const sockets: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:18765/")) offsite.push(request.url());
  });
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto("http://127.0.0.1:18765/");
  for (const name of [
    "initial-btc-to-ln-v1.json", "initial-ln-to-btc-no-prepayment-v1.json",
  ]) {
    const document = JSON.parse(readFileSync(`unit/fixtures/${name}`, "utf8"));
    const canonical = canonicalize(document);
    if (canonical === undefined) throw new Error("test recovery fixture is invalid");
    const original = new TextEncoder().encode(canonical);
    const identity = await generateIdentity();
    const recipient = await identityToRecipient(identity);
    const produced = await page.evaluate(async ({ bytes, ageRecipient }) => {
      const asset = "/recovery-age-test-only.js";
      const { encryptCanonicalRecoveryForRecipient } = await import(asset) as typeof import("../src/recoveryAgeContainer");
      const ciphertext = await encryptCanonicalRecoveryForRecipient(
        Uint8Array.from(bytes), ageRecipient,
      );
      return Array.from(ciphertext);
    }, { bytes: Array.from(original), ageRecipient: recipient });
    const ciphertext = Uint8Array.from(produced);
    expect(new TextDecoder().decode(ciphertext.subarray(0, 22)))
      .toBe("age-encryption.org/v1\n");
    const decryptor = new Decrypter();
    decryptor.addIdentity(identity);
    expect(await decryptor.decrypt(ciphertext)).toEqual(original);
  }
  expect(offsite).toEqual([]);
  expect(sockets).toEqual([]);
  await expect(page.getByText("Do not enter secrets or send funds.", { exact: false }))
    .toBeVisible();
});
