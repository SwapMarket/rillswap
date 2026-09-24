import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { expect, test } from "@playwright/test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";

function signedFixture(): { advertisement: Record<string, unknown>; signature: string } {
  return JSON.parse(readFileSync("unit/fixtures/manual-advertisement-regtest-v1.json", "utf8"));
}

function canonical(value: unknown): string {
  const serialized = canonicalize(value);
  if (serialized === undefined) throw new Error("test input invalid");
  return serialized;
}

function resignFixture(input: ReturnType<typeof signedFixture>): void {
  const encoder = new TextEncoder();
  const tag = sha256(encoder.encode("RillSwap/advertisement/v1"));
  const content = encoder.encode(canonical(input.advertisement));
  const bytes = new Uint8Array(64 + content.length);
  bytes.set(tag);
  bytes.set(tag, 32);
  bytes.set(content, 64);
  const scalar = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 2 : 0);
  input.signature = Buffer.from(schnorr.sign(sha256(bytes), scalar, new Uint8Array(32)))
    .toString("hex");
}

test("manual signed advertisement verifier executes without contacting an endpoint", async ({ page }) => {
  execFileSync("bun", [
    "build", "src/manualProviderAdvertisement.ts", "--target=browser", "--format=esm",
    "--outfile=tmp/preview/manual-advertisement-test-only.js",
  ]);
  const fixture = JSON.parse(readFileSync(
    "unit/fixtures/manual-advertisement-regtest-v1.json", "utf8",
  ));
  const signed = canonicalize(fixture);
  if (signed === undefined) throw new Error("test fixture could not be canonicalized");
  const offsiteRequests: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:18765/")) offsiteRequests.push(request.url());
  });
  await page.goto("http://127.0.0.1:18765/");
  const selected = await page.evaluate(async (raw) => {
    const testAsset = "/manual-advertisement-test-only.js";
    const { verifyManualProviderAdvertisement } = await import(testAsset) as typeof import("../src/manualProviderAdvertisement");
    const originalNow = Date.now;
    Date.now = () => 1703021600 * 1000;
    try {
      const network = {
        family: "bitcoin", name: "regtest",
        genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        signet_challenge: null, consensus_profile: "bitcoin-core-v30.0-regtest-default",
        deployment_namespace: "rillswap-e2e-v1",
      };
      const candidate = verifyManualProviderAdvertisement(
        raw, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        network, "btc-to-ln/v1",
      );
      return { source: candidate.source, inbox: candidate.advertisedEpochInboxKeys[0] };
    } finally {
      Date.now = originalNow;
    }
  }, signed);
  expect(selected.source).toBe("manual-app-signature-only");
  expect(selected.inbox).toBe("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
  expect(offsiteRequests).toEqual([]);
});

test("explicit manual import preserves user pin, inert metadata and tab-local revision maximum", async ({ page }) => {
  const offsiteRequests: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:18765/")) offsiteRequests.push(request.url());
  });
  await page.addInitScript(() => { Date.now = () => 1703021600 * 1000; });
  await page.goto("http://127.0.0.1:18765/");
  const status = page.locator("#manual-provider-status");
  const details = page.locator("#manual-provider-details");
  const importButton = page.getByRole("button", { name: "Verify manual advertisement" });
  const original = signedFixture();
  await page.locator("#signed-provider-advertisement").fill(canonical(original));
  await importButton.click();
  await expect(status).toContainText("independently approved provider identity");
  await page.locator("#approved-provider-identity").fill("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
  await page.locator("#approved-network").selectOption("regtest-rillswap-e2e-v1");
  await page.locator("#approved-profile").selectOption("btc-to-ln/v1");
  const tampered = structuredClone(original);
  (tampered.advertisement as Record<string, unknown>).epoch_inbox_xonly_keys = ["ff".repeat(32)];
  await page.locator("#signed-provider-advertisement").fill(canonical(tampered));
  await importButton.click();
  await expect(status).toContainText("Advertisement refused");
  await expect(details).toBeEmpty();

  await page.locator("#signed-provider-advertisement").fill(canonical(original));
  await importButton.click();
  await expect(status).toContainText("Historical offer only");
  await expect(details).toContainText("revision: 1");
  await expect(details).toContainText("wss://relay.example.invalid/");
  await importButton.click();
  await expect(status).toContainText("Same or lower revision");
  await expect(details).toContainText("revision: 1");

  const lower = structuredClone(original);
  lower.advertisement.revision = 0;
  resignFixture(lower);
  await page.locator("#signed-provider-advertisement").fill(canonical(lower));
  await importButton.click();
  await expect(status).toContainText("Same or lower revision");
  await expect(details).toContainText("revision: 1");

  const higher = structuredClone(original);
  higher.advertisement.revision = 2;
  higher.advertisement.transport_endpoints = ["wss://relay.example.invalid/<img src=x onerror=alert(1)>"];
  resignFixture(higher);
  await page.locator("#signed-provider-advertisement").fill(canonical(higher));
  await importButton.click();
  await expect(details).toContainText("revision: 2");
  await expect(details).toContainText("<img src=x onerror=alert(1)>");
  expect(await page.locator("#manual-provider-details img").count()).toBe(0);
  expect(offsiteRequests).toEqual([]);

  await page.reload();
  await expect(status).toContainText("no saved trust or revision history");
  await expect(details).toBeEmpty();
});
