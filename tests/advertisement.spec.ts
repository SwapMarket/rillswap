import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { expect, test } from "@playwright/test";
import canonicalize from "canonicalize";

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
