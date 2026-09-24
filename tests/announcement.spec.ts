import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { expect, test } from "@playwright/test";
import canonicalize from "canonicalize";

test("disconnected signed Nostr announcement verifies in Chromium without relay traffic", async ({ page }) => {
  execFileSync("bun", [
    "build", "src/nostrProviderAnnouncement.ts", "--target=browser", "--format=esm",
    "--outfile=tmp/preview/nostr-announcement-test-only.js",
  ]);
  const published = JSON.parse(readFileSync(
    "unit/fixtures/nostr-announcement-regtest-v1.json", "utf8",
  ));
  const application = JSON.parse(readFileSync(
    "unit/fixtures/manual-advertisement-regtest-v1.json", "utf8",
  ));
  const content = canonicalize(application);
  if (content === undefined) throw new Error("test application fixture failed");
  const raw = JSON.stringify({
    id: published.id, pubkey: published.pubkey, created_at: published.created_at,
    kind: published.kind, tags: published.tags, content, sig: published.sig,
  });
  const offsiteRequests: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:18765/")) offsiteRequests.push(request.url());
  });
  await page.goto("http://127.0.0.1:18765/");
  const candidate = await page.evaluate(async (rawEvent) => {
    const asset = "/nostr-announcement-test-only.js";
    const { verifyPrivateRegtestAnnouncement } = await import(asset) as typeof import("../src/nostrProviderAnnouncement");
    const original = Date.now;
    Date.now = () => 1703021600 * 1000;
    try {
      const network = {
        family: "bitcoin", name: "regtest",
        genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        signet_challenge: null, consensus_profile: "bitcoin-core-v30.0-regtest-default",
        deployment_namespace: "rillswap-e2e-v1",
      };
      return verifyPrivateRegtestAnnouncement(
        rawEvent,
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        network, "btc-to-ln/v1",
      );
    } finally {
      Date.now = original;
    }
  }, raw);
  expect(candidate.source).toBe("signed-nip01-announcement");
  expect(candidate.outerEventId).toBe(published.id);
  expect(candidate.addressD).toBe(published.tags[2][1]);
  expect(offsiteRequests).toEqual([]);
});
