import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { expect, test } from "@playwright/test";
import canonicalize from "canonicalize";

function signedEvent(): { id: string; pubkey: string; created_at: number; kind: number; tags: string[][]; content: string; sig: string } {
  const published = JSON.parse(readFileSync(
    "unit/fixtures/nostr-announcement-regtest-v1.json", "utf8",
  ));
  const application = JSON.parse(readFileSync(
    "unit/fixtures/manual-advertisement-regtest-v1.json", "utf8",
  ));
  const content = canonicalize(application);
  if (content === undefined) throw new Error("test application fixture failed");
  return {
    id: published.id, pubkey: published.pubkey, created_at: published.created_at,
    kind: published.kind, tags: published.tags, content, sig: published.sig,
  };
}

test("signed Nostr announcement verifier executes in Chromium without relay traffic", async ({ page }) => {
  execFileSync("bun", [
    "build", "src/nostrProviderAnnouncement.ts", "--target=browser", "--format=esm",
    "--outfile=tmp/preview/nostr-announcement-test-only.js",
  ]);
  const published = signedEvent();
  const raw = JSON.stringify(published);
  const offsiteRequests: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:18765/")) offsiteRequests.push(request.url());
  });
  await page.goto("http://127.0.0.1:18765/");
  const candidate = await page.evaluate(async (rawEvent) => {
    const asset = "/nostr-announcement-test-only.js";
    const { verifyNostrProviderAnnouncement } = await import(asset) as typeof import("../src/nostrProviderAnnouncement");
    const original = Date.now;
    Date.now = () => 1703021600 * 1000;
    try {
      const network = {
        family: "bitcoin", name: "regtest",
        genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        signet_challenge: null, consensus_profile: "bitcoin-core-v30.0-regtest-default",
        deployment_namespace: "rillswap-e2e-v1",
      };
      return verifyNostrProviderAnnouncement(
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
  expect(candidate.addressD).toBe(published.tags[2]![1]);
  expect(offsiteRequests).toEqual([]);
});

test("explicit signed-event paste stays offline and respects independent selection", async ({ page }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  await page.addInitScript(() => { Date.now = () => 1703021600 * 1000; });
  await page.goto("http://127.0.0.1:18765/");
  const format = page.locator("#provider-advertisement-format");
  const identity = page.locator("#approved-provider-identity");
  const network = page.locator("#approved-network");
  const profile = page.locator("#approved-profile");
  const text = page.locator("#signed-provider-advertisement");
  const verify = page.getByRole("button", { name: "Verify manual advertisement" });
  const status = page.locator("#manual-provider-status");
  const details = page.locator("#manual-provider-details");
  const event = signedEvent();
  await expect(format).toHaveValue("application");
  await format.selectOption("nostr-event");
  await expect(text).toHaveJSProperty("maxLength", 128 * 1024);
  await text.fill(JSON.stringify(event));
  await verify.click();
  await expect(status).toContainText("independently approved provider identity");
  await identity.fill(event.pubkey);
  await network.selectOption("regtest-rillswap-e2e-v1");
  await profile.selectOption("btc-to-ln/v1");
  await verify.click();
  await expect(status).toContainText("NIP-01 and application signatures verified");
  await expect(details).toContainText(`NIP-01 event ID: ${event.id}`);
  await expect(details).toContainText(`Address d: ${event.tags[2]![1]}`);
  await expect(details).toContainText("wss://relay.example.invalid/");
  expect(await details.locator("a").count()).toBe(0);

  await text.fill(JSON.stringify({ ...event, sig: "00".repeat(64) }));
  await verify.click();
  await expect(status).toContainText("Advertisement refused");
  await expect(details).toContainText(`NIP-01 event ID: ${event.id}`);
  await text.fill(JSON.stringify(event).replace('"kind":39417', '"kind":39417,"\\u006bind":39417'));
  await verify.click();
  await expect(status).toContainText("Advertisement refused");
  await text.fill(JSON.stringify(event));
  await identity.fill("aa".repeat(32));
  await verify.click();
  await expect(status).toContainText("Advertisement refused");
  await identity.fill(event.pubkey);
  await network.selectOption("mainnet");
  await verify.click();
  await expect(status).toContainText("Advertisement refused");
  await network.selectOption("regtest-rillswap-e2e-v1");
  await text.evaluate((textarea: HTMLTextAreaElement) => {
    textarea.value = "x".repeat(128 * 1024 + 1);
  });
  await verify.click();
  await expect(status).toContainText("Advertisement refused");
  await format.selectOption("application");
  await expect(text).toHaveJSProperty("maxLength", 64 * 1024);
  const application = JSON.parse(readFileSync(
    "unit/fixtures/manual-advertisement-regtest-v1.json", "utf8",
  ));
  const applicationBytes = canonicalize(application);
  if (applicationBytes === undefined) throw new Error("test application fixture failed");
  await text.fill(applicationBytes);
  await verify.click();
  await expect(status).toContainText("Same or lower revision already observed in this tab");
  await expect(details).toBeEmpty();
  expect(requests.every((request) => request.startsWith("http://127.0.0.1:18765/"))).toBe(true);
  await page.reload();
  await expect(format).toHaveValue("application");
  await expect(details).toBeEmpty();
  await expect(status).toContainText("no saved trust or revision history");
  await identity.fill(event.pubkey);
  await network.selectOption("regtest-rillswap-e2e-v1");
  await profile.selectOption("btc-to-ln/v1");
  await text.fill(applicationBytes);
  await verify.click();
  await expect(status).toContainText("Application signature verified");
  await format.selectOption("nostr-event");
  await expect(text).toBeEmpty();
  await expect(text).toHaveJSProperty("maxLength", 128 * 1024);
  await text.fill(JSON.stringify(event));
  await verify.click();
  await expect(status).toContainText("Same or lower revision already observed in this tab");
  await format.selectOption("application");
  await expect(text).toBeEmpty();
  await expect(text).toHaveJSProperty("maxLength", 64 * 1024);
  expect(requests.every((request) => request.startsWith("http://127.0.0.1:18765/"))).toBe(true);
});
