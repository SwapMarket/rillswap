import { execFileSync } from "node:child_process";

import { expect, test } from "@playwright/test";

test("disconnected NIP-59 producer runs in the supported browser without UI activation", async ({ page }) => {
  // Build only a test asset into Playwright's disposable preview tree. The
  // production Vite entry does not import or load this producer.
  execFileSync("bun", [
    "build", "src/nip59Transport.ts", "--target=browser", "--format=esm",
    "--outfile=tmp/preview/nip59-test-only.js",
  ]);
  await page.goto("http://127.0.0.1:18765/");
  const constructed = await page.evaluate(async () => {
    const testAsset = "/nip59-test-only.js";
    const { wrapPrivateRegtestEnvelope } = await import(testAsset) as typeof import("../src/nip59Transport");
    const sender = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 2 : 0);
    const recipient = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    // This known recipient is not trusted or funded; only browser execution
    // and byte construction are under test here.
    const content = "{\"protocol\":\"rillswap\",\"sender_session_key\":\"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\",\"wire_version\":\"1\"}";
    const wrap = wrapPrivateRegtestEnvelope(content, sender, recipient);
    return { kind: wrap.kind, tags: wrap.tags, bytes: new TextEncoder().encode(JSON.stringify(wrap)).length };
  });
  expect(constructed.kind).toBe(1059);
  expect(constructed.tags).toEqual([["p", "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"]]);
  expect(constructed.bytes).toBeGreaterThan(100);
  expect(constructed.bytes).toBeLessThanOrEqual(128 * 1024);
  await expect(page.getByText("Local-only development preview.", { exact: false })).toBeVisible();
});
