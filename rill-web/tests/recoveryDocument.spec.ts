import { expect, test } from "@playwright/test";
import canonicalize from "canonicalize";
import fixture from "../unit/fixtures/initial-btc-to-ln-v1.json" with { type: "json" };
import type { parseRecoveryPlaintext } from "../src/recoveryDocument";

declare global {
  interface Window {
    parseRecoveryPlaintext: typeof parseRecoveryPlaintext;
    recoveryAdmissionReady: boolean;
  }
}

test("static recovery admission runs in the browser without eval or network access and grants no authority", async ({ page }) => {
  const requests: string[] = [], sockets: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto("http://127.0.0.1:18765/test-only/recovery-admission.html");
  await page.waitForFunction(() => window.recoveryAdmissionReady);
  const result = await page.evaluate((canonical) => {
    const bytes = new TextEncoder().encode(canonical);
    const parsed = window.parseRecoveryPlaintext(bytes);
    const errors: string[] = [];
    for (const raw of [" " + canonical, canonical.replace('"format":"rillswap-recovery"', '"format":"private-error-canary"')]) {
      try { window.parseRecoveryPlaintext(new TextEncoder().encode(raw)); }
      catch (error) { errors.push((error as Error).message); }
    }
    return { authentication: parsed.authentication, format: parsed.document.format,
      frozen: Object.isFrozen(parsed.document) && Object.isFrozen(parsed.document.user_secret), errors };
  }, canonicalize(fixture)!);
  expect(result).toEqual({ authentication: "unverified", format: "rillswap-recovery", frozen: true,
    errors: ["Recovery document could not be parsed", "Recovery document could not be parsed"] });
  expect(sockets).toEqual([]);
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
});
