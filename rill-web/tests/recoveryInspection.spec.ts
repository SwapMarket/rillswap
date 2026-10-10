import { expect, test } from "@playwright/test";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import type { inspectRecoveryPlaintext } from "../src/recoveryInspection";
import type { InspectionCase } from "../unit/fixtures/recoveryInspectionCases";

declare global {
  interface Window { inspectRecoveryPlaintext: typeof inspectRecoveryPlaintext }
}

test("historical inspection in a no-network browser passes the native-signature corpus without storage or requests", async ({ page }) => {
  const requests: string[] = [], sockets: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto("http://127.0.0.1:18765/test-only/recovery-admission.html");
  await page.waitForFunction(() => window.recoveryAdmissionReady);
  const corpus = JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-inspection-cases.json", import.meta.url), "utf8")) as InspectionCase[];
  const cases = corpus.map(({ name, record, accepted, expectedNetwork }) => ({ name, accepted,
    canonical: canonicalize(record)!, expectedNetwork }));
  const results = await page.evaluate((vectors) => {
    let sideEffects = 0;
    const refuse = (): never => { sideEffects++; throw new Error("side effect attempted"); };
    // Fail even a caught attempt, rather than relying only on connect-src 'none'.
    Object.defineProperty(window, "fetch", { value: refuse });
    Object.defineProperty(window, "WebSocket", { value: class { constructor() { refuse(); } } });
    indexedDB.open = refuse;
    Storage.prototype.setItem = refuse;
    const outcomes = vectors.map(({ name, canonical, expectedNetwork }) => {
      try {
        const report = window.inspectRecoveryPlaintext(new TextEncoder().encode(canonical), expectedNetwork);
        return { name, accepted: true, count: report.recordedBindingCount, frozen: Object.isFrozen(report) };
      } catch (error) { return { name, accepted: false, error: (error as Error).message }; }
    });
    return { outcomes, sideEffects };
  }, cases);
  expect(results.sideEffects).toBe(0);
  for (const [i, result] of results.outcomes.entries()) {
    expect(result.accepted, result.name).toBe(cases[i]!.accepted);
    if (result.accepted) expect(result.frozen).toBe(true);
    else expect(result.error).toBe("Recovery document could not be authenticated");
  }
  expect(sockets).toEqual([]);
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
});
