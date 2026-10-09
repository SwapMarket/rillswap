import { expect, test } from "bun:test";

test("canceling a batch promptly discards completed offers, closes pending transports, and prevents failover", async () => {
  const child = Bun.spawn([process.execPath, "unit/fixtures/marketplaceCancellationFixture.ts"], { stdout: "pipe", stderr: "pipe" });
  const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(errors).toBe(""); expect(status).toBe(0);
  const result = JSON.parse(output);
  expect(result.opened).toEqual(["wss://fast/", "wss://slow/"]);
  expect(result.closed).toEqual(["wss://fast/", "wss://slow/"]);
  expect(result.disposed).toEqual(["wss://fast/"]);
  expect(result.returned).toBe(0);
});
