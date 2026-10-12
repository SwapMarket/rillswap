import { expect, test } from "bun:test";
async function run(mode: string): Promise<{ events: string[]; error: string }> {
  const child = Bun.spawn([process.execPath, "unit/fixtures/lnErc20Lifecycle.ts", mode], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  if (code !== 0) throw new Error(stderr);
  return JSON.parse(stdout);
}
test("pre-firm storage failure sends no firm request", async () => {
  const result = await run("secrets"); expect(result.error).toContain("secret commit aborted");
  expect(result.events).not.toContain("send:quote_request:firm");
});
test("terms storage failure exposes neither acceptance nor invoice", async () => {
  const result = await run("terms"); expect(result.error).toContain("terms commit aborted");
  expect(result.events).not.toContain("send:terms_accept:"); expect(result.events).not.toContain("invoice");
});
test("exposure storage failure never sends claim calldata", async () => {
  const result = await run("exposure"); expect(result.error).toContain("exposure commit aborted");
  expect(result.events).toContain("invoice"); expect(result.events).not.toContain("wallet:claim");
});
test("lost wallet response follows the durable exposure grant and never automatically retries", async () => {
  const result = await run("lost"); expect(result.error).toContain("wallet response lost");
  expect(result.events.indexOf("exposure:commit")).toBeLessThan(result.events.indexOf("wallet:claim"));
  expect(result.events.filter((event) => event === "wallet:claim")).toHaveLength(1);
});
test("a delayed exposure commit leaves UNKNOWN but sends no stale claim", async () => {
  const result = await run("stale"); expect(result.error).toContain("safety check became stale");
  expect(result.events).toContain("exposure:commit"); expect(result.events).not.toContain("wallet:claim");
});
