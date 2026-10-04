import { expect, test } from "bun:test";
import { probeExternalProviders } from "../src/discovery";

test("discovery is GET-only to fixed official origins and never enables execution", async () => {
  const urls: string[] = [];
  const result = await probeExternalProviders(async (url, init) => {
    urls.push(String(url)); expect(init?.method).toBe("GET"); expect(init?.redirect).toBe("error"); expect(init?.credentials).toBe("omit");
    return Response.json({ available: true, status: "success", maliciousProvider: "http://127.0.0.1/admin" });
  }, () => 1000);
  expect(result).toHaveLength(4); expect(result.every((entry) => entry.state === "unverified_catalog" && !entry.executable)).toBe(true);
  expect(urls.every((url) => ["https://mainnet.swaps-api.atomiq.exchange", "https://api.boltz.exchange"].includes(new URL(url).origin))).toBe(true);
  expect(JSON.stringify(result)).not.toContain("maliciousProvider");
});
test("paused services, DNS failure and spoofed HTML preserve disabled status", async () => {
  const paused = await probeExternalProviders(async () => new Response("web app is stopped", { status: 403 }), () => 1000);
  expect(paused.every((entry) => entry.state === "http_error" && entry.httpStatus === 403 && !entry.executable)).toBe(true);
  const offline = await probeExternalProviders(async () => { throw new Error("ENOTFOUND"); }, () => 1000);
  expect(offline.every((entry) => entry.state === "unreachable" && entry.httpStatus === null)).toBe(true);
  const html = await probeExternalProviders(async () => new Response("paid", { headers: { "Content-Type": "text/html" } }), () => 1000);
  expect(html.every((entry) => entry.state === "invalid_catalog" && !entry.executable)).toBe(true);
});
