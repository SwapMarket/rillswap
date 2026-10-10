import { describe, expect, test } from "bun:test";
import { NETWORK_NAMES, relaysForNetwork, resolveSwapDefaults, validateRelay, validateRelays } from "../src/swap/config";

describe("explicit deployment defaults", () => {
  test("unconfigured public builds select mainnet with an encrypted relay", () => {
    expect(resolveSwapDefaults({})).toEqual({ network: "mainnet", relays: ["wss://relay.damus.io/", "wss://nos.lol/", "wss://relay.primal.net/"], mempoolApi: "https://mempool.space/api", broadcastApi: "https://mempool.space/api" });
  });
  test("supports every declared network without hostname inference", () => {
    for (const network of NETWORK_NAMES) {
      expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network }).network).toBe(network);
    }
    expect(relaysForNetwork("regtest")).toEqual(["ws://127.0.0.1:7777/"]);
    expect(relaysForNetwork("signet").every((relay) => relay.startsWith("wss://"))).toBe(true);
  });
  test("node origins are explicit public configuration, with a local regtest default only", () => {
    expect(resolveSwapDefaults({}).nodeApi).toBeUndefined();
    expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "signet" }).nodeApi).toBeUndefined();
    expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest" }).nodeApi).toBe("http://127.0.0.1:8093");
    expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest", VITE_RILLSWAP_NODE_API: "http://127.0.0.1:18093/" }).nodeApi).toBe("http://127.0.0.1:18093");
    for (const value of ["http://node.example", "https://*", "https://*.example.com", "https://user:secret@node.example", "https://node.example/#secret", "https://node.example/?secret=1", ""]) {
      for (const network of ["signet", "mainnet"]) expect(() => resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network, VITE_RILLSWAP_NODE_API: value })).toThrow();
    }
  });
  test("public builds admit only an explicitly configured concrete node origin", async () => {
    for (const configured of [false, true]) {
      const destination = `tmp/node-csp-${configured ? "configured" : "unset"}`;
      const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("VITE_RILLSWAP_")));
      const child = Bun.spawn([process.execPath, "node_modules/vite/bin/vite.js", "build", "--outDir", destination], {
        env: { ...env, VITE_RILLSWAP_NETWORK: "signet", ...(configured ? { VITE_RILLSWAP_NODE_API: "https://node.example:10443/lnd" } : {}) }, stdout: "pipe", stderr: "pipe",
      });
      const [errors, status] = await Promise.all([new Response(child.stderr).text(), child.exited, new Response(child.stdout).text()]);
      expect(status).toBe(0); expect(errors).not.toContain("error");
      const html = await Bun.file(`${destination}/swap.html`).text(), csp = html.match(/content="([^"]*connect-src[^"]*)"/)![1]!;
      expect(csp.includes("https://node.example:10443")).toBe(configured); expect(csp).not.toContain("https://*"); expect(csp).not.toContain("http://127.0.0.1:8093");
    }
  }, 30000);
  test("returning to the deployment network restores a custom relay port", () => {
    const defaults = resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest", VITE_RILLSWAP_RELAY: "ws://localhost:8777" });
    expect(relaysForNetwork("signet", defaults)).not.toContain("ws://localhost:8777/");
    expect(relaysForNetwork("regtest", defaults)).toEqual(["ws://localhost:8777/"]);
  });
  test("empty, partial, and unsupported explicit configuration fails closed", () => {
    for (const network of ["", "regtes", "MAINNET"]) {
      expect(() => resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network })).toThrow();
    }
    expect(() => resolveSwapDefaults({ VITE_RILLSWAP_RELAY: "" })).toThrow();
    expect(() => resolveSwapDefaults({ VITE_RILLSWAP_RELAY: "ws://127.0.0.1:7777" })).toThrow();
  });
  test("relay URLs contain no credentials or fragments and plaintext is local regtest only", () => {
    for (const relay of ["https://relay.test", "wss://user:secret@relay.test", "wss://relay.test/#private",
      "ws://relay.test", "ws://localhost.evil.test"]) {
      expect(() => validateRelay(relay, "regtest")).toThrow();
    }
    expect(validateRelay("ws://localhost:7777", "regtest")).toBe("ws://localhost:7777/");
    expect(() => validateRelay("ws://localhost:7777", "signet")).toThrow();
  });
  test("relay lists are bounded, deduplicated and reject ambiguous deployment overrides", () => {
    expect(validateRelays("wss://nos.lol, wss://nos.lol/\nwss://relay.damus.io", "signet")).toHaveLength(2);
    expect(() => validateRelays("", "regtest")).toThrow();
    expect(() => validateRelays("wss://a.test wss://b.test wss://c.test wss://d.test wss://e.test", "signet")).toThrow();
    expect(() => resolveSwapDefaults({ VITE_RILLSWAP_RELAY: "wss://a.test", VITE_RILLSWAP_RELAYS: "wss://b.test" })).toThrow();
  });
  test("Vite rejects an invalid explicit network before producing a bundle", async () => {
    const child = Bun.spawn([process.execPath, "node_modules/vite/bin/vite.js", "build"], {
      env: { ...process.env, VITE_RILLSWAP_NETWORK: "regtes" }, stdout: "pipe", stderr: "pipe",
    });
    const [errors, status] = await Promise.all([new Response(child.stderr).text(), child.exited]);
    expect(status).not.toBe(0);
    expect(errors).toContain("VITE_RILLSWAP_NETWORK must be");
  });
});
