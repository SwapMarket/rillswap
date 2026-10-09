import { describe, expect, test } from "bun:test";
import { NETWORK_NAMES, relayForNetwork, resolveSwapDefaults, validateRelay } from "../src/swap/config";

describe("explicit deployment defaults", () => {
  test("unconfigured public builds select mainnet with an encrypted relay", () => {
    expect(resolveSwapDefaults({})).toEqual({ network: "mainnet", relay: "wss://relay.damus.io/" });
  });
  test("supports every declared network without hostname inference", () => {
    for (const network of NETWORK_NAMES) {
      expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network }).network).toBe(network);
    }
    expect(relayForNetwork("regtest")).toBe("ws://127.0.0.1:7777/");
    expect(relayForNetwork("signet")).toStartWith("wss://");
  });
  test("returning to the deployment network restores a custom relay port", () => {
    const defaults = resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest", VITE_RILLSWAP_RELAY: "ws://localhost:8777" });
    expect(relayForNetwork("signet", defaults)).toBe("wss://relay.damus.io/");
    expect(relayForNetwork("regtest", defaults)).toBe("ws://localhost:8777/");
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
  test("Vite rejects an invalid explicit network before producing a bundle", async () => {
    const child = Bun.spawn([process.execPath, "node_modules/vite/bin/vite.js", "build"], {
      env: { ...process.env, VITE_RILLSWAP_NETWORK: "regtes" }, stdout: "pipe", stderr: "pipe",
    });
    const [errors, status] = await Promise.all([new Response(child.stderr).text(), child.exited]);
    expect(status).not.toBe(0);
    expect(errors).toContain("VITE_RILLSWAP_NETWORK must be");
  });
});
