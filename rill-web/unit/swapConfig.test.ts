import { describe, expect, test } from "bun:test";
import { explorerTxUrl, MAX_RELAYS, NETWORK_NAMES, relaysForNetwork, resolveSwapDefaults, trustedEvmAsset, validateRelay, validateRelays } from "../src/swap/config";
import { isOnionRelay } from "../src/swap/publicRelays";

describe("explicit deployment defaults", () => {
  const asset = { family: "evm", chain_id: 31337, name: "anvil-dev", htlc_contract: `0x${"11".repeat(20)}`, htlc_version: 6,
    token_contract: `0x${"22".repeat(20)}`, token_symbol: "fUSDC", token_decimals: 6, block_seconds: 2, deployment_namespace: "rillswap-e2e-v1" } as const;
  test("trusted asset configuration is complete and isolated by network and namespace", () => {
    const defaults = resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest", VITE_RILLSWAP_EVM_ASSETS: JSON.stringify({ USDC: asset }) });
    expect(trustedEvmAsset("USDC", "regtest", "rillswap-e2e-v1", defaults)).toEqual(asset);
    expect(() => trustedEvmAsset("USDC", "signet", null, defaults)).toThrow("No trusted");
    expect(() => trustedEvmAsset("USDC", "regtest", "other-deployment", defaults)).toThrow("No trusted");
    expect(() => trustedEvmAsset("USDT", "regtest", "rillswap-e2e-v1", defaults)).toThrow("No trusted");
    expect(() => trustedEvmAsset("USDC", "regtest", "rillswap-e2e-v1", resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest" }))).toThrow("No trusted");
  });
  test("partial, malformed, and ambiguous asset maps fail closed", () => {
    for (const map of [null, [], { DAI: asset }, { USDC: {} }, { USDC: { ...asset, token_decimals: 37 } },
      { USDC: { ...asset, htlc_version: 7 } }, { USDC: { ...asset, token_contract: "0x123" } }]) {
      expect(() => resolveSwapDefaults({ VITE_RILLSWAP_EVM_ASSETS: JSON.stringify(map) })).toThrow();
    }
    expect(() => resolveSwapDefaults({ VITE_RILLSWAP_EVM_ASSETS: "{" })).toThrow();
  });
  test("unconfigured public builds select mainnet with an encrypted relay", () => {
    expect(resolveSwapDefaults({})).toEqual({ network: "mainnet", relays: [
      "wss://relay.primal.net/", "wss://relay.snort.social/", "wss://nostr.oxtr.dev/", "wss://relay.ditto.pub/",
      "wss://nostr.azzamo.net/", "wss://relay.angor.io/",
      "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion/",
      "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion/",
    ], mempoolApi: "https://mempool.space/api", broadcastApi: "https://mempool.space/api" });
  });
  test("published sibling builds are same-site relative directories for declared networks only", () => {
    expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "signet", VITE_RILLSWAP_DEPLOYMENTS: JSON.stringify({ mainnet: "../", signet: "./" }) }).deployments)
      .toEqual({ mainnet: "../", signet: "./" });
    expect(resolveSwapDefaults({ VITE_RILLSWAP_DEPLOYMENTS: JSON.stringify({ signet: "./signet/", testnet4: "./t4-dev/" }) }).deployments)
      .toEqual({ signet: "./signet/", testnet4: "./t4-dev/" });
    for (const map of [null, [], "../", { liquid: "./liquid/" }, { signet: 1 }, { signet: "" }, { signet: "/signet/" }, { signet: "//evil.example/" },
      { signet: "https://evil.example/" }, { signet: "./signet" }, { signet: "../?a" }, { signet: "./Signet/" }, { signet: "javascript:alert(1)//" }]) {
      expect(() => resolveSwapDefaults({ VITE_RILLSWAP_DEPLOYMENTS: JSON.stringify(map) })).toThrow("VITE_RILLSWAP_DEPLOYMENTS");
    }
    expect(() => resolveSwapDefaults({ VITE_RILLSWAP_DEPLOYMENTS: "{" })).toThrow();
  });
  test("supports every declared network without hostname inference", () => {
    for (const network of NETWORK_NAMES) {
      expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network }).network).toBe(network);
    }
    expect(relaysForNetwork("regtest")).toEqual(["ws://127.0.0.1:7777/"]);
    expect(relaysForNetwork("signet").every((relay) => relay.startsWith("wss://") || isOnionRelay(relay))).toBe(true);
    expect(relaysForNetwork("testnet4")).toEqual(relaysForNetwork("mainnet"));
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
  test("the EVM RPC is read-only public configuration with a local Anvil default on regtest", () => {
    expect(resolveSwapDefaults({}).evmRpc).toBeUndefined();
    expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest" }).evmRpc).toBe("http://127.0.0.1:8545");
    expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "mainnet", VITE_RILLSWAP_EVM_RPC: "https://rpc.example/v1/" }).evmRpc).toBe("https://rpc.example/v1");
    expect(() => resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "mainnet", VITE_RILLSWAP_EVM_RPC: "http://rpc.example" })).toThrow();
  });
  test("the gas sponsor is opt-in deployment configuration pinned together with its EntryPoint and delegate", () => {
    expect(resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest" }).evmSponsor).toBeUndefined();
    const env = { VITE_RILLSWAP_NETWORK: "regtest", VITE_RILLSWAP_EVM_SPONSOR: "http://127.0.0.1:8094/", VITE_RILLSWAP_EVM_ENTRY_POINT: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
      VITE_RILLSWAP_EVM_7702_DELEGATE: "0x77021100bD87b7008E5E1989d0eB38555d0d0000" };
    expect(resolveSwapDefaults(env).evmSponsor).toEqual({ url: "http://127.0.0.1:8094", entryPoint: "0x0000000071727de22e5e9d8baf0edac6f37da032", delegate: "0x77021100bd87b7008e5e1989d0eb38555d0d0000" });
    expect(() => resolveSwapDefaults({ ...env, VITE_RILLSWAP_EVM_7702_DELEGATE: undefined })).toThrow("together");
    expect(() => resolveSwapDefaults({ ...env, VITE_RILLSWAP_EVM_ENTRY_POINT: "0x1234" })).toThrow("lowercase 0x addresses");
    expect(() => resolveSwapDefaults({ ...env, VITE_RILLSWAP_NETWORK: "mainnet" })).toThrow();
    const policy = "0B1E8F2A-3C4D-4E5F-8A9B-0C1D2E3F4A5B";
    expect(resolveSwapDefaults({ ...env, VITE_RILLSWAP_EVM_SPONSOR_POLICY: policy }).evmSponsor?.policyId).toBe(policy.toLowerCase());
    expect(() => resolveSwapDefaults({ ...env, VITE_RILLSWAP_EVM_SPONSOR_POLICY: "my-policy" })).toThrow("UUID");
    expect(() => resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest", VITE_RILLSWAP_EVM_SPONSOR_POLICY: policy })).toThrow("needs VITE_RILLSWAP_EVM_SPONSOR");
  });
  test("public builds admit any https origin but plain http only for configured endpoints", async () => {
    for (const configured of [false, true]) {
      const destination = `tmp/node-csp-${configured ? "configured" : "unset"}`;
      const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("VITE_RILLSWAP_")));
      const child = Bun.spawn([process.execPath, "node_modules/vite/bin/vite.js", "build", "--outDir", destination], {
        env: { ...env, VITE_RILLSWAP_NETWORK: "regtest", ...(configured ? { VITE_RILLSWAP_NODE_API: "http://127.0.0.1:10443/lnd" } : {}) }, stdout: "pipe", stderr: "pipe",
      });
      const [errors, status] = await Promise.all([new Response(child.stderr).text(), child.exited, new Response(child.stdout).text()]);
      expect(status).toBe(0); expect(errors).not.toContain("error");
      const html = await Bun.file(`${destination}/swap.html`).text(), csp = html.match(/content="([^"]*connect-src[^"]*)"/)![1]!;
      const sources = csp.split(";").find((part) => part.trim().startsWith("connect-src"))!.trim().split(/\s+/);
      expect(sources).toContain("https:"); expect(sources).not.toContain("http:"); expect(sources).not.toContain("*");
      expect(sources.includes("http://127.0.0.1:10443")).toBe(configured);
      for (const source of sources.filter((item) => item.startsWith("http://"))) expect(source).toMatch(/^http:\/\/(127\.0\.0\.1|localhost):[0-9]+$/);
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
  test("plain ws:// is accepted for v3 onion relays only, on every network", () => {
    const onion = "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion";
    for (const network of NETWORK_NAMES) expect(validateRelay(onion, network)).toBe(`${onion}/`);
    expect(isOnionRelay(onion)).toBe(true);
    for (const relay of ["ws://short.onion", "ws://relay.test.onion.example", `ws://user:secret@${onion.slice(5)}`, `${onion}/#x`]) {
      expect(() => validateRelay(relay, "signet")).toThrow();
    }
    expect(isOnionRelay("ws://short.onion")).toBe(false);
    expect(isOnionRelay("wss://relay.primal.net")).toBe(false);
  });
  test("relay lists are bounded, deduplicated and reject ambiguous deployment overrides", () => {
    expect(validateRelays("wss://nos.lol, wss://nos.lol/\nwss://relay.damus.io", "signet")).toHaveLength(2);
    expect(() => validateRelays("", "regtest")).toThrow();
    expect(validateRelays("wss://a.test wss://b.test wss://c.test wss://d.test wss://e.test", "signet")).toHaveLength(5);
    expect(validateRelays(Array.from({ length: MAX_RELAYS }, (_, i) => `wss://r${i}.test`).join(" "), "signet")).toHaveLength(MAX_RELAYS);
    expect(() => validateRelays(Array.from({ length: MAX_RELAYS + 1 }, (_, i) => `wss://r${i}.test`).join(" "), "signet")).toThrow();
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

describe("explorer links", () => {
  const txid = "ab".repeat(32);
  test("map an API base to the same instance's transaction page", () => {
    expect(explorerTxUrl("https://mempool.space/api", txid)).toBe(`https://mempool.space/tx/${txid}`);
    expect(explorerTxUrl("https://mempool.space/testnet4/api/", txid)).toBe(`https://mempool.space/testnet4/tx/${txid}`);
    expect(explorerTxUrl("https://mempool.example/signet/api", txid)).toBe(`https://mempool.example/signet/tx/${txid}`);
    expect(explorerTxUrl("http://127.0.0.1:8091/api", txid)).toBe(`http://127.0.0.1:8091/tx/${txid}`);
    expect(explorerTxUrl("https://esplora.example", txid)).toBe(`https://esplora.example/tx/${txid}`);
  });
  test("refuse anything but a transaction ID", () => {
    expect(() => explorerTxUrl("https://mempool.space/api", "../x")).toThrow("Invalid transaction ID");
  });
});
