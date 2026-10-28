import { test, expect } from "@playwright/test";
import { assertDisposableStack, command, compose, composeEnabled, shopURL, webURL } from "./stack";

test("whole Compose stack is ready with real chains, funded channels and all four makers", async ({ page, request }) => {
  test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
  assertDisposableStack();
  const services = compose("config", "--services").split("\n");
  await expect(() => {
    const containers = compose("ps", "--all", "--format", "json").split("\n").filter(Boolean).map((line) => JSON.parse(line));
    expect(containers.map((value) => value.Service).sort()).toEqual([...services].sort());
    for (const container of containers) {
      if (container.Service === "bootstrap") {
        expect(container.State).toBe("exited"); expect(container.ExitCode).toBe(0);
      } else {
        expect(container.State, container.Service).toBe("running");
        if (container.Health) expect(container.Health, container.Service).toBe("healthy");
      }
    }
  }).toPass({ timeout: 120000 });

  expect(JSON.parse(command("bitcoin-cli", "getblockchaininfo")).chain).toBe("regtest");
  const evm = await request.post(`http://127.0.0.1:${process.env.RILL_DEV_ANVIL_PORT ?? "8545"}`, {
    data: { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] },
  });
  expect(evm.ok()).toBe(true); expect((await evm.json()).result).toBe("0x7a69");
  const monero = JSON.parse(compose("exec", "-T", "tools", "python", "-c",
    "import sys,json;sys.path.insert(0,'/src/dev');from devtool import MoneroDaemon;print(json.dumps(MoneroDaemon()('get_info')))"));
  expect(monero.nettype).toBe("fakechain"); expect(monero.height).toBeGreaterThanOrEqual(130);
  // Running containers can still be catching up with the blocks mined at bootstrap.
  await expect(() => {
    for (const node of ["maker", "user", "merchant"]) {
      const info = JSON.parse(command("lncli", node, "getinfo"));
      expect(info.synced_to_chain, node).toBe(true); expect(info.num_active_channels, node).toBeGreaterThan(0);
    }
  }).toPass({ timeout: 120000 });
  const balances = JSON.parse(command("info", "--json")).balances;
  expect(balances["core:user"].trusted_btc).toBeGreaterThan(0);
  expect(balances["monero:buyer"].unlocked_xmr).toBeGreaterThan(0);

  await expect(async () => {
    const response = await request.get(`${shopURL()}/api/catalog`);
    expect(response.ok()).toBe(true);
    const catalog = await response.json();
    const methods = catalog.products.find((product: { id: string }) => product.id === "stickers").methods;
    for (const rail of ["lightning", "btc-swap", "fusdc", "fusdt", "monero"]) {
      expect(methods.find((method: { id: string }) => method.id === rail)?.available, rail).toBe(true);
    }
  }).toPass({ timeout: 120000 });
  const tip = await request.get(`http://127.0.0.1:${process.env.RILL_DEV_CHAIN_PORT ?? "8091"}/api/blocks/tip/height`);
  expect(tip.ok()).toBe(true); expect(Number(await tip.text())).toBeGreaterThanOrEqual(150);

  await expect(async () => { await page.goto(webURL()); await expect(page.locator("#swap-start")).toBeVisible(); }).toPass({ timeout: 120000 });
  const info = JSON.parse(compose("exec", "-T", "tools", "cat", "/state/info.json"));
  await expect(async () => {
    const pubkeys = await page.evaluate((url) => new Promise<string[]>((resolve, reject) => {
      const relay = new WebSocket(url), keys = new Set<string>();
      const timer = setTimeout(() => { relay.close(); reject(new Error("Relay announcement query timed out")); }, 10000);
      relay.onerror = () => { clearTimeout(timer); relay.close(); reject(new Error("Relay connection failed")); };
      relay.onopen = () => relay.send(JSON.stringify(["REQ", "ci-readiness", { kinds: [39417] }]));
      relay.onmessage = ({ data }) => {
        const event = JSON.parse(String(data));
        if (event[0] === "EVENT") keys.add(event[2].pubkey);
        if (event[0] === "EOSE") { clearTimeout(timer); relay.close(); resolve([...keys]); }
      };
    }), `ws://127.0.0.1:${process.env.RILL_DEV_RELAY_PORT ?? "7777"}`);
    for (const key of Object.values(info.makers)) expect(pubkeys).toContain(key);
  }).toPass({ timeout: 60000 });
});
