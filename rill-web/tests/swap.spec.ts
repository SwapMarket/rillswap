import { expect, test } from "@playwright/test";

const SWAP = "http://127.0.0.1:18765/swap.html";

test("the swap page defaults to blocked mainnet and connects to nothing before start", async ({ page }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(SWAP);
  await expect(page.getByRole("heading", { name: "Bitcoin in. Lightning out." })).toBeVisible();
  const options = await page.locator("#swap-network option").allTextContents();
  expect(options).toEqual(["mainnet", "signet", "testnet4", "regtest"]);
  await expect(page.locator("#swap-start")).toBeDisabled();
  await expect(page.locator("#swap-network-badge")).toContainText("Mainnet");
  await expect(page.locator("#swap-success-fee")).not.toBeVisible();
  await expect(page.locator("#swap-provider")).not.toBeVisible();
  await expect(page.locator("#swap-log")).not.toBeVisible();
  await page.locator("#swap-wallet-setup summary").click();
  await expect(page.locator("#swap-prerequisites")).toContainText("PSBT");
  await expect(page.getByText("age-keygen -o rillswap-recovery.key", { exact: false })).toBeVisible();
  const csp = await page.locator("meta[http-equiv='Content-Security-Policy']").getAttribute("content");
  expect(csp).toContain("connect-src 'self' wss: ws://127.0.0.1:* ws://localhost:*;");
  expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval';");
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
  expect(sockets).toEqual([]);
});

test("the CSP admits the same-origin MuSig2 WASM and the cooperation journal APIs", async ({ page }) => {
  await page.goto(SWAP);
  const result = await page.evaluate(async () => {
    const listing = await (await fetch("assets/")).text();
    const name = /rill_crypto_wasm-[\w-]+\.wasm/.exec(listing)?.[0];
    if (!name) return "wasm asset missing";
    const module = await WebAssembly.compile(await (await fetch(`assets/${name}`)).arrayBuffer());
    if (WebAssembly.Module.exports(module).length < 10) return "wasm exports missing"; // names are minified
    if (!navigator.locks) return "web locks missing";
    let blocked = "no";
    try {
      await fetch("https://example.invalid/");
    } catch {
      blocked = "yes";
    }
    return `ok ${blocked}`;
  });
  expect(result).toBe("ok yes");
});

test("invalid input is refused before any relay connection", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(SWAP);
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("signet");
  await page.locator("#swap-relay").fill("wss://relay.invalid");
  await page.locator("#swap-settings-close").click();
  await page.locator("#swap-wallet-setup summary").click();
  await page.locator("#swap-refund").fill("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  await page.locator("#swap-tip").fill("1000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-log")).toContainText("refused: Address refused: not for this network");
  await page.locator("#swap-refund").fill("tb1qw508d6qejxtdg4y5r3zarvary0c5xdrpezj");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-log")).toContainText("refused:");
  expect(sockets).toEqual([]);
});

test("mainnet programmatic submission is refused before opening a relay", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(SWAP);
  await page.locator("#swap-form").evaluate((form) => form.dispatchEvent(new Event("submit", { cancelable: true })));
  await expect(page.locator("#swap-status")).toContainText("Mainnet swaps are blocked");
  expect(sockets).toEqual([]);
});

test("settings are keyboard accessible and switching networks resets local relays", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(SWAP);
  await page.locator("#swap-settings-toggle").focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.locator("#swap-network").selectOption("regtest");
  await expect(page.locator("#swap-relay")).toHaveValue("ws://127.0.0.1:7777/");
  await page.locator("#swap-network").selectOption("signet");
  await expect(page.locator("#swap-relay")).toHaveValue("wss://relay.damus.io/");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();
  expect(sockets).toEqual([]);
});

test("the minimal swap card fits a mobile viewport", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(SWAP);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await expect(page.locator("#swap-invoice")).toBeVisible();
  await expect(page.locator("#swap-status")).toBeVisible();
});

test("the preview page links to the swap page", async ({ page }) => {
  await page.goto("http://127.0.0.1:18765/");
  await page.getByRole("link", { name: /Experimental BTC to Lightning swap client/ }).click();
  await expect(page).toHaveURL(SWAP);
});

test("the swap page installs no service worker, so no release replaces it mid-swap (W11)", async ({ page }) => {
  await page.goto(SWAP);
  await expect(page.locator("#swap-start")).toBeVisible();
  const registrations = await page.evaluate(async () =>
    "serviceWorker" in navigator ? (await navigator.serviceWorker.getRegistrations()).length : 0);
  expect(registrations).toBe(0);
  const scripts = await page.locator("script").evaluateAll((nodes) =>
    nodes.map((node) => (node as HTMLScriptElement).src));
  for (const src of scripts) expect(new URL(src).host).toBe("127.0.0.1:18765");
});
