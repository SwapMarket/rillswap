import { expect, test } from "@playwright/test";
import { testInvoice } from "../../rill-payments/tests/helpers";
import { scriptAddress } from "../src/swap/address";

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
  await expect(page.locator("#swap-chain-disclosure")).not.toBeVisible();
  await expect(page.locator("#swap-chain-consent")).toHaveCount(0);
  await page.locator("#swap-privacy summary").click();
  await expect(page.locator("#swap-chain-disclosure")).toContainText("https://mempool.space/api");
  await page.locator("#swap-privacy summary").click();
  await page.locator("#swap-wallet-setup summary").click();
  await expect(page.locator("#swap-prerequisites")).toContainText("PSBT");
  await expect(page.locator("#swap-wallet-status")).toContainText("New browser recovery key created");
  await expect(page.getByRole("link", { name: "Download rillswap-recovery-key.json" })).toBeVisible();
  await expect(page.locator("#swap-refund")).toHaveValue("");
  await expect(page.locator("#swap-tip")).toHaveValue("");
  await expect(page.locator("#swap-age")).toHaveValue("");
  const csp = await page.locator("meta[http-equiv='Content-Security-Policy']").getAttribute("content");
  expect(csp).toContain("connect-src 'self' wss: ws://127.0.0.1:* ws://localhost:* https://mempool.space https://blockstream.info");
  expect(csp).not.toMatch(/\shttps:(?:\s|;)/);
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
  await expect(page.locator("#swap-chain-api")).toHaveValue("http://127.0.0.1:8091/api");
  await page.locator("#swap-network").selectOption("signet");
  await expect(page.locator("#swap-relay")).toHaveValue("wss://relay.damus.io/\nwss://nos.lol/\nwss://relay.primal.net/");
  await expect(page.locator("#swap-chain-api")).toHaveValue("https://mempool.space/signet/api");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();
  await page.locator("#swap-privacy summary").click();
  await expect(page.locator("#swap-chain-disclosure")).toContainText("https://mempool.space/signet/api");
  expect(sockets).toEqual([]);
});

test("the minimal swap card fits a mobile viewport", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(SWAP);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await expect(page.locator("#swap-invoice")).toBeVisible();
  await expect(page.locator("#swap-status")).toBeVisible();
});

test("automatic discovery uses every configured relay and restores inputs when no provider is found", async ({ page }) => {
  const sockets: string[] = [];
  await page.routeWebSocket(/ws:\/\/127\.0\.0\.1:777[78]\//, (socket) => {
    sockets.push(socket.url());
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "REQ") socket.send(JSON.stringify(["EOSE", frame[1]]));
    });
  });
  await page.goto(SWAP);
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-relay").fill("ws://127.0.0.1:7777\nws://127.0.0.1:7778");
  await page.locator("#swap-settings-close").click();
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("browser_discovery", "1000000", now, now + 7200));
  await page.locator("#swap-wallet-setup summary").click();
  await page.locator("#swap-refund").fill(scriptAddress("0014" + "11".repeat(20), "regtest"));
  await page.locator("#swap-tip").fill("1000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("No eligible provider found");
  await expect(page.locator("#swap-start")).toBeEnabled();
  expect(sockets.sort()).toEqual(["ws://127.0.0.1:7777/", "ws://127.0.0.1:7778/"]);
});

test("canceling discovery closes its relay and a new search cannot show stale results", async ({ page }) => {
  let requests = 0, closed = 0;
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onClose(() => { closed++; });
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "REQ") {
        requests++;
        if (requests > 1) socket.send(JSON.stringify(["EOSE", frame[1]]));
      }
    });
  });
  await page.goto(SWAP);
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("browser_cancel", "1000000", now, now + 7200));
  await page.locator("#swap-wallet-setup summary").click();
  await page.locator("#swap-refund").fill(scriptAddress("0014" + "11".repeat(20), "regtest"));
  await page.locator("#swap-tip").fill("1000");
  await page.locator("#swap-start").click();
  await expect.poll(() => requests).toBe(1);
  await page.locator("#swap-edit").click();
  await expect.poll(() => closed).toBe(1);
  await expect(page.locator("#swap-status")).toContainText("Ready for a new quote");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("No eligible provider found");
  await expect(page.locator("#swap-start")).toBeEnabled();
  expect(requests).toBe(2);
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
