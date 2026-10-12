import { expect, test } from "@playwright/test";

test("merchant invoice fragments prefill locally without connecting and are removed from the address bar", async ({ page }) => {
  const requests: string[] = [], sockets: string[] = [];
  page.on("request", (request) => requests.push(request.url())); page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto("http://127.0.0.1:18765/swap.html#invoice=ln-public-test-handoff");
  await expect(page.locator("#swap-invoice")).toHaveValue("ln-public-test-handoff");
  expect(new URL(page.url()).hash).toBe(""); expect(sockets).toEqual([]);
  for (const request of requests) { expect(request).not.toContain("ln-public-test-handoff"); expect(new URL(request).host).toBe("127.0.0.1:18765"); }
  await page.goto("about:blank");
  await page.goto("http://127.0.0.1:18765/swap.html#invoice=" + "x".repeat(4097));
  await expect(page.locator("#swap-invoice")).toHaveValue(""); expect(new URL(page.url()).hash).toBe("");
});

test("address and amount fragments prefill a Lightning to Bitcoin swap locally and are removed from the address bar", async ({ page }) => {
  const requests: string[] = [], sockets: string[] = [];
  page.on("request", (request) => requests.push(request.url())); page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto("http://127.0.0.1:18765/swap.html#address=bcrt1qtest-handoff&amount=50000");
  await expect(page.locator("#swap-from")).toHaveValue("ln"); await expect(page.locator("#swap-to")).toHaveValue("btc");
  await expect(page.locator("#swap-receive-address")).toHaveValue("bcrt1qtest-handoff");
  await expect(page.locator("#swap-receive-amount")).toHaveValue("50000");
  await expect(page.locator("#swap-invoice")).toBeHidden();
  expect(new URL(page.url()).hash).toBe(""); expect(sockets).toEqual([]);
  for (const request of requests) { expect(request).not.toContain("test-handoff"); expect(new URL(request).host).toBe("127.0.0.1:18765"); }
  await page.goto("about:blank");
  await page.goto("http://127.0.0.1:18765/swap.html#amount=12.5&address=" + "x".repeat(129));
  await expect(page.locator("#swap-from")).toHaveValue("ln");
  await expect(page.locator("#swap-receive-amount")).toHaveValue(""); await expect(page.locator("#swap-receive-address")).toHaveValue("");
  expect(new URL(page.url()).hash).toBe("");
});
import { testInvoice } from "../../rill-payments/tests/helpers";
import { scriptAddress } from "../src/swap/address";

const SWAP = "http://127.0.0.1:18765/swap.html";

test("direction flips between Bitcoin and Lightning, and stablecoins pair with Lightning only", async ({ page }) => {
  const requests: string[] = [], sockets: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(SWAP);
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  await expect(page.locator("#swap-from")).toHaveValue("btc");
  await expect(page.locator("#swap-to")).toHaveValue("ln");
  await expect(page.locator("#swap-invoice")).toBeVisible();
  await expect(page.locator("#swap-receive-address")).not.toBeVisible();
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();

  await page.getByRole("button", { name: "Switch direction" }).click();
  await expect(page.locator("#swap-from")).toHaveValue("ln");
  await expect(page.locator("#swap-to")).toHaveValue("btc");
  await expect(page.getByRole("heading", { name: "Lightning in. Bitcoin out." })).toBeVisible();
  await expect(page.locator("#swap-invoice")).not.toBeVisible();
  await expect(page.locator("#swap-wallet-setup")).toBeVisible(); // the recovery key serves both directions
  await expect(page.locator("#swap-forward-overrides")).not.toBeVisible();
  await expect(page.locator("#swap-receive-address")).toBeVisible();
  await expect(page.locator("#swap-receive-amount")).toBeVisible();
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();
  // Invalid reverse input is refused locally, before any connection.
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("Amount to receive must be a whole number");

  // Choosing the asset already on the other side swaps them.
  await page.locator("#swap-to").selectOption("ln");
  await expect(page.locator("#swap-from")).toHaveValue("btc");
  await expect(page.getByRole("heading", { name: "Bitcoin in. Lightning out." })).toBeVisible();

  // Stablecoins pair with Lightning only: sending them is quotable, receiving them is not yet.
  await page.locator("#swap-to").selectOption("usdt");
  await expect(page.locator("#swap-to option[value=usdt]")).toHaveText("USDT");
  await expect(page.locator("#swap-pair-note")).toHaveText("Bitcoin to Tether swaps are not offered.");
  await expect(page.locator("#swap-start")).toHaveText("Pair unavailable");
  await expect(page.locator("#swap-start")).toBeDisabled();
  await page.locator("#swap-from").selectOption("usdc");
  await page.locator("#swap-to").selectOption("ln");
  await expect(page.getByRole("heading", { name: "USD Coin in. Lightning out." })).toBeVisible();
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await expect(page.locator("#swap-invoice")).toBeVisible();
  await expect(page.locator("#swap-forward-overrides")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();
  await page.locator("#swap-start").click(); // an empty invoice is refused locally, before any connection
  await expect(page.locator("#swap-status")).toContainText("Invoice refused");
  await page.getByRole("button", { name: "Switch direction" }).click();
  await expect(page.locator("#swap-pair-note")).toHaveText("Lightning to USD Coin quotes are coming soon.");
  await expect(page.locator("#swap-start")).toBeDisabled();

  await page.locator("#swap-from").selectOption("btc");
  await page.locator("#swap-to").selectOption("ln");
  await expect(page.locator("#swap-start")).toBeEnabled();
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
  expect(sockets).toEqual([]);
});

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
  await expect(page.locator("#swap-status")).toContainText("No provider announced this swap direction");
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
  await expect(page.locator("#swap-status")).toContainText("No provider announced this swap direction");
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

test("the provider directory lists announced limits and fees on explicit load and chooses the pinned provider", async ({ page }) => {
  const { schnorr } = await import("@noble/curves/secp256k1.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const { default: canonicalize } = await import("canonicalize");
  const { finalizeEvent, getPublicKey } = await import("nostr-tools");
  const { default: application } = await import("../unit/fixtures/manual-advertisement-regtest-v1.json", { with: { type: "json" } });
  const { default: vector } = await import("../unit/fixtures/nostr-announcement-regtest-v1.json", { with: { type: "json" } });
  const secret = new Uint8Array(32); secret[31] = 2;
  const wrapper = structuredClone(application);
  wrapper.advertisement.provider_identity_xonly_key = getPublicKey(secret);
  wrapper.advertisement.expires_at = Math.floor(Date.now() / 1000) + 3600;
  wrapper.advertisement.created_at = Math.floor(Date.now() / 1000) - 60;
  const tag = sha256(new TextEncoder().encode("RillSwap/advertisement/v1"));
  const content = new TextEncoder().encode(canonicalize(wrapper.advertisement)!);
  const digest = new Uint8Array(64 + content.length); digest.set(tag); digest.set(tag, 32); digest.set(content, 64);
  wrapper.signature = Buffer.from(schnorr.sign(sha256(digest), secret)).toString("hex");
  const event = finalizeEvent({ kind: vector.kind, created_at: wrapper.advertisement.created_at, tags: structuredClone(vector.tags), content: canonicalize(wrapper)! }, secret);
  let requests = 0;
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "REQ") { requests++; socket.send(JSON.stringify(["EVENT", frame[1], event])); socket.send(JSON.stringify(["EOSE", frame[1]])); }
    });
  });
  await page.goto(SWAP);
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  await expect(page.locator("#swap-provider-choice")).toHaveText("Provider: automatic, lowest verified price");
  await page.locator("#swap-providers-toggle").click();
  await expect(page.locator("#swap-providers")).toBeVisible();
  await expect(page.locator("#swap-providers-intro")).toContainText("regtest");
  expect(requests).toBe(0); // opening the directory connects nowhere
  await expect(page.locator(".swap-provider")).toHaveCount(1); // automatic only
  await page.locator("#swap-providers-load").click();
  await expect(page.locator("#swap-providers-status")).toHaveText("1 announced provider.");
  expect(requests).toBe(1);
  const entry = page.locator(".swap-provider").nth(1);
  await expect(entry).toContainText("Directions: Bitcoin to Lightning, Lightning to Bitcoin");
  await expect(entry).toContainText("Limits: 1,000 to 100,000 sat");
  await expect(entry).toContainText("Fee: 50 sat + 0.10% (about 150 sat on a 100,000 sat swap)");
  await expect(entry).toContainText(`Identity: ${wrapper.advertisement.provider_identity_xonly_key}`);
  await entry.locator("input[type=radio]").check();
  await page.locator("#swap-providers-close").click();
  await expect(page.locator("#swap-provider-choice")).toHaveText(`Provider: ${wrapper.advertisement.provider_identity_xonly_key.slice(0, 12)}… (chosen by you)`);
  await page.locator("#swap-settings-toggle").click();
  await expect(page.locator("#swap-provider")).toHaveValue(wrapper.advertisement.provider_identity_xonly_key);
  await page.locator("#swap-provider").fill("");
  await page.locator("#swap-settings-close").click();
  await expect(page.locator("#swap-provider-choice")).toHaveText("Provider: automatic, lowest verified price");
});
