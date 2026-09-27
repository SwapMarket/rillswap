import { expect, test } from "@playwright/test";

const SWAP = "http://127.0.0.1:18765/swap.html";

test("the swap page loads locally, offers no mainnet, and connects to nothing before start", async ({ page }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(SWAP);
  await expect(page.getByRole("heading", { name: "Pay a Lightning invoice with on-chain BTC" })).toBeVisible();
  const options = await page.locator("#swap-network option").allTextContents();
  expect(options).toEqual(["signet", "testnet4", "regtest"]);
  const csp = await page.locator("meta[http-equiv='Content-Security-Policy']").getAttribute("content");
  expect(csp).toContain("connect-src wss: ws://127.0.0.1:* ws://localhost:*;");
  expect(csp).toContain("script-src 'self';");
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
  expect(sockets).toEqual([]);
});

test("invalid input is refused before any relay connection", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(SWAP);
  await page.locator("#swap-relay").fill("wss://relay.invalid");
  await page.locator("#swap-refund").fill("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  await page.locator("#swap-tip").fill("1000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-log")).toContainText("refused: Address refused: not for this network");
  await page.locator("#swap-refund").fill("tb1qw508d6qejxtdg4y5r3zarvary0c5xdrpezj");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-log")).toContainText("refused:");
  expect(sockets).toEqual([]);
});

test("the preview page links to the swap page", async ({ page }) => {
  await page.goto("http://127.0.0.1:18765/");
  await page.getByRole("link", { name: /Experimental BTC to Lightning swap client/ }).click();
  await expect(page).toHaveURL(SWAP);
});
