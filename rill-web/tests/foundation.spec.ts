import { expect, test } from "@playwright/test";

const ROOT = "http://127.0.0.1:18765/";

test("local assets load at root and repository subpath without external requests", async ({ page }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  for (const path of ["", "repository/"]) {
    await page.goto(`${ROOT}${path}`);
    await expect(page.getByRole("heading", { name: "RillSwap" })).toBeVisible();
    await expect(page.getByText("Do not enter secrets or send funds.", { exact: false })).toBeVisible();
    const select = page.locator("#chain-mode");
    await select.selectOption("remote-chain-source");
    await expect(page.getByText("No connection is made.", { exact: false })).toBeVisible();
  }
  expect(requests.length).toBeGreaterThan(2);
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
  const paths = requests.map((url) => new URL(url).pathname);
  expect(paths.some((path) => path.startsWith("/repository/assets/"))).toBe(true);
  expect(paths.some((path) => path.startsWith("/assets/"))).toBe(true);
});

test("untrusted provider text is inert even when it resembles HTML", async ({ page }) => {
  await page.goto(ROOT);
  const malicious = `<img src=x onerror="window.__injected = true"><script>alert(1)</script>`;
  await page.locator("#provider-description").fill(malicious);
  await expect(page.locator("#provider-text")).toHaveText(malicious);
  expect(await page.locator("#provider-text img, #provider-text script").count()).toBe(0);
  expect(await page.evaluate(() => "__injected" in window)).toBe(false);
});

test("startup and reload never probe storage, request persistence or contact a service", async ({ page }) => {
  await page.addInitScript(() => {
    const counters = { opened: 0, persisted: 0 };
    Object.defineProperty(window, "__rillProbeCounters", { value: counters });
    const originalOpen = indexedDB.open.bind(indexedDB);
    indexedDB.open = ((...args: Parameters<IDBFactory["open"]>) => {
      counters.opened += 1;
      return originalOpen(...args);
    }) as IDBFactory["open"];
    const originalPersist = navigator.storage.persist.bind(navigator.storage);
    navigator.storage.persist = async () => {
      counters.persisted += 1;
      return originalPersist();
    };
  });
  await page.goto(ROOT);
  await page.reload();
  const counts = await page.evaluate(() => (window as unknown as {
    __rillProbeCounters: { opened: number; persisted: number };
  }).__rillProbeCounters);
  expect(counts).toEqual({ opened: 0, persisted: 0 });
  await expect(page.locator("#storage-status")).toContainText("Storage not tested");
});

test("explicit diagnostic verifies synthetic round-trip, reports denied persistence, cleans up", async ({ page }) => {
  await page.addInitScript(() => {
    navigator.storage.persist = async () => false;
  });
  await page.goto(ROOT);
  await page.getByRole("button", { name: "Test browser storage" }).click();
  await expect(page.locator("#storage-status")).toContainText("Storage round-trip succeeded.");
  await expect(page.locator("#storage-status")).toContainText("Persistence granted: no.");
  await expect(page.locator("#storage-status")).toContainText("Cleanup: complete.");
  const orphaned = await page.evaluate(async () =>
    (await indexedDB.databases()).filter((item) => item.name?.startsWith("rillswap-diagnostic-")).length,
  );
  expect(orphaned).toBe(0);
});

test("blocked or quota-limited storage fails without a commitment path", async ({ page }) => {
  await page.addInitScript(() => {
    indexedDB.open = () => { throw new DOMException("blocked", "QuotaExceededError"); };
  });
  await page.goto(ROOT);
  await page.getByRole("button", { name: "Test browser storage" }).click();
  await expect(page.locator("#storage-status")).toContainText("Storage round-trip failed.");
  expect(await page.getByRole("button").allTextContents()).toEqual([
    "Test browser storage",
    "Verify manual advertisement",
  ]);
});

test("quota failure during the write aborts the diagnostic and cleans up", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.addInitScript(() => {
    IDBObjectStore.prototype.put = () => { throw new DOMException("quota", "QuotaExceededError"); };
  });
  await page.goto(ROOT);
  await page.getByRole("button", { name: "Test browser storage" }).click();
  await expect(page.locator("#storage-status")).toContainText("Storage round-trip failed.");
  expect(pageErrors).toEqual([]);
  const orphaned = await page.evaluate(async () =>
    (await indexedDB.databases()).filter((item) => item.name?.startsWith("rillswap-diagnostic-")).length,
  );
  expect(orphaned).toBe(0);
});

test("failed diagnostic with failed cleanup discloses both uncertainties", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.addInitScript(() => {
    IDBObjectStore.prototype.put = () => { throw new DOMException("quota", "QuotaExceededError"); };
    indexedDB.deleteDatabase = () => { throw new DOMException("denied", "UnknownError"); };
  });
  await page.goto(ROOT);
  await page.getByRole("button", { name: "Test browser storage" }).click();
  await expect(page.locator("#storage-status")).toContainText("Storage round-trip failed.");
  await expect(page.locator("#storage-status")).toContainText("Diagnostic cleanup: unconfirmed.");
  expect(pageErrors).toEqual([]);
});

test("cleanup uncertainty is disclosed, never called durable storage", async ({ page }) => {
  await page.addInitScript(() => {
    navigator.storage.persist = async () => false;
    indexedDB.deleteDatabase = () => { throw new DOMException("interrupted", "UnknownError"); };
  });
  await page.goto(ROOT);
  await page.getByRole("button", { name: "Test browser storage" }).click();
  await expect(page.locator("#storage-status")).toContainText("Cleanup: unconfirmed.");
  await expect(page.locator("#storage-status")).toContainText("does not guarantee survival");
});
