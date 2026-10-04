import { expect, type Page, test } from "@playwright/test";

const PAGE = "http://127.0.0.1:18765/test-only/journal.html";
const RECORD = { contract_hash: "11".repeat(32), cooperation_id: "22".repeat(32), signature_hash: "33".repeat(32), created_at: 1 };

async function open(page: Page): Promise<void> {
  await page.goto(PAGE);
  await page.waitForFunction(() => (window as unknown as { journalReady?: boolean }).journalReady === true);
}

/** Reserve `key` and report whether the body ran, or the refusal message. */
function reserve(page: Page, key: string): Promise<string> {
  return page.evaluate(async ({ key, record }) => {
    const w = window as unknown as { reserveCooperation: (k: string, r: unknown, b: () => Promise<string>) => Promise<string> };
    try {
      return await w.reserveCooperation(key, record, async () => "signed");
    } catch (error) {
      return `refused: ${(error as Error).message}`;
    }
  }, { key, record: RECORD });
}

test("an existing record refuses whatever its age or shape, and is never pruned", async ({ page }) => {
  await open(page);
  // An ancient, malformed record written by some older page version.
  await page.evaluate(() => new Promise<void>((resolve, reject) => {
    const opening = indexedDB.open("rillswap-cooperation", 1);
    opening.onupgradeneeded = () => opening.result.createObjectStore("reservations");
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
      const tx = opening.result.transaction("reservations", "readwrite");
      tx.objectStore("reservations").add({ junk: true, created_at: 0 }, "ancient");
      tx.oncomplete = () => { opening.result.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }));
  expect(await reserve(page, "ancient")).toMatch(/^refused: /);
  expect(await reserve(page, "fresh")).toBe("signed");
  await page.reload();
  await open(page);
  expect(await reserve(page, "fresh")).toMatch(/^refused: /);
  expect(await reserve(page, "ancient")).toMatch(/^refused: /);
});

test("another tab cannot reserve while one holds the lock, nor after it released", async ({ context }) => {
  const first = await context.newPage();
  const second = await context.newPage();
  await open(first);
  await open(second);
  const held = first.evaluate(async (record) => {
    const w = window as unknown as {
      reserveCooperation: (k: string, r: unknown, b: () => Promise<string>) => Promise<string>;
      release?: () => void;
    };
    return w.reserveCooperation("shared", record, () => new Promise<string>((resolve) => {
      w.release = () => resolve("signed");
    }));
  }, RECORD);
  await first.waitForFunction(() => typeof (window as unknown as { release?: unknown }).release === "function");
  expect(await reserve(second, "shared")).toBe("refused: another tab holds this cooperation");
  await first.evaluate(() => (window as unknown as { release: () => void }).release());
  expect(await held).toBe("signed");
  expect(await reserve(second, "shared")).toMatch(/^refused: /);
});

test("a page restored from the back/forward cache never signs", async ({ page }) => {
  await open(page);
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
  expect(await reserve(page, "after-restore")).toBe("refused: page was restored; cooperation disabled");
});
