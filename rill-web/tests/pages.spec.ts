import { directorySettled, expect, MAINNET_RELAYS, test } from "./fixtures/swapPage";

for (const prefix of ["", "repository/"]) {
  test(`assembled mainnet and signet have independent defaults and relative navigation under /${prefix}`, async ({ page, relaySockets: sockets }) => {
    const requests: string[] = [], errors: string[] = [];
    page.on("request", (request) => requests.push(request.url()));
    page.on("pageerror", (error) => errors.push(error.message));
    const base = `http://127.0.0.1:18866/${prefix}`;
    await page.goto(base);
    await directorySettled(page);
    await expect(page.locator("#swap-start")).toBeEnabled();
    await page.locator("#swap-settings-toggle").click();
    await expect(page.locator("#swap-network")).toHaveValue("mainnet");
    await expect(page.locator("#swap-chain-api")).toHaveValue("https://mempool.space/api");
    await page.locator("#swap-settings-close").click();
    await page.getByRole("navigation", { name: "Deployment network" }).getByRole("link", { name: "Signet", exact: true }).click();
    await expect(page).toHaveURL(`${base}signet/`);
    await directorySettled(page);
    await expect(page.locator("#swap-start")).toBeEnabled();
    await page.locator("#swap-settings-toggle").click();
    await expect(page.locator("#swap-network")).toHaveValue("signet");
    await expect(page.locator("#swap-chain-api")).toHaveValue("https://mempool.space/signet/api");
    await expect(page.locator("#swap-broadcast-api")).toHaveValue("https://mempool.space/signet/api");
    await page.locator("#swap-settings-close").click();
    await page.getByRole("navigation", { name: "Deployment network" }).getByRole("link", { name: "Mainnet", exact: true }).click();
    await expect(page).toHaveURL(base);
    await directorySettled(page);
    await expect(page.locator("#swap-start")).toBeEnabled();
    expect(errors).toEqual([]); expect([...new Set(sockets)].sort()).toEqual([...MAINNET_RELAYS].sort());
    expect(requests.some((url) => url.includes(`${prefix}signet/assets/`))).toBe(true);
    for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18866");
  });
}
