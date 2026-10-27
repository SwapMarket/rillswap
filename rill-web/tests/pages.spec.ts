import { directorySettled, expect, MAINNET_RELAYS, test } from "./fixtures/swapPage";

for (const prefix of ["", "repository/"]) {
  test(`assembled mainnet and signet have independent defaults and relative navigation under /${prefix}`, async ({ page, relaySockets: sockets }) => {
    const requests: string[] = [], errors: string[] = [], violations: string[] = [];
    page.on("request", (request) => requests.push(request.url()));
    page.on("pageerror", (error) => errors.push(error.message));
    // The page's CSP silently drops what it blocks; surface every violation.
    await page.exposeFunction("reportCspViolation", (entry: string) => violations.push(entry));
    await page.addInitScript(() => document.addEventListener("securitypolicyviolation", (event) =>
      (window as unknown as { reportCspViolation: (entry: string) => void }).reportCspViolation(`${event.violatedDirective} ${event.blockedURI}`)));
    const base = `http://127.0.0.1:18866/${prefix}`;
    await page.goto(base);
    await directorySettled(page);
    await expect(page.locator("#swap-start")).toBeEnabled();
    const deployments = page.getByRole("navigation", { name: "Deployment network" });
    await expect(deployments).toHaveCSS("text-align", "center");
    await expect(deployments).toHaveCSS("padding-top", "16px");
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
    expect(errors).toEqual([]); expect(violations).toEqual([]);
    expect([...new Set(sockets)].sort()).toEqual([...MAINNET_RELAYS].sort());
    expect(requests.some((url) => url.includes(`${prefix}signet/assets/`))).toBe(true);
    for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18866");
  });

  test(`the header network indicator opens the published sibling build under /${prefix}`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const base = `http://127.0.0.1:18866/${prefix}`;
    await page.goto(`${base}signet/`);
    await directorySettled(page);
    const picker = page.getByRole("combobox", { name: "Switch network" });
    await expect(picker).toHaveValue("signet");
    await picker.selectOption("mainnet");
    await expect(page).toHaveURL(base);
    await directorySettled(page);
    await expect(picker).toHaveValue("mainnet");
    await picker.selectOption("signet");
    await expect(page).toHaveURL(`${base}signet/`);
    await directorySettled(page);
    await expect(picker).toHaveValue("signet");
    // A network without a published build still reconfigures in place.
    await picker.selectOption("testnet4");
    await expect(page).toHaveURL(`${base}signet/`);
    await page.locator("#swap-settings-toggle").click();
    await expect(page.locator("#swap-network")).toHaveValue("testnet4");
    await page.locator("#swap-settings-close").click();
    await picker.selectOption("signet"); // the build's own network: in place, no reload
    await expect(page).toHaveURL(`${base}signet/`);
    await page.locator("#swap-settings-toggle").click();
    await expect(page.locator("#swap-network")).toHaveValue("signet");
    expect(errors).toEqual([]);
  });
}
