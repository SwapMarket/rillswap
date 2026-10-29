import { directorySettled, expect, MAINNET_RELAYS, openSettings, test } from "./fixtures/swapPage";
import { buildCommit } from "../scripts/build-commit";

for (const prefix of ["", "repository/"]) {
  test(`both network footers link to the build commit under /${prefix}`, async ({ page }) => {
    const commit = buildCommit();
    for (const network of ["", "signet/"]) {
      await page.goto(`http://127.0.0.1:18866/${prefix}${network}`);
      const revision = page.locator("footer #swap-build-commit");
      if (!commit) { await expect(revision).toHaveCount(0); continue; }
      await expect(revision).toHaveText(commit.slice(0, 7));
      await expect(revision).toHaveAttribute("href", `https://github.com/rillswap/rillswap/commit/${commit}`);
      await expect(revision).toHaveAttribute("target", "_blank");
      await expect(revision).toHaveAttribute("rel", "noopener noreferrer");
    }
  });

  test(`swap execution code is loaded with each page under /${prefix}`, async ({ page, request }) => {
    for (const network of ["", "signet/"]) {
      await page.goto(`http://127.0.0.1:18866/${prefix}${network}`);
      const modules = await page.locator('script[type="module"][src], link[rel="modulepreload"]').evaluateAll((elements) =>
        elements.map((element) => element instanceof HTMLScriptElement ? element.src : (element as HTMLLinkElement).href));
      expect(modules.length).toBeGreaterThan(0);
      for (const url of modules) {
        const response = await request.get(url);
        expect(response.ok()).toBe(true);
        // Deferred browser code disappears on the next Pages deployment. The
        // Node-only WASM loader's external-module placeholder is never run here.
        for (const imported of (await response.text()).matchAll(/\bimport\s*\(([^)]*)\)/g)) {
          expect(imported[1], `deferred import in ${url}`).toMatch(/^["'`]\.\/__vite-browser-external-[\w-]+\.js["'`]$/);
        }
      }
    }
  });

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
    // The header picker is the only network switch; the footer repeats no deployment links.
    await expect(page.getByRole("navigation", { name: "Deployment network" })).toHaveCount(0);
    const picker = page.getByRole("combobox", { name: "Switch network" });
    await openSettings(page, "connection");
    await expect(page.locator("#swap-network")).toHaveValue("mainnet");
    await expect(page.locator("#swap-chain-api")).toHaveValue("https://mempool.space/api");
    await page.locator("#swap-settings-close").click();
    await picker.selectOption("signet");
    await expect(page).toHaveURL(`${base}signet/`);
    await directorySettled(page);
    await expect(page.locator("#swap-start")).toBeEnabled();
    await openSettings(page, "connection");
    await expect(page.locator("#swap-network")).toHaveValue("signet");
    await expect(page.locator("#swap-chain-api")).toHaveValue("https://mempool.space/signet/api");
    await expect(page.locator("#swap-broadcast-api")).toHaveValue("https://mempool.space/signet/api");
    await page.locator("#swap-settings-close").click();
    await picker.selectOption("mainnet");
    await expect(page).toHaveURL(base);
    await directorySettled(page);
    await expect(page.locator("#swap-start")).toBeEnabled();
    expect(errors).toEqual([]); expect(violations).toEqual([]);
    expect([...new Set(sockets)].sort()).toEqual([...MAINNET_RELAYS].sort());
    expect(requests.some((url) => url.includes(`${prefix}signet/assets/`))).toBe(true);
    for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18866");
  });

  test(`each deployment has its own title, description, canonical address and social card under /${prefix}`, async ({ page, request }) => {
    const base = `http://127.0.0.1:18866/${prefix}`, site = "https://rillswap.github.io/rillswap/";
    const meta = (selector: string, attribute = "content") => page.locator(selector).getAttribute(attribute);
    for (const [path, url, title] of [
      ["", site, "RillSwap: decentralized, permissionless Lightning swaps"],
      ["signet/", `${site}signet/`, "RillSwap Signet: try Lightning swaps with test coins"],
    ] as const) {
      await page.goto(`${base}${path}`);
      await expect(page).toHaveTitle(title);
      expect(await meta('meta[name="description"]')).toMatch(/permissionless|decentralized/);
      expect(await meta('link[rel="canonical"]', "href")).toBe(url);
      expect(await meta('meta[property="og:url"]')).toBe(url);
      expect(await meta('meta[property="og:title"]')).toBe(title);
      expect(await meta('meta[property="og:image"]')).toBe(`${site}social-card.png`);
      expect(await meta('meta[name="twitter:card"]')).toBe("summary_large_image");
      const data = JSON.parse((await page.locator('script[type="application/ld+json"]').textContent())!);
      expect(data).toMatchObject({ "@type": "WebApplication", name: "RillSwap", url, sameAs: ["https://github.com/rillswap/rillswap"] });
      for (const asset of ["favicon.png", "apple-touch-icon.png", "social-card.png"]) {
        expect((await request.get(`${base}${path}${asset}`)).ok()).toBe(true);
      }
      await expect(page.locator('meta[name="robots"]')).toHaveCount(0);
      await page.goto(`${base}${path}diagnostic.html`);
      expect(await meta('meta[name="robots"]')).toBe("noindex");
    }
    const sitemap = await (await request.get(`${base}sitemap.xml`)).text();
    expect(sitemap).toContain(`<loc>${site}</loc>`); expect(sitemap).toContain(`<loc>${site}signet/</loc>`);
    expect(await (await request.get(`${base}robots.txt`)).text()).toContain(`Sitemap: ${site}sitemap.xml`);
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
    await openSettings(page, "connection");
    await expect(page.locator("#swap-network")).toHaveValue("testnet4");
    await page.locator("#swap-settings-close").click();
    await picker.selectOption("signet"); // the build's own network: in place, no reload
    await expect(page).toHaveURL(`${base}signet/`);
    await openSettings(page, "connection");
    await expect(page.locator("#swap-network")).toHaveValue("signet");
    expect(errors).toEqual([]);
  });
}
