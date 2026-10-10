import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "tests", testMatch: "pages.spec.ts", workers: 1,
  use: { ...devices["Desktop Chrome"], headless: true },
  webServer: {
    command: "bun run build:pages && bun scripts/prepare-pages-preview.ts && python3 -m http.server 18866 --bind 127.0.0.1 --directory tmp/pages-preview",
    url: "http://127.0.0.1:18866/", reuseExistingServer: false, timeout: 60000,
  },
});
