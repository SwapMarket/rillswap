import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "tests",
  testIgnore: "pages.spec.ts",
  fullyParallel: false,
  workers: 1,
  use: {
    ...devices["Desktop Chrome"],
    headless: true,
  },
  webServer: {
    command: "bun run build && bun scripts/prepare-preview.ts && python3 -m http.server 18765 --bind 127.0.0.1 --directory tmp/preview",
    url: "http://127.0.0.1:18765/",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
