import { defineConfig } from "@playwright/test";
export default defineConfig({ testDir: "browser", workers: 1, use: { baseURL: "http://127.0.0.1:8798", browserName: "chromium" },
  webServer: { command: "bun browser/server.ts", url: "http://127.0.0.1:8798", reuseExistingServer: false, timeout: 30000 },
  outputDir: "tmp/playwright-results" });
