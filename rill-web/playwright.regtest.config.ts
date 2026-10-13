import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./regtest", workers: 1, timeout: 180000, expect: { timeout: 30000 },
  reporter: [["list"], ["junit", { outputFile: "tmp/regtest-report.xml" }]], outputDir: "tmp/regtest-results",
  use: { headless: true, acceptDownloads: true, actionTimeout: 30000, navigationTimeout: 30000,
    trace: "retain-on-failure", screenshot: "only-on-failure" },
});
