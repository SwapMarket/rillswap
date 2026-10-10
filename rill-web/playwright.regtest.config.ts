import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./regtest", workers: 1, timeout: 180000, expect: { timeout: 30000 },
  reporter: "list", outputDir: "tmp/regtest-results",
  use: { headless: true, acceptDownloads: true, trace: "retain-on-failure", screenshot: "only-on-failure" },
});
