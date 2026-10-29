import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import viteConfig from "../vite.config.ts";

const config = viteConfig({ command: "build", mode: "production" });
const onLog = config.build!.rolldownOptions!.onLog!;
const glue = fileURLToPath(new URL("../src/vendor/rill-crypto/rill_crypto_wasm.mjs", import.meta.url));
const diagnostic = {
  plugin: "rolldown:vite-resolve",
  message: `Module "node:module" has been externalized for browser compatibility, imported by "${glue}". See https://vite.dev/guide/troubleshooting.html#module-externalized-for-browser-compatibility for more details.`,
};

test("only the pinned universal WASM loader's Node-only diagnostic becomes debug output", () => {
  const logs: unknown[] = [];
  onLog("warn", diagnostic, (...args) => logs.push(args));
  expect(logs).toEqual([["debug", diagnostic]]);
});

test("other modules, importers, plugins, and log levels keep their diagnostics", () => {
  for (const log of [
    { ...diagnostic, message: diagnostic.message.replace("node:module", "node:fs") },
    { ...diagnostic, message: diagnostic.message.replace(glue, "/src/other.mjs") },
    { ...diagnostic, plugin: "another-plugin" },
    { ...diagnostic, message: "Some chunks are larger than 500 kB after minification" },
  ]) {
    const logs: unknown[] = [];
    onLog("warn", log, (...args) => logs.push(args));
    expect(logs).toEqual([["warn", log]]);
  }
  const logs: unknown[] = [];
  onLog("info", diagnostic, (...args) => logs.push(args));
  expect(logs).toEqual([["info", diagnostic]]);
});
