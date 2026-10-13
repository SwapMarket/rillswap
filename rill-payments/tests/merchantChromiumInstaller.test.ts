import { expect, test } from "bun:test";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

test.skipIf(process.platform !== "linux" || process.arch !== "x64").each(["cached", "downloaded"])("merchant Chromium installer rejects corrupt %s archives before extraction or execution", (source) => {
  const root = resolve("../tmp"); mkdirSync(root, { recursive: true });
  const directory = mkdtempSync(join(root, "merchant-chromium-installer-"));
  try {
    const scripts = join(directory, "rill-payments/scripts"), bin = join(directory, "bin"), marker = join(directory, "unchecked-operation");
    mkdirSync(scripts, { recursive: true }); mkdirSync(bin);
    const script = join(scripts, "install-merchant-chromium.sh"); copyFileSync("scripts/install-merchant-chromium.sh", script);
    const cache = join(directory, "tmp/merchant-chromium-157.0.8090.0"); mkdirSync(cache, { recursive: true });
    if (source === "cached") writeFileSync(join(cache, "chrome-linux64.zip"), "corrupt cached archive");
    for (const command of ["curl", "unzip"]) {
      const path = join(bin, command);
      const body = command === "curl" && source === "downloaded"
        ? '#!/bin/sh\nfor argument; do output="$argument"; done\nprintf corrupt > "$output"\n'
        : '#!/bin/sh\ntouch "$INSTALLER_TEST_MARKER"\nexit 0\n';
      writeFileSync(path, body); chmodSync(path, 0o700);
    }
    const result = Bun.spawnSync(["sh", script], { env: { ...process.env, PATH: bin + ":" + process.env.PATH, INSTALLER_TEST_MARKER: marker }, stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode).not.toBe(0); expect(result.stdout.toString()).toBe("");
    expect(result.stderr.toString()).toContain("FAILED"); expect(existsSync(marker)).toBe(false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
