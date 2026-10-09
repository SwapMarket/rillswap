import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";

// Copy identical dist bytes to root and a repository subpath for loopback tests.
rmSync("tmp/preview", { recursive: true, force: true });
mkdirSync("tmp/preview/repository", { recursive: true });
cpSync("dist", "tmp/preview", { recursive: true });
cpSync("dist", "tmp/preview/repository", { recursive: true });

// Test-only page for the cooperation journal; never part of dist or a release.
const journal = await Bun.build({
  entrypoints: ["src/swap/cooperationJournal.ts"],
  outdir: "tmp/preview/test-only",
  target: "browser",
  format: "esm",
});
if (!journal.success) throw new AggregateError(journal.logs, "journal test bundle failed");
writeFileSync(
  "tmp/preview/test-only/journal.html",
  '<!doctype html><script type="module">import { reserveCooperation } from "./cooperationJournal.js";' +
    "window.reserveCooperation = reserveCooperation; window.journalReady = true;</script>",
);

const wallet = await Bun.build({ entrypoints: ["src/browserRecoveryWallet.ts"], outdir: "tmp/preview/test-only", target: "browser", format: "esm" });
if (!wallet.success) throw new AggregateError(wallet.logs, "wallet test bundle failed");
writeFileSync("tmp/preview/test-only/wallet.html", '<!doctype html><script type="module">' +
  'import { BrowserRecoveryWallet, WALLET_DATABASE } from "./browserRecoveryWallet.js";' +
  "window.walletApi = { BrowserRecoveryWallet, WALLET_DATABASE }; window.walletReady = true;</script>");
