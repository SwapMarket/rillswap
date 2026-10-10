import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { recoveryInspectionCases } from "../unit/fixtures/recoveryInspectionCases";

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

// Test only orchestration, never protocol authentication, with real wallet/tip/UI code.
const ui = await Bun.build({ entrypoints: ["src/swapUi.ts"], outdir: "tmp/preview/test-only", target: "browser", format: "esm",
  define: { __SWAP_DEFAULTS__: JSON.stringify({ network: "regtest", relays: ["ws://127.0.0.1:7777/"], mempoolApi: "http://127.0.0.1:8091/api" }) },
  plugins: [{ name: "test-only-ui", setup(build) {
    build.onLoad({ filter: /\/src\/swap\/marketplace\.ts$/ }, () => ({ contents: readFileSync("tests/fixtures/swapUiMarketplace.ts", "utf8"), loader: "ts" }));
    build.onLoad({ filter: /\/src\/swap\/browserCosigner\.ts$/ }, () => ({ contents: "export const browserCosigner = {};", loader: "ts" }));
  } }],
});
if (!ui.success) throw new AggregateError(ui.logs, "UI test bundle failed");
writeFileSync("tmp/preview/test-only/swap.html", readFileSync("dist/swap.html", "utf8")
  .replace(/src="\.\/assets\/[^"]+"/, 'src="./swapUi.js"').replaceAll("./assets/", "/assets/"));

const recoveryAdmission = await Bun.build({ entrypoints: ["src/recoveryDocument.ts", "src/recoveryInspection.ts"], outdir: "tmp/preview/test-only", target: "browser", format: "esm" });
if (!recoveryAdmission.success) throw new AggregateError(recoveryAdmission.logs, "recovery admission test bundle failed");
// Generate the synthetic native-signature corpus in Bun, not Playwright's Node
// runner (unbundled Ajv standalone output uses require for its static runtime).
writeFileSync("tmp/preview/test-only/recovery-inspection-cases.json", JSON.stringify(recoveryInspectionCases()));
const admissionCsp = "default-src 'none'; script-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'";
writeFileSync("tmp/preview/test-only/recovery-admission.html", `<!doctype html><meta http-equiv="Content-Security-Policy" content="${admissionCsp}">` +
  '<script type="module" src="./recovery-admission-harness.js"></script>');
writeFileSync("tmp/preview/test-only/recovery-admission-harness.js", 'import { parseRecoveryPlaintext } from "./recoveryDocument.js";' +
  'import { inspectRecoveryPlaintext } from "./recoveryInspection.js";' +
  'window.parseRecoveryPlaintext = parseRecoveryPlaintext; window.inspectRecoveryPlaintext = inspectRecoveryPlaintext; window.recoveryAdmissionReady = true;');
