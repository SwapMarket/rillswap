/** Static mainnet root and signet subsite. Builds only, never publishes. */
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

rmSync("tmp/pages", { recursive: true, force: true });
mkdirSync("tmp/pages", { recursive: true });
for (const network of ["mainnet", "signet"] as const) {
  const env = { ...process.env };
  // Local regtest overrides must never leak into a public artifact.
  for (const key of Object.keys(env)) if (key.startsWith("VITE_RILLSWAP_")) delete env[key];
  env.VITE_RILLSWAP_NETWORK = network;
  // The header network picker opens the sibling build instead of reconfiguring in place.
  env.VITE_RILLSWAP_DEPLOYMENTS = JSON.stringify(network === "mainnet" ? { mainnet: "./", signet: "./signet/" } : { mainnet: "../", signet: "./" });
  const output = `tmp/pages-build/${network}`;
  const child = Bun.spawn([process.execPath, "node_modules/vite/bin/vite.js", "build", "--outDir", output, "--emptyOutDir"],
    { env, stdout: "inherit", stderr: "inherit" });
  if (await child.exited !== 0) throw new Error(`Static ${network} build failed`);
  const target = network === "mainnet" ? "tmp/pages" : "tmp/pages/signet";
  cpSync(output, target, { recursive: true });
  writeFileSync(`${target}/diagnostic.html`, readFileSync(`${target}/index.html`));
  const navigation = `<nav aria-label="Deployment network" style="text-align:center;padding:1rem;font:inherit"><a href="${network === "mainnet" ? "./" : "../"}">Mainnet</a> · <a href="${network === "mainnet" ? "./signet/" : "./"}">Signet</a></nav>`;
  const swap = readFileSync(`${target}/swap.html`, "utf8").replace("</body>", `${navigation}</body>`);
  writeFileSync(`${target}/index.html`, swap);
  writeFileSync(`${target}/swap.html`, swap);
}
writeFileSync("tmp/pages/.nojekyll", "");
