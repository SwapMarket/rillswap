/** Static mainnet root and signet subsite. Builds only, never publishes. */
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

/** Public address of the mainnet root, ending in "/". Override for a fork or a custom domain. */
const SITE = new URL(process.env.RILLSWAP_SITE_URL ?? "https://rillswap.github.io/rillswap/").href;
if (!SITE.endsWith("/")) throw new Error("RILLSWAP_SITE_URL must end with /");
const SOURCE_CODE_URL = "https://github.com/rillswap/rillswap";
const SIGNET = {
  title: "RillSwap Signet: try Lightning swaps with test coins",
  description: "Try the RillSwap decentralized Lightning swap market on Bitcoin signet. Test coins only, with no real value. Non-custodial, no account.",
};

const escape = (text: string): string =>
  text.replaceAll("&", "&amp;").replaceAll("\"", "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

function only(html: string, pattern: RegExp, what: string): string {
  const found = html.match(pattern);
  if (!found?.[1]) throw new Error(`swap.html is missing its ${what}`);
  return found[1];
}

/** Canonical address, Open Graph, Twitter card and JSON-LD for one deployment's page. */
function withSearchMetadata(html: string, network: "mainnet" | "signet"): string {
  if (network === "signet") {
    html = html.replace(/<title>[^<]*<\/title>/, () => `<title>${escape(SIGNET.title)}</title>`)
      .replace(/<meta name="description" content="[^"]*"/, () => `<meta name="description" content="${escape(SIGNET.description)}"`);
  }
  const title = only(html, /<title>([^<]*)<\/title>/, "title");
  const description = only(html, /<meta name="description" content="([^"]*)"/, "description");
  const url = network === "mainnet" ? SITE : new URL("signet/", SITE).href;
  const image = new URL("social-card.png", SITE).href;
  const application = JSON.stringify({
    "@context": "https://schema.org", "@type": "WebApplication", name: "RillSwap", url, description,
    applicationCategory: "FinanceApplication", operatingSystem: "Any", browserRequirements: "Requires JavaScript and WebAssembly",
    isAccessibleForFree: true, license: "https://opensource.org/licenses/MIT", image, sameAs: [SOURCE_CODE_URL],
  }).replaceAll("<", "\\u003c");
  const head = [
    `<link rel="canonical" href="${escape(url)}" />`,
    `<meta property="og:type" content="website" />`,
    `<meta property="og:site_name" content="RillSwap" />`,
    `<meta property="og:title" content="${title}" />`,
    `<meta property="og:description" content="${description}" />`,
    `<meta property="og:url" content="${escape(url)}" />`,
    `<meta property="og:image" content="${escape(image)}" />`,
    `<meta property="og:image:width" content="1200" />`,
    `<meta property="og:image:height" content="630" />`,
    `<meta property="og:image:alt" content="RillSwap: permissionless Lightning swaps" />`,
    `<meta name="twitter:card" content="summary_large_image" />`,
    `<meta name="twitter:title" content="${title}" />`,
    `<meta name="twitter:description" content="${description}" />`,
    `<meta name="twitter:image" content="${escape(image)}" />`,
    `<script type="application/ld+json">${application}</script>`,
  ].map((line) => `    ${line}\n`).join("");
  if (html.split("</head>").length !== 2) throw new Error("swap.html must have exactly one </head>");
  return html.replace(/[ \t]*<\/head>/, () => `${head}  </head>`);
}

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
  // The local diagnostic page carries its own noindex.
  writeFileSync(`${target}/diagnostic.html`, readFileSync(`${target}/index.html`));
  const swap = withSearchMetadata(readFileSync(`${target}/swap.html`, "utf8"), network);
  writeFileSync(`${target}/index.html`, swap);
  writeFileSync(`${target}/swap.html`, swap);
}
writeFileSync("tmp/pages/sitemap.xml", `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${escape(SITE)}</loc></url>
  <url><loc>${escape(new URL("signet/", SITE).href)}</loc></url>
</urlset>
`);
// Crawlers read robots.txt only at a domain root, so this applies once the site has its own domain.
writeFileSync("tmp/pages/robots.txt", `User-agent: *\nAllow: /\nSitemap: ${new URL("sitemap.xml", SITE).href}\n`);
writeFileSync("tmp/pages/.nojekyll", "");
