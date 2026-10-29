import { defineConfig, loadEnv } from "vite";
import { buildCommit } from "./scripts/build-commit";
import { resolveSwapDefaults } from "./src/swap/config";

export default defineConfig(({ mode }) => {
  const defaults = resolveSwapDefaults({ ...loadEnv(mode, process.cwd(), "VITE_"), ...process.env });
  const commit = buildCommit();
  return {
    base: "./",
    define: { __SWAP_DEFAULTS__: JSON.stringify(defaults) },
    plugins: [{ name: "swap-chain-csp", transformIndexHtml(html, context) {
      if (!context.filename.endsWith("swap.html")) return html;
      // Any https origin may serve chain data, so users can point Settings at their own mempool
      // instance. Plain http stays limited to the configured (local) endpoints.
      const origins = new Set(["https:", "http://127.0.0.1:8091", "http://localhost:8091"]);
      for (const url of [defaults.mempoolApi, defaults.broadcastApi, defaults.nodeApi, defaults.evmRpc, defaults.evmSponsor?.url]) {
        if (url && new URL(url).protocol === "http:") origins.add(new URL(url).origin);
      }
      return html.replace("__CHAIN_API_ORIGINS__", [...origins].join(" "));
    } }, {
      name: "build-commit",
      // Keep revision-only changes out of bundle URLs used by the update safeguard.
      transformIndexHtml: () => commit ? [{
        tag: "meta", attrs: { name: "rillswap-build-commit", content: commit }, injectTo: "head",
      }] : [],
    }],
    build: {
      outDir: "dist",
      emptyOutDir: true,
      sourcemap: false,
      rollupOptions: {
        // The preview page makes no connections; the swap page may reach relays.
        input: { main: "index.html", swap: "swap.html" },
      },
    },
  };
});
