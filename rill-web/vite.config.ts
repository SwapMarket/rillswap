import { defineConfig, loadEnv } from "vite";
import { resolveSwapDefaults } from "./src/swap/config";

export default defineConfig(({ mode }) => {
  const defaults = resolveSwapDefaults({ ...loadEnv(mode, process.cwd(), "VITE_"), ...process.env });
  return {
    base: "./",
    define: { __SWAP_DEFAULTS__: JSON.stringify(defaults) },
    plugins: [{ name: "swap-chain-csp", transformIndexHtml(html, context) {
      if (!context.filename.endsWith("swap.html")) return html;
      const origins = new Set(["https://mempool.space", "https://blockstream.info",
        "http://127.0.0.1:8091", "http://localhost:8091", new URL(defaults.mempoolApi).origin, new URL(defaults.broadcastApi).origin]);
      if (defaults.nodeApi) origins.add(new URL(defaults.nodeApi).origin);
      return html.replace("__CHAIN_API_ORIGINS__", [...origins].join(" "));
    } }],
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
