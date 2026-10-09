import { defineConfig, loadEnv } from "vite";
import { resolveSwapDefaults } from "./src/swap/config";

export default defineConfig(({ mode }) => {
  const defaults = resolveSwapDefaults({ ...loadEnv(mode, process.cwd(), "VITE_"), ...process.env });
  return {
    base: "./",
    define: { __SWAP_DEFAULTS__: JSON.stringify(defaults) },
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
