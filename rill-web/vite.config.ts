import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      // The preview page makes no connections; the swap page may reach relays.
      input: { main: "index.html", swap: "swap.html" },
    },
  },
});
