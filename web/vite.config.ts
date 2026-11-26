import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

/**
 * Strips sonner's runtime <style> injection so strict CSP (`default-src 'self'`)
 * never reports inline style violations; sonner/dist/styles.css is bundled statically.
 */
function stripSonnerInlineCss(): Plugin {
  return {
    name: "strip-sonner-inline-css",
    transform(code, id) {
      if (!id.includes("/node_modules/sonner/")) {
        return null;
      }
      return code.replace(
        /function __insertCSS\([^)]*\)\s*\{[\s\S]*?\n\}/,
        "function __insertCSS() {}",
      );
    },
  };
}

export default defineConfig({
  plugins: [stripSonnerInlineCss(), react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          "vendor-react": ["react", "react-dom", "react-router-dom"],
          "vendor-ui": ["@base-ui/react", "sonner"],
          "vendor-icons": ["lucide-react"],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api/v1": {
        target: process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
});
