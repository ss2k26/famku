import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

// The production build is written next to the Go code and compiled into the binary (go:embed).
const outDir = fileURLToPath(new URL('../backend/internal/infrastructure/webui/dist', import.meta.url));

export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  resolve: { alias: { $lib: fileURLToPath(new URL('./src/lib', import.meta.url)) } },
  build: { outDir, emptyOutDir: true, sourcemap: false, target: 'es2022' },
  server: {
    port: 5173,
    // same origin in development: the browser talks to Vite, Vite forwards /api to the Go server (no CORS needed)
    proxy: { '/api': { target: process.env.API_PROXY ?? 'http://localhost:8080', changeOrigin: false } }
  }
});
