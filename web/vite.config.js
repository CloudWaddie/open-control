import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `npm run build` writes the SPA into the Go package so go:embed picks it up.
// `npm run dev` serves on :5173 and proxies /api to a locally running server.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/web/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8080' },
  },
});
