import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  base: '/ui/',
  plugins: [react()],
  build: {
    outDir: '../../server/Siem.Api/wwwroot/ui',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 55446,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:55443',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
  },
})
