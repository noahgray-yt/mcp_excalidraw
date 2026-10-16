import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The canvas server rejects foreign Origin headers; present proxied dev
// requests as same-origin with the canvas server.
const canvasProxy = {
  target: 'http://127.0.0.1:3000',
  changeOrigin: true,
  configure: (proxy) => {
    proxy.on('proxyReq', (proxyReq) => {
      if (proxyReq.getHeader('origin')) proxyReq.setHeader('origin', 'http://127.0.0.1:3000')
    })
  },
}

export default defineConfig({
  root: 'frontend',
  plugins: [react()],
  build: {
    outDir: '../dist/frontend',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // Excalidraw's font subsetting worker looks for these files by their
        // original (unhashed) names. Preserve them so the 404 doesn't break export.
        chunkFileNames: (chunkInfo) => {
          if (chunkInfo.name.startsWith('subset-')) {
            return 'assets/[name].js'
          }
          return 'assets/[name]-[hash].js'
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': canvasProxy,
      '/health': canvasProxy,
    },
  },
})
