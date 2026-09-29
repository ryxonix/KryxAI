import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({ mode }) => {
  // The backend target is configurable instead of hardcoded, so the dev server
  // can be pointed at a backend on another port. This matters in practice: port
  // 8000 is a common default and anything else may already hold it, in which
  // case a hardcoded proxy silently forwards to the wrong server and every
  // request appears to work while returning someone else's data.
  // Read process.env directly as well as .env files: loadEnv only guarantees
  // .env coverage, and a dev server started with an inline env var must work
  // without a .env file being present.
  const env = loadEnv(mode, process.cwd(), '')
  const target = process.env.VITE_API_TARGET || env.VITE_API_TARGET || 'http://localhost:8000'

  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: {
        '/ws': {
          target,
          ws: true,
        },
        '/api': {
          target,
          changeOrigin: true,
        },
        '/health': {
          target,
          changeOrigin: true,
        },
      },
    },
  }
})
