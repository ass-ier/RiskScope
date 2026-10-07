import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const base = env.VITE_API_BASE_URL || process.env.VITE_API_BASE_URL
  if (process.env.VERCEL === '1' && !base) {
    throw new Error('Set VITE_API_BASE_URL to the Render API HTTPS origin before deploying to Vercel.')
  }
  if (base) {
    const url = new URL(base)
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
      || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) {
      throw new Error('VITE_API_BASE_URL must be an HTTPS origin without a path, credentials, query or fragment.')
    }
    if (process.env.VERCEL === '1' && !url.hostname.endsWith('.onrender.com')) {
      throw new Error('The supplied Vercel CSP supports Render onrender.com URLs. Update connect-src before using a custom API domain.')
    }
  }
  return {
    plugins: [react(), tailwindcss()],
    server: {
      proxy: {
        '/api': {
          target: env.VITE_API_PROXY || 'http://127.0.0.1:8765',
          changeOrigin: true,
        },
      },
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            graph: ['cytoscape'],
            charts: ['recharts'],
          },
        },
      },
    },
  }
})
