import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      }
    },
  },
  define: {
    'process.env.VITE_APP_NAME': JSON.stringify('PhishGuard'),
    'process.env.VITE_API_VERSION': JSON.stringify('1.0.0'),
  }
}) 