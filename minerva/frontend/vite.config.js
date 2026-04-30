/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: "http://127.0.0.1:5000",  // Changed from localhost to 127.0.0.1
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.js'],
    include: ['tests/**/*.test.{js,jsx}'],
    exclude: ['tests/e2e/**', 'node_modules/**'],
    reporters: ['default', 'html'],
    outputFile: {
      html: './reports/tests/frontend_unit_test_report/index.html',
    },
  },
})