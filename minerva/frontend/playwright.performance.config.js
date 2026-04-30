// @ts-check
import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright config for Minerva frontend performance tests.
 * Same prerequisites as E2E (backend on :5000, frontend on :3000).
 */
export default defineConfig({
  testDir: './tests/performance',
  testMatch: '**/*.spec.{js,jsx}',
  timeout: 30_000,
  workers: 1,
  reporter: [
    ['list'],
    ['html', {
      outputFolder: './reports/tests/frontend_performance_test_report',
      open: 'never',
    }],
  ],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:3000',
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
