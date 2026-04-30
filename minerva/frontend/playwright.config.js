// @ts-check
import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright config for Minerva System / End-to-End tests.
 *
 * Prerequisites (run these in two separate terminals before `npm run test:e2e`):
 *   1. Backend:   cd minerva/backend  && python run.py        (serves on :5000)
 *   2. Frontend:  cd minerva/frontend && npm run dev          (serves on :3000)
 *
 * Default credentials (seeded by initialize_default_data):
 *   admin@minerva.local / admin123
 */
export default defineConfig({
  testDir: './tests/e2e',
  testMatch: '**/*.spec.{js,jsx}',
  timeout: 30_000,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', {
      outputFolder: './reports/tests/frontend_e2e_test_report',
      open: 'never',
    }],
  ],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:3000',
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
