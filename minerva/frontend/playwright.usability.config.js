// @ts-check
import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright config for Minerva accessibility / usability tests.
 *
 * Same prerequisites as the E2E config — backend on :5000, frontend on :3000.
 * Distinct testDir + report folder so the two suites stay separate.
 */
export default defineConfig({
  testDir: './tests/usability',
  testMatch: '**/*.spec.{js,jsx}',
  timeout: 30_000,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', {
      outputFolder: './reports/tests/frontend_usability_test_report',
      open: 'never',
    }],
  ],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:3000',
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
