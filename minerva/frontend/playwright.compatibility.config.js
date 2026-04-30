// @ts-check
import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright config for cross-browser / multi-device compatibility tests.
 *
 * Same prerequisites as E2E (backend on :5000, frontend on :3000).
 * Each project below runs the same smoke specs in a different rendering
 * engine or device profile, so we can prove the UI works in all of them.
 */
export default defineConfig({
  testDir: './tests/compatibility',
  testMatch: '**/*.spec.{js,jsx}',
  timeout: 30_000,
  workers: 1,
  reporter: [
    ['list'],
    ['html', {
      outputFolder: './reports/tests/frontend_compatibility_test_report',
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
    // Three desktop rendering engines.
    {
      name: 'chromium',           // Chrome / Edge / Brave / Opera
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',            // Firefox + Tor Browser
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',             // Safari (macOS / iOS Safari rendering engine)
      use: { ...devices['Desktop Safari'] },
    },
    // One mobile viewport — proves the UI doesn't shatter at 375×667.
    {
      name: 'mobile-iphone-13',
      use: { ...devices['iPhone 13'] },
    },
  ],
})
