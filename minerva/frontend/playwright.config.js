// @ts-check
import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright config for Minerva System / End-to-End tests.
 *
 * The `webServer` block below auto-starts both the backend (Flask :5000)
 * and the frontend (Vite :3000) before tests run, and shuts them down
 * after — so `npm run test:e2e` is a single self-contained command.
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
  webServer: [
    {
      command: 'python run.py',
      cwd: '../backend',
      url: 'http://localhost:5000/api/v1/health/ready',
      timeout: 60_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'ignore',
      stderr: 'pipe',
      env: {
        // Force UTF-8 stdout so the run.py banner (Unicode box-drawing chars)
        // doesn't crash on Windows where the default subprocess encoding is cp1252.
        PYTHONIOENCODING: 'utf-8',
        PYTHONUTF8: '1',
        // Disable Flask's debug auto-reloader during E2E. The reloader forks a
        // child process which confuses Playwright's webServer lifecycle and
        // causes "Exit code: 1" when the parent watcher shuts down.
        FLASK_DEBUG: 'false',
        FLASK_ENV: 'development',
      },
    },
    {
      command: 'npm run dev',
      cwd: '.',
      url: 'http://localhost:3000',
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
    },
  ],
})
