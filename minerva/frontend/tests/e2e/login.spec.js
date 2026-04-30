// @ts-check
/**
 * System / E2E test — login + logout journey.
 *
 * Drives the real React frontend (served by Vite on :3000) in a real
 * Chromium browser. The frontend in turn talks to the real Flask
 * backend on :5000 (which talks to its real SQLite database). Nothing
 * is mocked.
 *
 * Default credentials are seeded automatically by
 * `initialize_default_data()` when the backend boots:
 *     admin@minerva.local / admin123
 */

import { test, expect } from '@playwright/test'


// Override via env vars if you need to test against a different DB / install:
//   E2E_ADMIN_EMAIL=admin@minerva.local E2E_ADMIN_PASSWORD=admin123 npm run test:e2e
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL || 'admin@aegis.local'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'admin123'


test.describe('Login journey', () => {
  test('shows the sign-in form on /login', async ({ page }) => {
    await page.goto('/login')
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible()
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible()
  })

  test('redirects unauthenticated visits to /login', async ({ page }) => {
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/\/login$/)
  })

  test('rejects invalid credentials and stays on /login', async ({ page }) => {
    // Listen for the 401 from /auth/login — that's the contract we care about.
    const loginResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes('/auth/login') && resp.request().method() === 'POST',
    )

    await page.goto('/login')
    await page.locator('input[type="email"]').fill(ADMIN_EMAIL)
    await page.locator('input[type="password"]').fill('definitely-wrong-password')
    await page.getByRole('button', { name: /sign in/i }).click()

    const loginResponse = await loginResponsePromise
    expect(loginResponse.status()).toBe(401)

    // We must NOT be on the dashboard.
    await expect(page).not.toHaveURL(/\/dashboard/)
    await expect(page).toHaveURL(/\/login$/)
  })

  test('logs in with admin credentials and lands on the dashboard', async ({ page }) => {
    await page.goto('/login')
    await page.locator('input[type="email"]').fill(ADMIN_EMAIL)
    await page.locator('input[type="password"]').fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page).toHaveURL(/\/dashboard$/)
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
    await expect(page.getByText(/welcome back/i)).toBeVisible()
  })

  test('persists session across a page reload', async ({ page }) => {
    await page.goto('/login')
    await page.locator('input[type="email"]').fill(ADMIN_EMAIL)
    await page.locator('input[type="password"]').fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).toHaveURL(/\/dashboard$/)

    // Hard reload — the persisted Zustand store should keep us logged in.
    await page.reload()
    await expect(page).toHaveURL(/\/dashboard$/)
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  })
})
