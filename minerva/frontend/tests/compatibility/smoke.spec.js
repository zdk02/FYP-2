// @ts-check
/**
 * Cross-browser / multi-device compatibility smoke tests.
 *
 * Each test in this file runs once per browser project defined in
 * `playwright.compatibility.config.js`:
 *   - chromium          (Chrome, Edge, Brave, Opera)
 *   - firefox           (Firefox)
 *   - webkit            (Safari engine)
 *   - mobile-iphone-13  (375 × 667 viewport, mobile UA)
 *
 * The bar here is *minimum viable functionality* — log in, see the
 * dashboard, navigate. We're not re-running the full E2E matrix; we
 * just prove the engine doesn't break.
 */

import { test, expect } from '@playwright/test'


const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL || 'admin@aegis.local'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'admin123'


test.describe('Cross-browser smoke', () => {
  test('login form renders and submits', async ({ page }, testInfo) => {
    await page.goto('/login')

    // The form must be present and interactive in every browser.
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible()
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()

    await page.locator('input[type="email"]').fill(ADMIN_EMAIL)
    await page.locator('input[type="password"]').fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page).toHaveURL(/\/dashboard$/)
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()

    console.log(`[compat:${testInfo.project.name}] login + dashboard render OK`)
  })

  test('navigates to Targets page from dashboard', async ({ page }, testInfo) => {
    // Quick login.
    await page.goto('/login')
    await page.locator('input[type="email"]').fill(ADMIN_EMAIL)
    await page.locator('input[type="password"]').fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).toHaveURL(/\/dashboard$/)

    await page.goto('/targets')
    await expect(page).toHaveURL(/\/targets$/)
    await expect(page.getByRole('heading', { name: 'Targets' })).toBeVisible()

    console.log(`[compat:${testInfo.project.name}] /targets page OK`)
  })

  test('protected route redirects to /login when unauthenticated',
    async ({ page }, testInfo) => {
      await page.goto('/dashboard')
      await expect(page).toHaveURL(/\/login$/)
      console.log(`[compat:${testInfo.project.name}] route protection OK`)
    },
  )
})
