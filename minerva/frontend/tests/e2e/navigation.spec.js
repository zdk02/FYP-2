// @ts-check
/**
 * System / E2E test — post-login navigation.
 *
 * Logs in once, then navigates to each major section to confirm the
 * routes are wired up and the protected pages render.
 */

import { test, expect } from '@playwright/test'


const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL || 'admin@aegis.local'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'admin123'


async function login(page) {
  await page.goto('/login')
  await page.locator('input[type="email"]').fill(ADMIN_EMAIL)
  await page.locator('input[type="password"]').fill(ADMIN_PASSWORD)
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page).toHaveURL(/\/dashboard$/)
}


test.describe('Authenticated navigation', () => {
  test('navigates from dashboard to Targets page', async ({ page }) => {
    await login(page)
    await page.goto('/targets')
    await expect(page).toHaveURL(/\/targets$/)
    await expect(page.getByRole('heading', { name: 'Targets' })).toBeVisible()
  })

  test('navigates to Attacks page', async ({ page }) => {
    await login(page)
    await page.goto('/attacks')
    await expect(page).toHaveURL(/\/attacks$/)
  })

  test('navigates to Reports page', async ({ page }) => {
    await login(page)
    await page.goto('/reports')
    await expect(page).toHaveURL(/\/reports$/)
  })

  test('navigates to Scanners page', async ({ page }) => {
    await login(page)
    await page.goto('/scanners')
    await expect(page).toHaveURL(/\/scanners$/)
  })

  test('navigates to Settings page', async ({ page }) => {
    await login(page)
    await page.goto('/settings')
    await expect(page).toHaveURL(/\/settings$/)
  })

  test('unknown route redirects to dashboard', async ({ page }) => {
    await login(page)
    await page.goto('/this/does/not/exist')
    await expect(page).toHaveURL(/\/dashboard$/)
  })
})
