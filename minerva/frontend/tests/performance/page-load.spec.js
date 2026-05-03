// @ts-check
/**
 * Frontend page-load performance tests.
 *
 * Measures the browser's own performance timing API to assert page
 * load is fast enough for usable interaction. Thresholds are
 * generous on purpose — they catch order-of-magnitude regressions
 * (a giant unsplit bundle, a sync XHR on first paint) without
 * flapping on small variance.
 *
 * Both servers must be running first.
 */

import { test, expect } from '@playwright/test'


const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL || 'admin@minerva.local'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'admin123'


// Generous thresholds for a Vite dev build over localhost.
// (A production build would be 3–5× faster.)
const THRESHOLDS = {
  loginDomContentLoadedMs: 4000,
  loginFullyLoadedMs:      6000,
  dashboardNavigationMs:   5000,
}


/**
 * Read browser-side performance timing for the most recent
 * navigation. Works on Chromium via the Performance Timing API.
 */
async function readNavigationTiming(page) {
  return await page.evaluate(() => {
    const nav = performance.getEntriesByType('navigation')[0]
    return {
      dom_content_loaded: Math.round(nav.domContentLoadedEventEnd),
      load_event:         Math.round(nav.loadEventEnd),
      transfer_size:      nav.transferSize,
    }
  })
}


test.describe('Page-load performance — login page (cold load)', () => {
  test('login page DOMContentLoaded is under 4 seconds', async ({ page }) => {
    await page.goto('/login', { waitUntil: 'load' })
    const t = await readNavigationTiming(page)

    console.log(
      `[perf:fe] /login domContentLoaded=${t.dom_content_loaded}ms ` +
      `load=${t.load_event}ms transfer=${t.transfer_size}B`,
    )

    expect(
      t.dom_content_loaded,
      'login DOMContentLoaded under threshold',
    ).toBeLessThanOrEqual(THRESHOLDS.loginDomContentLoadedMs)
  })

  test('login page fully loaded is under 6 seconds', async ({ page }) => {
    await page.goto('/login', { waitUntil: 'load' })
    const t = await readNavigationTiming(page)
    expect(t.load_event).toBeLessThanOrEqual(THRESHOLDS.loginFullyLoadedMs)
  })
})


test.describe('Page-load performance — login → dashboard navigation', () => {
  test('login flow completes within 5 seconds end-to-end', async ({ page }) => {
    const t0 = Date.now()

    await page.goto('/login', { waitUntil: 'load' })
    await page.locator('input[type="email"]').fill(ADMIN_EMAIL)
    await page.locator('input[type="password"]').fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).toHaveURL(/\/dashboard$/)
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()

    const elapsed = Date.now() - t0
    console.log(`[perf:fe] login flow elapsed=${elapsed}ms`)

    expect(elapsed).toBeLessThanOrEqual(THRESHOLDS.dashboardNavigationMs)
  })
})
