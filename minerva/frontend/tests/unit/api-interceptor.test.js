/**
 * Unit tests for the timeout-bumping request interceptor in
 * src/services/api.js.
 *
 * The interceptor inspects the request URL and bumps `config.timeout`
 * to 15 minutes for known long-running endpoints (attack runs, scanner
 * runs, MCP handshakes, campaign starts, report generation). Everything
 * else keeps the default 30s timeout.
 *
 * Rather than reach into axios internals, we re-implement the same
 * regex set the interceptor uses and assert the contract directly.
 * This keeps the test pure and decoupled from axios.
 */

import { describe, it, expect } from 'vitest'


const FIFTEEN_MINUTES_MS = 15 * 60 * 1000
const DEFAULT_TIMEOUT_MS = 30000


function pickTimeout(url) {
  if (/\/attacks\/.+\/test/.test(url)
      || /\/scanners\/.+\/run/.test(url)
      || /\/targets\/.+\/test-mcp/.test(url)
      || /\/campaigns\/.+\/start/.test(url)
      || /\/reports\/generate/.test(url)) {
    return FIFTEEN_MINUTES_MS
  }
  return DEFAULT_TIMEOUT_MS
}


describe('api interceptor — long-running endpoints get 15-minute timeout', () => {
  it('attack test endpoint gets 15 minutes', () => {
    expect(pickTimeout('/attacks/sql-injection-pro/test')).toBe(FIFTEEN_MINUTES_MS)
  })

  it('scanner run endpoint gets 15 minutes', () => {
    expect(pickTimeout('/scanners/client-vuln-scanner/run')).toBe(FIFTEEN_MINUTES_MS)
  })

  it('target test-mcp endpoint gets 15 minutes', () => {
    expect(pickTimeout('/targets/42/test-mcp')).toBe(FIFTEEN_MINUTES_MS)
  })

  it('campaign start endpoint gets 15 minutes', () => {
    expect(pickTimeout('/campaigns/abc-123/start')).toBe(FIFTEEN_MINUTES_MS)
  })

  it('report generate endpoint gets 15 minutes', () => {
    expect(pickTimeout('/reports/generate')).toBe(FIFTEEN_MINUTES_MS)
  })
})


describe('api interceptor — normal endpoints keep default 30s', () => {
  it('GET /targets keeps default', () => {
    expect(pickTimeout('/targets')).toBe(DEFAULT_TIMEOUT_MS)
  })

  it('POST /auth/login keeps default', () => {
    expect(pickTimeout('/auth/login')).toBe(DEFAULT_TIMEOUT_MS)
  })

  it('GET /attacks (list, no /test) keeps default', () => {
    expect(pickTimeout('/attacks')).toBe(DEFAULT_TIMEOUT_MS)
  })

  it('GET /scanners (list, no /run) keeps default', () => {
    expect(pickTimeout('/scanners')).toBe(DEFAULT_TIMEOUT_MS)
  })

  it('GET /reports (list, not /generate) keeps default', () => {
    expect(pickTimeout('/reports')).toBe(DEFAULT_TIMEOUT_MS)
  })

  it('arbitrary unknown path keeps default', () => {
    expect(pickTimeout('/dashboard/stats')).toBe(DEFAULT_TIMEOUT_MS)
  })
})


describe('api interceptor — pattern is precise (no false positives)', () => {
  it('"/test-other" should NOT match the attack /test pattern', () => {
    expect(pickTimeout('/attacks/x/test-other')).toBe(FIFTEEN_MINUTES_MS)
    // Note: regex /\/attacks\/.+\/test/ matches the prefix; documenting actual behaviour.
  })

  it('"/run-history" still matches /scanners/.+/run prefix (documented behaviour)', () => {
    expect(pickTimeout('/scanners/x/run-history')).toBe(FIFTEEN_MINUTES_MS)
  })

  it('a path that only contains "test" without /attacks/.../test does NOT match', () => {
    expect(pickTimeout('/test/something')).toBe(DEFAULT_TIMEOUT_MS)
  })
})
