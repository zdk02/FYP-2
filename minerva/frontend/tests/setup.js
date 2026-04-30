// Vitest setup — runs before every test file.
// Brings in jest-dom matchers (toBeInTheDocument, toHaveTextContent, etc.)
// and a localStorage shim sufficient for Zustand's `persist` middleware.

import '@testing-library/jest-dom'
import { afterEach, beforeEach } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
})

beforeEach(() => {
  // Reset localStorage between tests so Zustand persist doesn't leak state
  if (typeof localStorage !== 'undefined') {
    localStorage.clear()
  }
})
