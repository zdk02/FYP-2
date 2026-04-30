/**
 * Frontend stress test — does the UI stay responsive when given an
 * unusually large dataset?
 *
 * `<FindingsTable />` is the table component used to display scanner
 * findings. In normal use it shows ~10–50 rows. Here we feed it
 * 500 and 1000 rows to confirm:
 *   - Render does not throw
 *   - Render completes within a generous time budget
 *   - Every row is in the DOM (no silent truncation)
 *   - Expand-collapse still works on row #500 of a 1000-row list
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import FindingsTable from '../../src/components/scanners/FindingsTable.jsx'


function makeFindings(n) {
  return Array.from({ length: n }, (_, i) => ({
    severity: ['critical', 'high', 'medium', 'low', 'info'][i % 5],
    confidence: ['confirmed', 'high', 'medium', 'low'][i % 4],
    cve: `CVE-2024-${String(10000 + i).padStart(5, '0')}`,
    client: `client-${i % 12}`,
    title: `Stress finding #${i}: lorem ipsum dolor sit amet`,
    description: `Detailed description for finding ${i}.`,
    remediation: `Fix instructions for finding ${i}.`,
  }))
}


describe('<FindingsTable /> — stress: large lists', () => {
  it('renders 500 findings within 1.5 seconds', () => {
    const findings = makeFindings(500)

    const t0 = performance.now()
    render(<FindingsTable findings={findings} />)
    const elapsed = performance.now() - t0

    console.log(`[stress:fe] rendered 500 findings in ${elapsed.toFixed(0)}ms`)

    expect(elapsed).toBeLessThan(1500)

    // First and last rows must both be in the DOM.
    expect(screen.getByText(/Stress finding #0/)).toBeInTheDocument()
    expect(screen.getByText(/Stress finding #499/)).toBeInTheDocument()
  })

  it('renders 1000 findings within 3 seconds', () => {
    const findings = makeFindings(1000)

    const t0 = performance.now()
    render(<FindingsTable findings={findings} />)
    const elapsed = performance.now() - t0

    console.log(`[stress:fe] rendered 1000 findings in ${elapsed.toFixed(0)}ms`)

    expect(elapsed).toBeLessThan(3000)
    expect(screen.getByText(/Stress finding #999/)).toBeInTheDocument()
  })

  it('expand-collapse still works on a row deep in a 1000-row list', () => {
    const findings = makeFindings(1000)
    render(<FindingsTable findings={findings} />)

    // The expand chevron is the first button in each row, so the 500th
    // chevron is at index 499.
    const buttons = screen.getAllByRole('button')
    expect(buttons.length).toBeGreaterThanOrEqual(1000)

    fireEvent.click(buttons[499])
    // Description for finding #499 should now be visible.
    expect(
      screen.getByText('Detailed description for finding 499.'),
    ).toBeInTheDocument()
  })
})
