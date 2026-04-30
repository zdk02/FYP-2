/**
 * Component tests for <FindingsTable />.
 *
 * Renders the component into jsdom with various props and asserts on
 * the resulting DOM. Where unit tests verify pure functions in
 * isolation, component tests verify what the user actually sees.
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'

import FindingsTable from '../../src/components/scanners/FindingsTable.jsx'


describe('<FindingsTable /> — empty state', () => {
  it('renders the "No findings." placeholder when given no findings', () => {
    render(<FindingsTable findings={[]} />)
    expect(screen.getByText('No findings.')).toBeInTheDocument()
  })

  it('renders the placeholder when no prop is supplied at all', () => {
    render(<FindingsTable />)
    expect(screen.getByText('No findings.')).toBeInTheDocument()
  })

  it('does not render a table in the empty state', () => {
    render(<FindingsTable findings={[]} />)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })
})


describe('<FindingsTable /> — populated state', () => {
  const sample = [
    {
      severity: 'critical',
      confidence: 'confirmed',
      cve: 'CVE-2024-0001',
      client: 'Claude Code',
      title: 'Remote code execution via pickle deserialization',
      description: 'Server unpickles untrusted input.',
      remediation: 'Switch to JSON serialization.',
    },
    {
      severity: 'medium',
      confidence: 'high',
      cve: null,
      client: 'Cursor',
      title: 'Information disclosure in error response',
    },
  ]

  it('renders one row per finding', () => {
    render(<FindingsTable findings={sample} />)
    expect(
      screen.getByText('Remote code execution via pickle deserialization'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('Information disclosure in error response'),
    ).toBeInTheDocument()
  })

  it('shows the severity label in the row', () => {
    render(<FindingsTable findings={sample} />)
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('medium')).toBeInTheDocument()
  })

  it('shows the confidence label in the row', () => {
    render(<FindingsTable findings={sample} />)
    expect(screen.getByText('confirmed')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
  })

  it('renders a CVE link to NVD when the CVE id starts with "CVE-"', () => {
    render(<FindingsTable findings={sample} />)
    const link = screen.getByRole('link', { name: /CVE-2024-0001/ })
    expect(link).toBeInTheDocument()
    expect(link).toHaveAttribute(
      'href',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-0001',
    )
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noreferrer')
  })

  it('renders an em-dash placeholder when no CVE is present', () => {
    render(<FindingsTable findings={sample} />)
    // The second finding has cve=null, so there should be an em-dash in its row.
    const dashes = screen.getAllByText('—')
    expect(dashes.length).toBeGreaterThan(0)
  })

  it('renders the client column for each finding', () => {
    render(<FindingsTable findings={sample} />)
    expect(screen.getByText('Claude Code')).toBeInTheDocument()
    expect(screen.getByText('Cursor')).toBeInTheDocument()
  })

  it('renders a real <table> with a header row in populated state', () => {
    render(<FindingsTable findings={sample} />)
    const table = screen.getByRole('table')
    expect(table).toBeInTheDocument()
    expect(within(table).getByText('Severity')).toBeInTheDocument()
    expect(within(table).getByText('Confidence')).toBeInTheDocument()
    expect(within(table).getByText('CVE')).toBeInTheDocument()
  })
})


describe('<FindingsTable /> — fallback handling', () => {
  it('falls back to "info" severity when severity is missing', () => {
    render(
      <FindingsTable findings={[{ title: 'No-severity finding' }]} />,
    )
    expect(screen.getByText('info')).toBeInTheDocument()
  })

  it('falls back to "low" confidence when confidence is missing', () => {
    render(
      <FindingsTable findings={[{ title: 'No-conf finding' }]} />,
    )
    expect(screen.getByText('low')).toBeInTheDocument()
  })

  it('lowercases severity values that came in capitalised', () => {
    render(
      <FindingsTable findings={[{ severity: 'CRITICAL', title: 'Yelling' }]} />,
    )
    expect(screen.getByText('critical')).toBeInTheDocument()
  })
})


describe('<FindingsTable /> — expand / collapse interaction', () => {
  const sample = [
    {
      severity: 'high',
      confidence: 'confirmed',
      title: 'Auth bypass',
      description: 'Bypass via header smuggling.',
      remediation: 'Validate headers server-side.',
    },
  ]

  it('does not show the description by default', () => {
    render(<FindingsTable findings={sample} />)
    expect(screen.queryByText(/Bypass via header smuggling/)).not.toBeInTheDocument()
  })

  it('shows the description after clicking the expand chevron', () => {
    render(<FindingsTable findings={sample} />)
    // The expand chevron is the only button in the row.
    const expandBtn = screen.getAllByRole('button')[0]
    fireEvent.click(expandBtn)
    expect(screen.getByText('Bypass via header smuggling.')).toBeInTheDocument()
    expect(screen.getByText('Validate headers server-side.')).toBeInTheDocument()
  })

  it('hides the description again on a second click (toggle)', () => {
    render(<FindingsTable findings={sample} />)
    const expandBtn = screen.getAllByRole('button')[0]
    fireEvent.click(expandBtn)
    expect(screen.getByText(/Bypass via header smuggling/)).toBeInTheDocument()
    fireEvent.click(expandBtn)
    expect(screen.queryByText(/Bypass via header smuggling/)).not.toBeInTheDocument()
  })
})
