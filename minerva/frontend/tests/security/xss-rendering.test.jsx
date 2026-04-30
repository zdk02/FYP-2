/**
 * Frontend XSS-rendering tests.
 *
 * The backend stores user-supplied strings verbatim (proven by the
 * backend security suite). The defence against XSS therefore lives
 * on the frontend, in React's automatic JSX escaping. These tests
 * pin that contract: when a malicious payload arrives in props,
 * React must render it as inert text, never as live HTML.
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import FindingsTable from '../../src/components/scanners/FindingsTable.jsx'


const XSS_PAYLOADS = [
  "<script>alert('xss')</script>",
  "<img src=x onerror=alert(1)>",
  "<svg/onload=alert(1)>",
  "javascript:alert('xss')",
  "<iframe src='javascript:alert(1)'>",
]


describe('XSS — React escapes payloads in finding titles', () => {
  it.each(XSS_PAYLOADS)(
    'renders %s as inert text, not as executable HTML',
    (payload) => {
      const { container } = render(
        <FindingsTable findings={[{ severity: 'high', title: payload }]} />,
      )

      // The literal payload string must appear in the DOM.
      expect(screen.getByText(payload)).toBeInTheDocument()

      // No actual <script> element must have been added by React.
      expect(container.querySelectorAll('script')).toHaveLength(0)

      // The cell's HTML should contain escaped angle brackets, not raw <script>.
      const html = container.innerHTML
      // If React had injected the raw payload it would render literally; instead
      // it should render escaped.
      expect(html).not.toContain('<script>alert')
      expect(html).not.toContain('<svg/onload=')
      expect(html).not.toContain('<iframe src=')
    },
  )
})


describe('XSS — React escapes payloads in finding descriptions', () => {
  it('description with <img onerror> renders as text after expand, no event fires', () => {
    const findings = [
      {
        severity: 'high',
        title: 'desc-test',
        description: "<img src=x onerror=alert('pwned')>",
      },
    ]
    const { container } = render(<FindingsTable findings={findings} />)

    // Expand the row to reveal description.
    const expandBtn = screen.getAllByRole('button')[0]
    fireEvent.click(expandBtn)

    expect(
      screen.getByText("<img src=x onerror=alert('pwned')>"),
    ).toBeInTheDocument()

    // No real <img> with an onerror handler should have been created.
    const imgs = container.querySelectorAll('img')
    for (const img of imgs) {
      expect(img.getAttribute('onerror')).toBeNull()
    }
  })

  it('CVE column with non-CVE-prefixed value does not render as a link', () => {
    // CVE links are only rendered when the id starts with "CVE-".
    // A malicious value like "javascript:alert(1)" should NOT become a link.
    render(
      <FindingsTable
        findings={[{ severity: 'medium', title: 't', cve: "javascript:alert(1)" }]}
      />,
    )
    // No link should exist for this row's CVE value.
    const links = screen.queryAllByRole('link', { name: /javascript:/ })
    expect(links).toHaveLength(0)
  })
})


describe('XSS — innerHTML is escaped consistently', () => {
  it('all 5 payloads round-trip without producing executable HTML', () => {
    const findings = XSS_PAYLOADS.map((p, i) => ({
      severity: 'high',
      title: `item-${i}`,
      description: p,
    }))
    const { container } = render(<FindingsTable findings={findings} />)

    const html = container.innerHTML
    // None of these raw fragments should appear as live HTML.
    const dangerous_fragments = [
      '<script>alert',
      '<img src=x onerror=',
      '<svg/onload=',
      '<iframe src=',
    ]
    for (const frag of dangerous_fragments) {
      expect(html).not.toContain(frag)
    }

    // No <script>, <iframe>, or onload-bearing nodes should have been added.
    expect(container.querySelectorAll('script')).toHaveLength(0)
    expect(container.querySelectorAll('iframe')).toHaveLength(0)
  })
})
