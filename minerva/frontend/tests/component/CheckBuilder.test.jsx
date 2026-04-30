/**
 * Component tests for <CheckBuilder />.
 *
 * CheckBuilder is a controlled form component used in the scanner-plugin
 * editor. It renders a list of "check" rows, lets the user select a check
 * type from a known schema, edit per-type fields, and add or remove rows.
 * Every change fires `onChange` with the next `checks` array — these tests
 * pin that contract.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'

import CheckBuilder from '../../src/components/scanners/CheckBuilder.jsx'


// Minimal check-types catalogue mirroring the backend cve_schema.
const CHECK_TYPES = [
  {
    type: 'file_exists',
    label: 'File exists',
    required: ['path'],
    fields: { path: { type: 'string', placeholder: '~/.claude/settings.json' } },
  },
  {
    type: 'port_open',
    label: 'TCP port open',
    // `host` is required AND has a default — so type-selection should seed it.
    // `port` is required but has no default — so it should be left unset.
    required: ['host', 'port'],
    fields: {
      host: { type: 'string', default: '127.0.0.1' },
      port: { type: 'integer', min: 1, max: 65535 },
    },
  },
]


describe('<CheckBuilder /> — empty state', () => {
  it('renders the empty placeholder when there are no checks', () => {
    render(<CheckBuilder checks={[]} checkTypes={CHECK_TYPES} onChange={() => {}} />)
    expect(screen.getByText('No checks yet.')).toBeInTheDocument()
  })

  it('renders the "Add check" button even when empty', () => {
    render(<CheckBuilder checks={[]} checkTypes={CHECK_TYPES} onChange={() => {}} />)
    expect(screen.getByRole('button', { name: /add check/i })).toBeInTheDocument()
  })
})


describe('<CheckBuilder /> — adding a check', () => {
  it('calls onChange with a new empty check appended when "Add check" is clicked', () => {
    const onChange = vi.fn()
    render(<CheckBuilder checks={[]} checkTypes={CHECK_TYPES} onChange={onChange} />)

    fireEvent.click(screen.getByRole('button', { name: /add check/i }))

    expect(onChange).toHaveBeenCalledOnce()
    expect(onChange).toHaveBeenCalledWith([{ type: '' }])
  })

  it('appends to existing checks rather than replacing them', () => {
    const onChange = vi.fn()
    const existing = [{ type: 'file_exists', path: '/etc/passwd' }]
    render(
      <CheckBuilder checks={existing} checkTypes={CHECK_TYPES} onChange={onChange} />,
    )

    fireEvent.click(screen.getByRole('button', { name: /add check/i }))

    expect(onChange).toHaveBeenCalledWith([
      { type: 'file_exists', path: '/etc/passwd' },
      { type: '' },
    ])
  })
})


describe('<CheckBuilder /> — populated state', () => {
  it('renders one row per check', () => {
    const checks = [
      { type: 'file_exists', path: '/a' },
      { type: 'port_open', host: '127.0.0.1', port: 8080 },
    ]
    render(
      <CheckBuilder checks={checks} checkTypes={CHECK_TYPES} onChange={() => {}} />,
    )
    // Every row has its own type-select dropdown.
    const selects = screen.getAllByRole('combobox')
    expect(selects).toHaveLength(2)
  })

  it('hides the empty placeholder when checks exist', () => {
    render(
      <CheckBuilder
        checks={[{ type: 'file_exists', path: '/x' }]}
        checkTypes={CHECK_TYPES}
        onChange={() => {}}
      />,
    )
    expect(screen.queryByText('No checks yet.')).not.toBeInTheDocument()
  })

  it('renders the per-type fields when a type is selected', () => {
    render(
      <CheckBuilder
        checks={[{ type: 'file_exists', path: '/etc/passwd' }]}
        checkTypes={CHECK_TYPES}
        onChange={() => {}}
      />,
    )
    // The "path" field should be rendered with the existing value.
    const input = screen.getByDisplayValue('/etc/passwd')
    expect(input).toBeInTheDocument()
  })
})


describe('<CheckBuilder /> — type selection seeds defaults', () => {
  it('switching to port_open seeds host with the schema default 127.0.0.1', () => {
    const onChange = vi.fn()
    render(
      <CheckBuilder
        checks={[{ type: '' }]}
        checkTypes={CHECK_TYPES}
        onChange={onChange}
      />,
    )

    const select = screen.getByRole('combobox')
    fireEvent.change(select, { target: { value: 'port_open' } })

    expect(onChange).toHaveBeenCalledOnce()
    const newChecks = onChange.mock.calls[0][0]
    expect(newChecks).toEqual([
      { type: 'port_open', description: '', host: '127.0.0.1' },
    ])
  })
})


describe('<CheckBuilder /> — removing a check', () => {
  it('calls onChange with the row removed', () => {
    const onChange = vi.fn()
    const checks = [
      { type: 'file_exists', path: '/a' },
      { type: 'file_exists', path: '/b' },
    ]
    render(
      <CheckBuilder checks={checks} checkTypes={CHECK_TYPES} onChange={onChange} />,
    )

    // Find each row's remove button (it has title="Remove check").
    const removeButtons = screen.getAllByTitle('Remove check')
    fireEvent.click(removeButtons[0])

    expect(onChange).toHaveBeenCalledWith([{ type: 'file_exists', path: '/b' }])
  })
})


describe('<CheckBuilder /> — editing a field', () => {
  it('typing into the path input fires onChange with the updated row', () => {
    const onChange = vi.fn()
    render(
      <CheckBuilder
        checks={[{ type: 'file_exists', path: '/old' }]}
        checkTypes={CHECK_TYPES}
        onChange={onChange}
      />,
    )

    const input = screen.getByDisplayValue('/old')
    fireEvent.change(input, { target: { value: '/new/path' } })

    expect(onChange).toHaveBeenCalled()
    const last = onChange.mock.calls[onChange.mock.calls.length - 1][0]
    expect(last).toEqual([{ type: 'file_exists', path: '/new/path' }])
  })
})
