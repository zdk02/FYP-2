import { useEffect, useState } from 'react'
import { Save, Loader2, Plus, Trash2 } from 'lucide-react'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

function linesToArr(s) {
  return String(s || '')
    .split('\n')
    .map((v) => v.trim())
    .filter(Boolean)
}
function arrToLines(arr) {
  return Array.isArray(arr) ? arr.join('\n') : arr || ''
}

function PatternList({ patterns = [], onChange }) {
  const add = () =>
    onChange([
      ...patterns,
      { pattern: '', description: '', severity: 'medium', related_cve: '' },
    ])
  const updateAt = (i, next) =>
    onChange(patterns.map((p, idx) => (idx === i ? next : p)))
  const removeAt = (i) => onChange(patterns.filter((_, idx) => idx !== i))
  return (
    <div className="space-y-2">
      {patterns.map((p, i) => (
        <div
          key={i}
          className="border border-dark-800 rounded-lg p-3 space-y-2 bg-dark-900/50"
        >
          <div className="flex items-center gap-2">
            <input
              className="input font-mono text-xs"
              placeholder="Regex pattern"
              value={p.pattern || ''}
              onChange={(e) =>
                updateAt(i, { ...p, pattern: e.target.value })
              }
            />
            <select
              className="input appearance-none max-w-[140px]"
              value={p.severity || 'medium'}
              onChange={(e) =>
                updateAt(i, { ...p, severity: e.target.value })
              }
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => removeAt(i)}
              className="btn btn-ghost btn-sm text-red-400"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
          <input
            className="input text-xs"
            placeholder="Description"
            value={p.description || ''}
            onChange={(e) =>
              updateAt(i, { ...p, description: e.target.value })
            }
          />
          <input
            className="input font-mono text-xs"
            placeholder="Related CVE (optional)"
            value={p.related_cve || ''}
            onChange={(e) =>
              updateAt(i, { ...p, related_cve: e.target.value })
            }
          />
        </div>
      ))}
      <button
        type="button"
        onClick={add}
        className="btn btn-secondary btn-sm"
      >
        <Plus className="w-4 h-4" /> Add pattern
      </button>
    </div>
  )
}

export default function GlobalsPanel({ globals, onSave, isSaving }) {
  const [form, setForm] = useState({
    dangerous_config_patterns: [],
    remote_probe_paths: [],
    websocket_probe_ports: [],
    interesting_headers: [],
  })

  useEffect(() => {
    if (globals) {
      setForm({
        dangerous_config_patterns: globals.dangerous_config_patterns || [],
        remote_probe_paths: globals.remote_probe_paths || [],
        websocket_probe_ports: globals.websocket_probe_ports || [],
        interesting_headers: globals.interesting_headers || [],
      })
    }
  }, [globals])

  const submit = (e) => {
    e.preventDefault()
    onSave(form)
  }

  return (
    <form onSubmit={submit} className="space-y-6">
      <div>
        <div className="text-xs uppercase tracking-wide text-dark-500 mb-2">
          Dangerous config patterns
        </div>
        <PatternList
          patterns={form.dangerous_config_patterns}
          onChange={(v) =>
            setForm((f) => ({ ...f, dangerous_config_patterns: v }))
          }
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="text-xs text-dark-400 mb-1 block">
            Remote probe paths (one per line)
          </label>
          <textarea
            className="input min-h-[120px] font-mono text-xs"
            value={arrToLines(form.remote_probe_paths)}
            onChange={(e) =>
              setForm((f) => ({
                ...f,
                remote_probe_paths: linesToArr(e.target.value),
              }))
            }
          />
        </div>
        <div>
          <label className="text-xs text-dark-400 mb-1 block">
            WebSocket probe ports (one per line, numbers)
          </label>
          <textarea
            className="input min-h-[120px] font-mono text-xs"
            value={(form.websocket_probe_ports || []).join('\n')}
            onChange={(e) =>
              setForm((f) => ({
                ...f,
                websocket_probe_ports: linesToArr(e.target.value)
                  .map((v) => Number(v))
                  .filter((v) => !Number.isNaN(v)),
              }))
            }
          />
        </div>
        <div>
          <label className="text-xs text-dark-400 mb-1 block">
            Interesting headers (one per line)
          </label>
          <textarea
            className="input min-h-[120px] font-mono text-xs"
            value={arrToLines(form.interesting_headers)}
            onChange={(e) =>
              setForm((f) => ({
                ...f,
                interesting_headers: linesToArr(e.target.value),
              }))
            }
          />
        </div>
      </div>

      <div className="flex justify-end">
        <button type="submit" className="btn btn-primary" disabled={isSaving}>
          {isSaving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" /> Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" /> Save Globals
            </>
          )}
        </button>
      </div>
    </form>
  )
}
