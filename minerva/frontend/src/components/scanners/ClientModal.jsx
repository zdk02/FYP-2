import { useEffect, useState } from 'react'
import { X, Save, Loader2 } from 'lucide-react'

const CLIENT_TYPES = [
  'cli',
  'ide',
  'ide_extension',
  'desktop_app',
  'browser_extension',
  'web',
  'mcp_server',
  'proxy',
  'debug_tool',
  'other',
]

function emptyClient() {
  return {
    key: '',
    display_name: '',
    vendor: '',
    type: 'cli',
    detection: {
      process_names: [],
      npm_package: '',
      config_paths: [],
      version_commands: [],
      indicators: [],
    },
  }
}

function arrToLines(arr) {
  return Array.isArray(arr) ? arr.join('\n') : arr || ''
}
function linesToArr(s) {
  return String(s || '')
    .split('\n')
    .map((v) => v.trim())
    .filter(Boolean)
}

export default function ClientModal({
  open,
  initial,
  isNew,
  onClose,
  onSave,
  isSaving,
}) {
  const [form, setForm] = useState(emptyClient())

  useEffect(() => {
    if (open) {
      const base = emptyClient()
      const init = initial || {}
      setForm({
        ...base,
        ...init,
        detection: { ...base.detection, ...(init.detection || {}) },
      })
    }
  }, [open, initial])

  if (!open) return null

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))
  const setDet = (k, v) =>
    setForm((f) => ({ ...f, detection: { ...f.detection, [k]: v } }))

  const submit = (e) => {
    e.preventDefault()
    onSave(form)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 overflow-auto bg-black/60">
      <form
        onSubmit={submit}
        className="w-full max-w-2xl bg-dark-900 border border-dark-700 rounded-xl shadow-2xl my-10"
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-800">
          <h2 className="text-lg font-semibold text-white">
            {isNew ? 'Add Client' : `Edit ${initial?.display_name || initial?.key}`}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-dark-400 hover:text-white p-1 rounded"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-dark-400">Key (slug) *</label>
              <input
                className="input font-mono"
                value={form.key}
                onChange={(e) =>
                  set(
                    'key',
                    e.target.value
                      .toLowerCase()
                      .replace(/[^a-z0-9_-]/g, '_')
                  )
                }
                disabled={!isNew}
                required
              />
            </div>
            <div>
              <label className="text-xs text-dark-400">Type *</label>
              <select
                className="input appearance-none"
                value={form.type}
                onChange={(e) => set('type', e.target.value)}
              >
                {CLIENT_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <div className="col-span-2">
              <label className="text-xs text-dark-400">Display name *</label>
              <input
                className="input"
                value={form.display_name}
                onChange={(e) => set('display_name', e.target.value)}
                required
              />
            </div>
            <div className="col-span-2">
              <label className="text-xs text-dark-400">Vendor *</label>
              <input
                className="input"
                value={form.vendor}
                onChange={(e) => set('vendor', e.target.value)}
                required
              />
            </div>
          </div>

          <div className="border-t border-dark-800 pt-3 space-y-3">
            <div className="text-xs uppercase tracking-wide text-dark-500">
              Detection
            </div>
            <div>
              <label className="text-xs text-dark-400">
                Process names (one per line)
              </label>
              <textarea
                className="input min-h-[60px] font-mono text-xs"
                value={arrToLines(form.detection.process_names)}
                onChange={(e) =>
                  setDet('process_names', linesToArr(e.target.value))
                }
              />
            </div>
            <div>
              <label className="text-xs text-dark-400">
                npm package (optional)
              </label>
              <input
                className="input font-mono"
                value={form.detection.npm_package || ''}
                onChange={(e) => setDet('npm_package', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-dark-400">
                Config paths (one per line)
              </label>
              <textarea
                className="input min-h-[60px] font-mono text-xs"
                value={arrToLines(form.detection.config_paths)}
                onChange={(e) =>
                  setDet('config_paths', linesToArr(e.target.value))
                }
              />
            </div>
            <div>
              <label className="text-xs text-dark-400">
                Version commands (one per line)
              </label>
              <textarea
                className="input min-h-[60px] font-mono text-xs"
                value={arrToLines(form.detection.version_commands)}
                onChange={(e) =>
                  setDet('version_commands', linesToArr(e.target.value))
                }
              />
            </div>
            <div>
              <label className="text-xs text-dark-400">
                Extension / indicator substrings (one per line)
              </label>
              <textarea
                className="input min-h-[60px] font-mono text-xs"
                value={arrToLines(form.detection.indicators)}
                onChange={(e) => setDet('indicators', linesToArr(e.target.value))}
              />
            </div>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-dark-800 flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="btn btn-secondary"
            disabled={isSaving}
          >
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={isSaving}>
            {isSaving ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> Saving...
              </>
            ) : (
              <>
                <Save className="w-4 h-4" /> Save
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  )
}
