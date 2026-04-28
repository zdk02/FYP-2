import { useEffect, useState } from 'react'
import { X, Save, Loader2, Plus, Trash2 } from 'lucide-react'
import CheckBuilder from './CheckBuilder'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

function emptyCve() {
  return {
    id: '',
    title: '',
    severity: 'medium',
    cvss: '',
    cvss_vector: '',
    cwe: '',
    affected_versions: '',
    fixed_version: '',
    disclosure_date: '',
    reported_by: '',
    description: '',
    exploitation: '',
    remediation: '',
    references: [],
    env_checks: [],
    active_checks: [],
  }
}

function TabButton({ active, onClick, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-3 py-1.5 text-sm rounded-t-lg border-b-2 transition-colors ${
        active
          ? 'border-aegis-500 text-white'
          : 'border-transparent text-dark-400 hover:text-white'
      }`}
    >
      {children}
    </button>
  )
}

function RefList({ refs, onChange }) {
  const add = () => onChange([...(refs || []), ''])
  const updateAt = (i, v) =>
    onChange(refs.map((r, idx) => (idx === i ? v : r)))
  const removeAt = (i) => onChange(refs.filter((_, idx) => idx !== i))
  return (
    <div className="space-y-2">
      {(refs || []).map((r, i) => (
        <div key={i} className="flex gap-2">
          <input
            className="input"
            value={r}
            onChange={(e) => updateAt(i, e.target.value)}
            placeholder="https://..."
          />
          <button
            type="button"
            onClick={() => removeAt(i)}
            className="btn btn-ghost btn-sm text-red-400"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      ))}
      <button type="button" onClick={add} className="btn btn-secondary btn-sm">
        <Plus className="w-4 h-4" /> Add reference
      </button>
    </div>
  )
}

export default function CveModal({
  open,
  initial,
  isNew,
  checkTypes = [],
  onClose,
  onSave,
  isSaving,
}) {
  const [tab, setTab] = useState('identity')
  const [form, setForm] = useState(emptyCve())

  useEffect(() => {
    if (open) {
      setTab('identity')
      setForm({ ...emptyCve(), ...(initial || {}) })
    }
  }, [open, initial])

  if (!open) return null

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))

  const submit = (e) => {
    e.preventDefault()
    // Normalize cvss to number or omit
    const out = { ...form }
    if (out.cvss === '' || out.cvss === null || out.cvss === undefined) {
      delete out.cvss
    } else {
      const n = Number(out.cvss)
      if (!Number.isNaN(n)) out.cvss = n
    }
    out.references = (out.references || []).filter(Boolean)
    onSave(out)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 overflow-auto bg-black/60">
      <form
        onSubmit={submit}
        className="w-full max-w-4xl bg-dark-900 border border-dark-700 rounded-xl shadow-2xl my-10"
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-800">
          <h2 className="text-lg font-semibold text-white">
            {isNew ? 'Add CVE' : `Edit ${initial?.id || 'CVE'}`}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-dark-400 hover:text-white p-1 rounded"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 pt-3 border-b border-dark-800 flex gap-1 flex-wrap">
          <TabButton active={tab === 'identity'} onClick={() => setTab('identity')}>
            Identity
          </TabButton>
          <TabButton active={tab === 'versions'} onClick={() => setTab('versions')}>
            Versions
          </TabButton>
          <TabButton
            active={tab === 'description'}
            onClick={() => setTab('description')}
          >
            Description
          </TabButton>
          <TabButton active={tab === 'env'} onClick={() => setTab('env')}>
            Env Checks ({form.env_checks?.length || 0})
          </TabButton>
          <TabButton active={tab === 'active'} onClick={() => setTab('active')}>
            Active Checks ({form.active_checks?.length || 0})
          </TabButton>
        </div>

        <div className="px-6 py-4 space-y-4 min-h-[320px]">
          {tab === 'identity' && (
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2 md:col-span-1">
                <label className="text-xs text-dark-400">CVE ID *</label>
                <input
                  className="input font-mono"
                  value={form.id}
                  onChange={(e) => set('id', e.target.value.toUpperCase())}
                  placeholder="CVE-2026-12345"
                  disabled={!isNew}
                  required
                />
              </div>
              <div className="col-span-2 md:col-span-1">
                <label className="text-xs text-dark-400">Severity *</label>
                <select
                  className="input appearance-none"
                  value={form.severity}
                  onChange={(e) => set('severity', e.target.value)}
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <div className="col-span-2">
                <label className="text-xs text-dark-400">Title *</label>
                <input
                  className="input"
                  value={form.title}
                  onChange={(e) => set('title', e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">CVSS score</label>
                <input
                  className="input"
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={form.cvss}
                  onChange={(e) => set('cvss', e.target.value)}
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">CWE</label>
                <input
                  className="input"
                  value={form.cwe}
                  onChange={(e) => set('cwe', e.target.value)}
                  placeholder="CWE-78"
                />
              </div>
              <div className="col-span-2">
                <label className="text-xs text-dark-400">CVSS vector</label>
                <input
                  className="input font-mono"
                  value={form.cvss_vector}
                  onChange={(e) => set('cvss_vector', e.target.value)}
                />
              </div>
            </div>
          )}

          {tab === 'versions' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-dark-400">Affected versions</label>
                <input
                  className="input"
                  value={form.affected_versions}
                  onChange={(e) => set('affected_versions', e.target.value)}
                  placeholder="< 2.0.31"
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">Fixed version</label>
                <input
                  className="input"
                  value={form.fixed_version}
                  onChange={(e) => set('fixed_version', e.target.value)}
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">Disclosure date</label>
                <input
                  className="input"
                  type="date"
                  value={form.disclosure_date}
                  onChange={(e) => set('disclosure_date', e.target.value)}
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">Reported by</label>
                <input
                  className="input"
                  value={form.reported_by}
                  onChange={(e) => set('reported_by', e.target.value)}
                />
              </div>
            </div>
          )}

          {tab === 'description' && (
            <div className="space-y-3">
              <div>
                <label className="text-xs text-dark-400">Description *</label>
                <textarea
                  className="input min-h-[100px]"
                  value={form.description}
                  onChange={(e) => set('description', e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">Exploitation</label>
                <textarea
                  className="input min-h-[80px]"
                  value={form.exploitation}
                  onChange={(e) => set('exploitation', e.target.value)}
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">Remediation</label>
                <textarea
                  className="input min-h-[60px]"
                  value={form.remediation}
                  onChange={(e) => set('remediation', e.target.value)}
                />
              </div>
              <div>
                <label className="text-xs text-dark-400">References</label>
                <RefList
                  refs={form.references}
                  onChange={(refs) => set('references', refs)}
                />
              </div>
            </div>
          )}

          {tab === 'env' && (
            <div>
              <p className="text-xs text-dark-500 mb-3">
                Environment checks verify that conditions making the CVE exploitable
                exist on the target (Layer 2). Passing any bumps confidence to
                "high".
              </p>
              <CheckBuilder
                checks={form.env_checks || []}
                checkTypes={checkTypes}
                onChange={(v) => set('env_checks', v)}
              />
            </div>
          )}

          {tab === 'active' && (
            <div>
              <p className="text-xs text-dark-500 mb-3">
                Active checks are non-destructive probes that prove the
                vulnerability is present (Layer 3). Passing any bumps confidence to
                "confirmed".
              </p>
              <CheckBuilder
                checks={form.active_checks || []}
                checkTypes={checkTypes}
                onChange={(v) => set('active_checks', v)}
              />
            </div>
          )}
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
