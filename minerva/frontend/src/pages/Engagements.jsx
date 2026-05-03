import { useEffect, useState } from 'react'
import {
  Briefcase, Plus, Power, RotateCcw, Upload, Shield, ShieldAlert,
  Trash2, Check, X, FileText, ExternalLink,
} from 'lucide-react'
import { engagementsApi } from '../services/api'
import { useEngagementStore } from '../stores/engagementStore'

const empty = {
  name: '',
  client_name: '',
  description: '',
  signed_off_by: '',
  rules_of_engagement: '',
  authorized_targets: ['127.0.0.1', 'localhost'],
  max_requests: 100000,
  max_wall_seconds: 14400,
  max_concurrent: 4,
  safe_mode: false,
  dry_run_default: false,
  notify_min_severity: 'high',
  health_threshold_x: 3.0,
  status: 'active',
  is_active_default: false,
  webhook_url: '',
  slack_url: '',
  teams_url: '',
  time_window_start: '',
  time_window_end: '',
}

export default function Engagements() {
  const { list, active, load, kill, revive, resetQuota, activate } = useEngagementStore()
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState(empty)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    load()
  }, [load])

  const startCreate = () => {
    setEditing('new')
    setForm(empty)
    setError(null)
  }

  const startEdit = (e) => {
    setEditing(e.id)
    setForm({
      ...empty,
      ...e,
      authorized_targets: e.authorized_targets || [],
      time_window_start: e.time_window_start ? e.time_window_start.slice(0, 16) : '',
      time_window_end: e.time_window_end ? e.time_window_end.slice(0, 16) : '',
    })
    setError(null)
  }

  const cancel = () => {
    setEditing(null)
    setError(null)
  }

  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      const body = {
        ...form,
        time_window_start: form.time_window_start || null,
        time_window_end: form.time_window_end || null,
        max_requests: parseInt(form.max_requests, 10),
        max_wall_seconds: parseInt(form.max_wall_seconds, 10),
        max_concurrent: parseInt(form.max_concurrent, 10),
        health_threshold_x: parseFloat(form.health_threshold_x),
      }
      if (editing === 'new') {
        await engagementsApi.create(body)
      } else {
        await engagementsApi.update(editing, body)
      }
      await load()
      setEditing(null)
    } catch (e) {
      setError(e.response?.data?.error || e.message)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (e) => {
    if (!confirm(`Delete engagement "${e.name}"? This is permanent.`)) return
    await engagementsApi.delete(e.id)
    await load()
  }

  const uploadSow = async (e, file) => {
    if (!file) return
    await engagementsApi.uploadSow(e.id, file)
    await load()
  }

  const updateAllow = (idx, value) => {
    const arr = [...form.authorized_targets]
    arr[idx] = value
    setForm({ ...form, authorized_targets: arr })
  }
  const addAllow = () => setForm({ ...form, authorized_targets: [...form.authorized_targets, ''] })
  const removeAllow = (idx) =>
    setForm({ ...form, authorized_targets: form.authorized_targets.filter((_, i) => i !== idx) })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Briefcase className="w-6 h-6" /> Engagements
          </h1>
          <p className="text-sm text-dark-400">
            Legal authorization scope. Every attack run is bound to an engagement —
            out-of-scope targets are hard-rejected by the preflight gate.
          </p>
        </div>
        <button
          onClick={startCreate}
          className="btn btn-primary flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> New Engagement
        </button>
      </div>

      {editing && (
        <div className="card p-4 space-y-4 border-2 border-cyan-700">
          <h2 className="text-lg font-semibold text-white">
            {editing === 'new' ? 'Create engagement' : `Edit: ${form.name}`}
          </h2>
          {error && (
            <div className="px-3 py-2 bg-red-900/40 border border-red-700 text-red-100 text-sm rounded">
              {error}
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <Field label="Name *">
              <input className="input" value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Client">
              <input className="input" value={form.client_name || ''}
                onChange={(e) => setForm({ ...form, client_name: e.target.value })} />
            </Field>
            <Field label="Signed off by *">
              <input className="input" placeholder="Name + role of authoriser"
                value={form.signed_off_by || ''}
                onChange={(e) => setForm({ ...form, signed_off_by: e.target.value })} />
            </Field>
            <Field label="Status">
              <select className="input" value={form.status}
                onChange={(e) => setForm({ ...form, status: e.target.value })}>
                <option value="active">active</option>
                <option value="paused">paused</option>
                <option value="completed">completed</option>
                <option value="archived">archived</option>
              </select>
            </Field>
          </div>

          <Field label="Description">
            <textarea className="input min-h-[60px]" value={form.description || ''}
              onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </Field>

          <Field label="Rules of engagement">
            <textarea className="input min-h-[80px]"
              value={form.rules_of_engagement || ''}
              onChange={(e) => setForm({ ...form, rules_of_engagement: e.target.value })} />
          </Field>

          <Field label="Authorized targets (host / IP / CIDR / *.domain) *">
            <div className="space-y-2">
              {form.authorized_targets.map((t, i) => (
                <div key={i} className="flex gap-2">
                  <input className="input flex-1" value={t}
                    onChange={(e) => updateAllow(i, e.target.value)} />
                  <button onClick={() => removeAllow(i)}
                    className="btn btn-sm btn-secondary">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              ))}
              <button onClick={addAllow} className="btn btn-sm btn-secondary flex items-center gap-1">
                <Plus className="w-3 h-3" /> Add allowlist entry
              </button>
            </div>
          </Field>

          <div className="grid grid-cols-3 gap-3">
            <Field label="Max requests">
              <input type="number" className="input" value={form.max_requests}
                onChange={(e) => setForm({ ...form, max_requests: e.target.value })} />
            </Field>
            <Field label="Max wall seconds">
              <input type="number" className="input" value={form.max_wall_seconds}
                onChange={(e) => setForm({ ...form, max_wall_seconds: e.target.value })} />
            </Field>
            <Field label="Max concurrent">
              <input type="number" className="input" value={form.max_concurrent}
                onChange={(e) => setForm({ ...form, max_concurrent: e.target.value })} />
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Window start">
              <input type="datetime-local" className="input"
                value={form.time_window_start}
                onChange={(e) => setForm({ ...form, time_window_start: e.target.value })} />
            </Field>
            <Field label="Window end">
              <input type="datetime-local" className="input"
                value={form.time_window_end}
                onChange={(e) => setForm({ ...form, time_window_end: e.target.value })} />
            </Field>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <label className="flex items-center gap-2 text-sm text-white">
              <input type="checkbox" checked={form.safe_mode}
                onChange={(e) => setForm({ ...form, safe_mode: e.target.checked })} />
              Safe mode (block RCE/RS/DoS)
            </label>
            <label className="flex items-center gap-2 text-sm text-white">
              <input type="checkbox" checked={form.dry_run_default}
                onChange={(e) => setForm({ ...form, dry_run_default: e.target.checked })} />
              Dry-run by default
            </label>
            <label className="flex items-center gap-2 text-sm text-white">
              <input type="checkbox" checked={form.is_active_default}
                onChange={(e) => setForm({ ...form, is_active_default: e.target.checked })} />
              Set as active default
            </label>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <Field label="Webhook URL">
              <input className="input" value={form.webhook_url || ''}
                onChange={(e) => setForm({ ...form, webhook_url: e.target.value })} />
            </Field>
            <Field label="Slack webhook">
              <input className="input" value={form.slack_url || ''}
                onChange={(e) => setForm({ ...form, slack_url: e.target.value })} />
            </Field>
            <Field label="Teams webhook">
              <input className="input" value={form.teams_url || ''}
                onChange={(e) => setForm({ ...form, teams_url: e.target.value })} />
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Notify min severity">
              <select className="input" value={form.notify_min_severity}
                onChange={(e) => setForm({ ...form, notify_min_severity: e.target.value })}>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
              </select>
            </Field>
            <Field label="Health threshold ×baseline">
              <input type="number" step="0.5" className="input" value={form.health_threshold_x}
                onChange={(e) => setForm({ ...form, health_threshold_x: e.target.value })} />
            </Field>
          </div>

          <div className="flex gap-2 pt-2">
            <button onClick={save} disabled={busy}
              className="btn btn-primary flex items-center gap-2">
              <Check className="w-4 h-4" /> {busy ? 'Saving…' : 'Save'}
            </button>
            <button onClick={cancel} className="btn btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {list.map((e) => (
          <div key={e.id}
            className={`card p-4 ${e.is_active_default ? 'border-2 border-emerald-700' : ''}`}>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  {e.is_killed ? (
                    <Power className="w-4 h-4 text-red-400" />
                  ) : e.is_active_default ? (
                    <Shield className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                  )}
                  <h3 className="text-white font-semibold">{e.name}</h3>
                  {e.is_active_default && (
                    <span className="px-1.5 py-0.5 rounded bg-emerald-800/60 text-emerald-100 text-xs">
                      ACTIVE
                    </span>
                  )}
                  {e.is_killed && (
                    <span className="px-1.5 py-0.5 rounded bg-red-800/60 text-red-100 text-xs">
                      KILLED
                    </span>
                  )}
                  {e.safe_mode && (
                    <span className="px-1.5 py-0.5 rounded bg-amber-800/60 text-amber-100 text-xs">
                      SAFE MODE
                    </span>
                  )}
                  {e.dry_run_default && (
                    <span className="px-1.5 py-0.5 rounded bg-blue-800/60 text-blue-100 text-xs">
                      DRY-RUN
                    </span>
                  )}
                </div>
                <div className="text-sm text-dark-300 mt-1">{e.client_name} · {e.signed_off_by}</div>
                <div className="text-xs text-dark-400 mt-2 flex flex-wrap gap-x-4 gap-y-1">
                  <span>Scope: {(e.authorized_targets || []).join(', ') || '(none)'}</span>
                  <span>Budget: {(e.current_requests || 0).toLocaleString()}/{(e.max_requests || 0).toLocaleString()}</span>
                  <span>Concurrent ≤ {e.max_concurrent}</span>
                  {e.sow_filename && (
                    <span className="flex items-center gap-1">
                      <FileText className="w-3 h-3" /> SOW: {e.sow_filename}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex gap-1">
                {!e.is_active_default && (
                  <button onClick={() => activate(e.id)}
                    className="btn btn-sm btn-secondary" title="Set as active default">
                    <Shield className="w-4 h-4" />
                  </button>
                )}
                {e.is_killed ? (
                  <button onClick={() => revive(e.id)}
                    className="btn btn-sm btn-secondary" title="Revive">
                    <RotateCcw className="w-4 h-4" />
                  </button>
                ) : (
                  <button onClick={() => kill(e.id)}
                    className="btn btn-sm btn-secondary" title="Kill switch">
                    <Power className="w-4 h-4" />
                  </button>
                )}
                <button onClick={() => resetQuota(e.id)}
                  className="btn btn-sm btn-secondary" title="Reset quota counter">
                  <RotateCcw className="w-4 h-4" />
                </button>
                <label className="btn btn-sm btn-secondary cursor-pointer" title="Upload SOW">
                  <Upload className="w-4 h-4" />
                  <input type="file" className="hidden"
                    accept=".pdf,.docx,.txt,.md"
                    onChange={(ev) => uploadSow(e, ev.target.files?.[0])} />
                </label>
                <button onClick={() => startEdit(e)}
                  className="btn btn-sm btn-secondary">Edit</button>
                <button onClick={() => remove(e)}
                  className="btn btn-sm btn-danger">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
        {list.length === 0 && (
          <div className="card p-8 text-center text-dark-400">
            No engagements yet. <button onClick={startCreate} className="text-cyan-400 underline">
              Create one →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="block text-xs font-medium text-dark-300 mb-1">{label}</span>
      {children}
    </label>
  )
}
