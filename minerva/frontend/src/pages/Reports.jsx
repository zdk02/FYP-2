import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  FileText, Download, Eye, Calendar, AlertTriangle, Search,
  Plus, Trash2, Loader2, X, FileCode, FileJson, FileType,
} from 'lucide-react'
import { reportsApi, campaignsApi } from '../services/api'
import { format } from 'date-fns'
import toast from 'react-hot-toast'


const GRADE_COLOR = {
  A: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  B: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
  C: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  D: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  F: 'bg-red-500/15 text-red-400 border-red-500/40',
}


function GenerateModal({ open, onClose }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    campaign_id: '', name: '', client_name: '',
    subtitle: '', include_evidence: true,
  })
  const { data: campaigns } = useQuery({
    queryKey: ['campaigns-all'],
    queryFn: () => campaignsApi.getAll(),
    enabled: open,
  })
  const mut = useMutation({
    mutationFn: (body) => reportsApi.generate(body),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['reports'] })
      const grade = data?.risk?.grade
      toast.success(`Report generated${grade ? ` — Grade ${grade}` : ''}`)
      onClose()
    },
    onError: (e) => toast.error(
      e?.response?.data?.error || 'Failed to generate report'),
  })

  if (!open) return null
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))
  const submit = (e) => {
    e.preventDefault()
    if (!form.campaign_id) {
      toast.error('Select a campaign first')
      return
    }
    mut.mutate(form)
  }

  const list = campaigns?.campaigns || campaigns || []

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 overflow-auto bg-black/60">
      <form onSubmit={submit}
            className="w-full max-w-xl bg-dark-900 border border-dark-700 rounded-xl shadow-2xl my-10">
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-800">
          <h2 className="text-lg font-semibold text-white">Generate Pentest Report</h2>
          <button type="button" onClick={onClose}
                  className="text-dark-400 hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="text-xs text-dark-400">Campaign *</label>
            <select className="input appearance-none" required
                    value={form.campaign_id}
                    onChange={(e) => set('campaign_id', e.target.value)}>
              <option value="">— select —</option>
              {list.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-dark-400">Report title</label>
              <input className="input" value={form.name}
                     onChange={(e) => set('name', e.target.value)}
                     placeholder="e.g. Q3 MCP Pentest" />
            </div>
            <div>
              <label className="text-xs text-dark-400">Client name</label>
              <input className="input" value={form.client_name}
                     onChange={(e) => set('client_name', e.target.value)}
                     placeholder="e.g. Acme Corp" />
            </div>
          </div>
          <div>
            <label className="text-xs text-dark-400">Subtitle (optional)</label>
            <input className="input" value={form.subtitle}
                   onChange={(e) => set('subtitle', e.target.value)} />
          </div>
          <label className="inline-flex items-center gap-2 text-sm text-dark-300">
            <input type="checkbox" checked={form.include_evidence}
                   onChange={(e) => set('include_evidence', e.target.checked)} />
            Include raw evidence in report
          </label>
        </div>
        <div className="px-6 py-4 border-t border-dark-800 flex justify-end gap-2">
          <button type="button" onClick={onClose}
                  className="btn btn-secondary" disabled={mut.isPending}>Cancel</button>
          <button type="submit" className="btn btn-primary"
                  disabled={mut.isPending}>
            {mut.isPending
              ? (<><Loader2 className="w-4 h-4 animate-spin" /> Generating...</>)
              : (<><Plus className="w-4 h-4" /> Generate</>)}
          </button>
        </div>
      </form>
    </div>
  )
}


async function downloadBlob(id, fmt, filename) {
  try {
    const resp = await reportsApi.download(id, fmt)
    const blob = new Blob([resp.data],
      { type: resp.headers['content-type'] || 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
  } catch (e) {
    toast.error('Download failed: ' + (e?.message || 'unknown'))
  }
}


export default function Reports() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [modalOpen, setModalOpen] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.getAll(),
  })
  const delMut = useMutation({
    mutationFn: (id) => reportsApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['reports'] })
      toast.success('Report deleted')
    },
    onError: () => toast.error('Delete failed'),
  })

  const all = data?.reports || []
  const reports = all.filter((r) =>
    !search || (r.name || '').toLowerCase().includes(search.toLowerCase()))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-aegis-400" />
            Reports
          </h1>
          <p className="text-dark-400 text-sm mt-1">
            {all.length} report{all.length === 1 ? '' : 's'} · HTML · PDF · JSON · SARIF
          </p>
        </div>
        <button onClick={() => setModalOpen(true)} className="btn btn-primary">
          <Plus className="w-4 h-4" /> Generate from Campaign
        </button>
      </div>

      <div className="relative w-96 max-w-full">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
        <input type="text" placeholder="Search reports..." value={search}
               onChange={(e) => setSearch(e.target.value)}
               className="input pl-10" />
      </div>

      {isLoading ? (
        <div className="text-dark-400 text-sm">Loading...</div>
      ) : reports.length === 0 ? (
        <div className="card">
          <div className="card-body text-center py-12 text-dark-400">
            <FileText className="w-10 h-10 mx-auto mb-3 opacity-50" />
            <p>No reports yet.</p>
            <p className="text-xs text-dark-500 mt-1">
              Complete a campaign, then click <b>Generate from Campaign</b> above.
            </p>
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="card-body overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-dark-500 border-b border-dark-800">
                <tr>
                  <th className="py-2 pr-3">Report</th>
                  <th className="py-2 pr-3">Campaign</th>
                  <th className="py-2 pr-3">Grade</th>
                  <th className="py-2 pr-3">Findings</th>
                  <th className="py-2 pr-3">Created</th>
                  <th className="py-2 pr-3 text-right">Download</th>
                  <th className="py-2 pr-3 text-right"></th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <tr key={r.id} className="border-b border-dark-800/60 hover:bg-dark-800/30">
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-aegis-400" />
                        <Link to={`/reports/${r.id}`}
                              className="text-white hover:underline">{r.name}</Link>
                      </div>
                    </td>
                    <td className="py-2 pr-3 text-dark-300">{r.campaign?.name || '—'}</td>
                    <td className="py-2 pr-3">
                      {r.risk_grade ? (
                        <span className={`inline-block px-2 py-0.5 text-xs font-semibold rounded border ${GRADE_COLOR[r.risk_grade] || ''}`}>
                          {r.risk_grade}{r.risk_score != null ? ` · ${r.risk_score}` : ''}
                        </span>
                      ) : '—'}
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-1.5 text-xs">
                        <span className="text-red-400">{r.critical_findings}</span>/
                        <span className="text-orange-400">{r.high_findings}</span>/
                        <span className="text-yellow-400">{r.medium_findings}</span>/
                        <span className="text-sky-400">{r.low_findings}</span>
                      </div>
                    </td>
                    <td className="py-2 pr-3 text-dark-400">
                      <span className="inline-flex items-center gap-1 text-xs">
                        <Calendar className="w-3 h-3" />
                        {r.created_at ? format(new Date(r.created_at), 'MMM d, yyyy') : '—'}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-right">
                      <div className="inline-flex items-center gap-1">
                        <button onClick={() => downloadBlob(r.id, 'html', `${r.name}.html`)}
                                className="btn btn-ghost btn-sm" title="Download HTML">
                          <FileCode className="w-4 h-4" />
                        </button>
                        <button onClick={() => downloadBlob(r.id, 'pdf', `${r.name}.pdf`)}
                                className="btn btn-ghost btn-sm" title="Download PDF">
                          <FileType className="w-4 h-4" />
                        </button>
                        <button onClick={() => downloadBlob(r.id, 'json', `${r.name}.json`)}
                                className="btn btn-ghost btn-sm" title="Download JSON">
                          <FileJson className="w-4 h-4" />
                        </button>
                        <button onClick={() => downloadBlob(r.id, 'sarif', `${r.name}.sarif`)}
                                className="btn btn-ghost btn-sm" title="Download SARIF">
                          <Download className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                    <td className="py-2 pr-3 text-right">
                      <button onClick={() => window.confirm(`Delete "${r.name}"?`) && delMut.mutate(r.id)}
                              className="btn btn-ghost btn-sm text-red-400">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <GenerateModal open={modalOpen} onClose={() => setModalOpen(false)} />
    </div>
  )
}
