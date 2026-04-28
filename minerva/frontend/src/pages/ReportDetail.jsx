import { useEffect, useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  Download,
  Printer,
  AlertTriangle,
  CheckCircle,
  Shield,
  Loader2,
  Pencil,
  Save,
  X,
  Plus,
  Trash2,
  StickyNote,
  Building2,
  User as UserIcon,
} from 'lucide-react'
import { reportsApi } from '../services/api'
import toast from 'react-hot-toast'
import ReportAnalytics from '../components/reports/ReportAnalytics'

function downloadBlob(blob, filename) {
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
}

const SEVERITY_RING = {
  critical: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/40',
  high:     'bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/40',
  medium:   'bg-yellow-500/15 text-yellow-300 ring-1 ring-yellow-500/40',
  low:      'bg-blue-500/15 text-blue-300 ring-1 ring-blue-500/40',
  info:     'bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/40',
}

const CONF_COLOR = {
  confirmed: 'text-emerald-300',
  high:      'text-blue-300',
  medium:    'text-purple-300',
  low:       'text-slate-400',
}

function SectionHeader({ title, subtitle, icon: Icon, action }) {
  return (
    <div className="flex items-end justify-between border-b border-dark-800 pb-3 mb-4">
      <div className="flex items-center gap-3">
        {Icon && (
          <div className="w-9 h-9 rounded-lg bg-aegis-500/10 flex items-center justify-center">
            <Icon className="w-4 h-4 text-aegis-400" />
          </div>
        )}
        <div>
          <h2 className="text-base font-semibold text-white tracking-tight">{title}</h2>
          {subtitle && <p className="text-xs text-dark-500 mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  )
}

export default function ReportDetail() {
  const { id } = useParams()
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['report', id],
    queryFn: () => reportsApi.get(id),
  })

  const report = data
  const content = report?.content || {}
  const meta = content.meta || {}

  // Recommendations: prefer the analyst-edited override list, otherwise
  // surface the per-finding remediation strings.
  const baseRecs = useMemo(() => {
    if (Array.isArray(content.recommendations_override)) {
      return content.recommendations_override
    }
    const fromFindings = (content.findings || [])
      .map(f => f.remediation)
      .filter(Boolean)
    if (fromFindings.length) {
      return Array.from(new Set(fromFindings)).slice(0, 30)
    }
    if (Array.isArray(report?.recommendations)) return report.recommendations
    return []
  }, [content, report])

  // ---- Edit mode state -------------------------------------------------
  const [editMode, setEditMode] = useState(false)
  const [draft, setDraft] = useState({
    name: '', client_name: '', assessor: '',
    executive_summary: '', notes: '', recommendations: [],
  })

  useEffect(() => {
    if (!report) return
    setDraft({
      name: report.name || meta.title || '',
      client_name: meta.client_name || '',
      assessor: meta.assessor || '',
      executive_summary: content.executive_summary || '',
      notes: content.notes || '',
      recommendations: baseRecs,
    })
  }, [report?.id, editMode]) // re-seed draft when entering edit mode or switching reports

  const updateMutation = useMutation({
    mutationFn: (body) => reportsApi.update(id, body),
    onSuccess: () => {
      toast.success('Report updated')
      queryClient.invalidateQueries({ queryKey: ['report', id] })
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      setEditMode(false)
    },
    onError: (e) => toast.error(e.response?.data?.error || 'Failed to update report'),
  })

  const downloadMutation = useMutation({
    mutationFn: (format) => reportsApi.download(id, format),
    onSuccess: (response, format) => {
      const blob = new Blob([response.data], {
        type:
          format === 'pdf' ? 'application/pdf' :
          format === 'html' ? 'text/html' :
          format === 'sarif' ? 'application/sarif+json' :
          'application/json',
      })
      const slug = (report?.name || meta.title || 'report')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'report'
      const ext = format === 'sarif' ? 'sarif.json' : format
      downloadBlob(blob, `${slug}.${ext}`)
      toast.success(`Downloaded ${format.toUpperCase()} report`)
    },
    onError: (e) => toast.error(e.response?.data?.error || 'Failed to download report'),
  })

  const handlePrint = () => window.print()
  const handleExport = (format) => downloadMutation.mutate(format)

  const handleSave = () => {
    updateMutation.mutate({
      name: draft.name,
      client_name: draft.client_name,
      assessor: draft.assessor,
      executive_summary: draft.executive_summary,
      recommendations: draft.recommendations.filter(r => r.trim()),
      notes: draft.notes,
    })
  }

  const setRec = (i, value) => {
    const next = [...draft.recommendations]; next[i] = value
    setDraft({ ...draft, recommendations: next })
  }
  const addRec = () => setDraft({
    ...draft, recommendations: [...draft.recommendations, ''],
  })
  const removeRec = (i) => setDraft({
    ...draft,
    recommendations: draft.recommendations.filter((_, idx) => idx !== i),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner w-8 h-8" />
      </div>
    )
  }
  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-dark-400">
        <AlertTriangle className="w-12 h-12 mb-4" />
        <p>Report not found</p>
        <Link to="/reports" className="btn-secondary mt-4">Back to Reports</Link>
      </div>
    )
  }

  const findings = content.findings || report.findings || []

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* ---------- Header ---------- */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <Link to="/reports" className="btn-ghost p-2 mt-1" aria-label="Back to reports">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div className="min-w-0">
            {editMode ? (
              <input
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                className="input text-2xl font-bold w-full mb-2"
                placeholder="Report title"
              />
            ) : (
              <h1 className="text-2xl font-bold text-white tracking-tight leading-tight">
                {report.name || meta.title || 'Untitled Report'}
              </h1>
            )}
            <div className="flex items-center gap-3 mt-1 text-sm text-dark-400 flex-wrap">
              {report.campaign?.name && (
                <span className="inline-flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-dark-500" />
                  Campaign: <span className="text-dark-200">{report.campaign.name}</span>
                </span>
              )}
              {meta.generated_at && (
                <span className="inline-flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-dark-500" />
                  Generated {meta.generated_at}
                </span>
              )}
              {content.risk?.grade && (
                <span className="inline-flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-dark-500" />
                  Risk grade
                  <span className="font-bold text-white ml-1">{content.risk.grade}</span>
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0 print:hidden">
          {editMode ? (
            <>
              <button
                type="button"
                onClick={() => setEditMode(false)}
                disabled={updateMutation.isPending}
                className="btn-secondary"
              >
                <X className="w-4 h-4" />
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSave}
                disabled={updateMutation.isPending}
                className="btn-primary"
              >
                {updateMutation.isPending
                  ? <Loader2 className="w-4 h-4 animate-spin" />
                  : <Save className="w-4 h-4" />}
                Save changes
              </button>
            </>
          ) : (
            <>
              <button type="button" onClick={() => setEditMode(true)} className="btn-secondary">
                <Pencil className="w-4 h-4" />
                Edit
              </button>
              <button type="button" onClick={handlePrint} className="btn-secondary">
                <Printer className="w-4 h-4" />
                Print
              </button>
              <div className="hidden md:flex items-center gap-1 border border-dark-700 rounded-lg p-0.5">
                {['html', 'json', 'sarif'].map(fmt => (
                  <button key={fmt}
                    type="button"
                    onClick={() => handleExport(fmt)}
                    disabled={downloadMutation.isPending}
                    className="px-2.5 py-1.5 text-xs uppercase tracking-wide text-dark-300 hover:text-white hover:bg-dark-800 rounded transition-colors flex items-center gap-1.5">
                    {downloadMutation.isPending && downloadMutation.variables === fmt
                      ? <Loader2 className="w-3 h-3 animate-spin" />
                      : <Download className="w-3 h-3" />}
                    {fmt}
                  </button>
                ))}
              </div>
              <button
                type="button"
                onClick={() => handleExport('pdf')}
                disabled={downloadMutation.isPending}
                className="btn-primary"
              >
                {downloadMutation.isPending && downloadMutation.variables === 'pdf'
                  ? <Loader2 className="w-4 h-4 animate-spin" />
                  : <Download className="w-4 h-4" />}
                Export PDF
              </button>
            </>
          )}
        </div>
      </div>

      {/* ---------- Edit-mode meta inputs ---------- */}
      {editMode && (
        <div className="card p-5 space-y-4">
          <SectionHeader title="Report metadata"
            subtitle="Shows in the header of every export (PDF / HTML / JSON)"
            icon={Building2} />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="label text-xs flex items-center gap-1.5">
                <Building2 className="w-3 h-3" /> Client
              </label>
              <input
                value={draft.client_name}
                onChange={(e) => setDraft({ ...draft, client_name: e.target.value })}
                placeholder="e.g. Acme Corp"
                className="input w-full"
              />
            </div>
            <div>
              <label className="label text-xs flex items-center gap-1.5">
                <UserIcon className="w-3 h-3" /> Assessor
              </label>
              <input
                value={draft.assessor}
                onChange={(e) => setDraft({ ...draft, assessor: e.target.value })}
                placeholder="e.g. Minerva Framework v1.0"
                className="input w-full"
              />
            </div>
          </div>
        </div>
      )}

      {/* ---------- Executive Summary ---------- */}
      <section className="card p-5">
        <SectionHeader
          title="Executive Summary"
          subtitle="Plain-language assessment for stakeholders"
          icon={Shield}
        />
        {editMode ? (
          <textarea
            rows={8}
            value={draft.executive_summary}
            onChange={(e) => setDraft({ ...draft, executive_summary: e.target.value })}
            placeholder="Summarize the engagement: scope, key risks, the overall posture, and what the client should do next…"
            className="input w-full font-serif text-[15px] leading-relaxed"
          />
        ) : (
          <>
            {(content.executive_summary || report.executive_summary || '').trim() ? (
              <p className="text-[15px] leading-relaxed text-dark-200 whitespace-pre-line">
                {content.executive_summary || report.executive_summary}
              </p>
            ) : (
              <p className="italic text-dark-500">No summary written yet — click Edit to add one.</p>
            )}
          </>
        )}
      </section>

      {/* ---------- Statistical Analytics ---------- */}
      {content.analytics && (
        <section>
          <SectionHeader
            title="Statistical analysis"
            subtitle="Severity, confidence, attack effectiveness, and coverage"
          />
          <ReportAnalytics
            analytics={content.analytics}
            risk={content.risk}
          />
        </section>
      )}

      {/* ---------- Findings ---------- */}
      <section className="card p-5">
        <SectionHeader
          title="Detailed findings"
          subtitle={`${findings.length} finding${findings.length === 1 ? '' : 's'} ranked by severity, confidence, then CVSS`}
        />
        {findings.length > 0 ? (
          <ol className="divide-y divide-dark-800 -mx-5">
            {findings.map((finding, index) => (
              <li key={finding.id || index} className="px-5 py-4">
                <div className="flex items-start justify-between gap-4 mb-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-dark-500">#{index + 1}</span>
                      <h3 className="font-semibold text-white text-[15px] tracking-tight">
                        {finding.title}
                      </h3>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-dark-500 flex-wrap">
                      {finding.attack_name && (
                        <span>via <span className="text-aegis-400">{finding.attack_name}</span></span>
                      )}
                      {finding.tool && (
                        <span>tool <span className="font-mono text-aegis-400">{finding.tool}</span></span>
                      )}
                      {finding.parameter && (
                        <span>param <span className="font-mono">{finding.parameter}</span></span>
                      )}
                      {finding.cwe && (
                        <span>CWE <span className="font-mono">{finding.cwe}</span></span>
                      )}
                      {typeof finding.cvss_score === 'number' && (
                        <span>CVSS <span className="font-mono">{finding.cvss_score}</span></span>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wide ${SEVERITY_RING[finding.severity] || SEVERITY_RING.info}`}>
                      {finding.severity}
                    </span>
                    {finding.confidence && (
                      <span className={`text-[11px] uppercase tracking-wide ${CONF_COLOR[finding.confidence] || 'text-dark-400'}`}>
                        {finding.confidence}
                      </span>
                    )}
                  </div>
                </div>
                {finding.description && (
                  <p className="text-sm text-dark-300 leading-relaxed mb-2">{finding.description}</p>
                )}
                {finding.impact && (
                  <p className="text-xs text-dark-400 mb-2">
                    <span className="font-semibold text-dark-300 uppercase tracking-wide mr-1">Impact:</span>
                    {finding.impact}
                  </p>
                )}
                {finding.remediation && (
                  <p className="text-xs text-dark-400 mb-2">
                    <span className="font-semibold text-emerald-400 uppercase tracking-wide mr-1">Fix:</span>
                    {finding.remediation}
                  </p>
                )}
                {finding.payload && (
                  <pre className="text-[11px] text-dark-300 bg-dark-950 px-2.5 py-1.5 rounded overflow-x-auto max-h-32 mb-2">
                    {finding.payload}
                  </pre>
                )}
                {Array.isArray(finding.evidence) && finding.evidence.length > 0 && (
                  <details className="text-xs">
                    <summary className="cursor-pointer text-dark-400 hover:text-dark-200 inline-flex items-center gap-1">
                      Evidence ({finding.evidence.length})
                    </summary>
                    <pre className="text-[11px] text-dark-300 bg-dark-950 p-2.5 rounded overflow-x-auto mt-2 max-h-64">
                      {JSON.stringify(finding.evidence, null, 2)}
                    </pre>
                  </details>
                )}
              </li>
            ))}
          </ol>
        ) : (
          <div className="py-12 text-center text-dark-500">
            <CheckCircle className="w-12 h-12 mx-auto mb-3 text-emerald-500" />
            <p className="font-medium text-dark-300">No vulnerabilities identified</p>
            <p className="text-xs mt-1">All attacks ran cleanly without producing findings.</p>
          </div>
        )}
      </section>

      {/* ---------- Recommendations ---------- */}
      <section className="card p-5">
        <SectionHeader
          title="Recommendations"
          subtitle="Prioritized actions for the client to remediate"
          icon={Shield}
          action={editMode && (
            <button
              type="button"
              onClick={addRec}
              className="btn-secondary btn-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              Add
            </button>
          )}
        />
        {editMode ? (
          <ol className="space-y-2">
            {draft.recommendations.length === 0 && (
              <p className="text-xs italic text-dark-500">No recommendations yet — click "Add".</p>
            )}
            {draft.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-dark-500 text-sm font-mono mt-2.5 flex-shrink-0 w-5 text-right">{i + 1}.</span>
                <textarea
                  rows={2}
                  value={rec}
                  onChange={(e) => setRec(i, e.target.value)}
                  placeholder="e.g. Add output sanitization on all eval-style MCP tools…"
                  className="input flex-1 text-sm leading-relaxed"
                />
                <button
                  type="button"
                  onClick={() => removeRec(i)}
                  className="btn-ghost btn-sm text-red-400 mt-1.5"
                  aria-label="Remove"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </li>
            ))}
          </ol>
        ) : baseRecs.length > 0 ? (
          <ol className="space-y-3 list-decimal list-inside marker:text-aegis-400 marker:font-semibold">
            {baseRecs.map((rec, index) => (
              <li key={index} className="text-sm text-dark-200 leading-relaxed pl-1">
                {rec}
              </li>
            ))}
          </ol>
        ) : (
          <p className="italic text-dark-500">No recommendations written yet — click Edit to add some.</p>
        )}
      </section>

      {/* ---------- Analyst notes ---------- */}
      <section className="card p-5">
        <SectionHeader
          title="Analyst notes"
          subtitle="Free-text appendix for context, observations, follow-ups"
          icon={StickyNote}
        />
        {editMode ? (
          <textarea
            rows={6}
            value={draft.notes}
            onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
            placeholder={'Anything not covered by findings/recommendations — environmental notes, ROE deviations, things to revisit next quarter…'}
            className="input w-full font-serif text-[14px] leading-relaxed"
          />
        ) : (content.notes || '').trim() ? (
          <p className="text-[14px] leading-relaxed text-dark-200 whitespace-pre-line">{content.notes}</p>
        ) : (
          <p className="italic text-dark-500">No analyst notes yet.</p>
        )}
      </section>
    </div>
  )
}
