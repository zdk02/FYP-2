import { useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  ArrowLeft,
  Shield,
  Clock,
  Tag,
  Code,
  FileText,
  AlertTriangle,
  CheckCircle,
  Copy,
  Play,
  X,
  Loader2,
  Target as TargetIcon,
} from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { attacksApi, targetsApi } from '../services/api'
import toast from 'react-hot-toast'

const severityColors = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

function paramFieldType(prop) {
  if (!prop) return 'string'
  return prop.type || (prop.enum ? 'enum' : 'string')
}

function arrayToText(value) {
  if (!Array.isArray(value)) return ''
  return value.join('\n')
}

function textToArray(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)
}

export default function AttackDetail() {
  const { id } = useParams()

  const { data, isLoading, error } = useQuery({
    queryKey: ['attack', id],
    queryFn: () => attacksApi.get(id),
  })

  const attack = data

  const [showRunModal, setShowRunModal] = useState(false)
  const [selectedTargetId, setSelectedTargetId] = useState('')
  const [runParams, setRunParams] = useState({})
  const [runResult, setRunResult] = useState(null)

  const { data: targetsData } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.getAll({ limit: 200 }),
    enabled: showRunModal,
  })

  const targets = targetsData?.targets || targetsData || []

  const schemaProps = useMemo(() => {
    if (!attack?.config_schema) return {}
    const schema = typeof attack.config_schema === 'string'
      ? (() => { try { return JSON.parse(attack.config_schema) } catch { return {} } })()
      : attack.config_schema
    return schema?.properties || {}
  }, [attack])

  const defaultConfig = useMemo(() => {
    if (!attack?.default_config) return {}
    if (typeof attack.default_config !== 'string') return attack.default_config
    try { return JSON.parse(attack.default_config) } catch { return {} }
  }, [attack])

  const openRunModal = () => {
    setRunParams({ ...defaultConfig })
    setRunResult(null)
    setSelectedTargetId('')
    setShowRunModal(true)
  }

  const runMutation = useMutation({
    mutationFn: (body) => attacksApi.test(attack.id, body),
    onSuccess: (data) => {
      setRunResult(data)
      const n = Array.isArray(data?.findings) ? data.findings.length : 0
      if (n > 0) toast.success(`Attack finished — ${n} vulnerabilit${n === 1 ? 'y' : 'ies'} found`)
      else toast.success('Attack finished — no vulnerabilities detected')
    },
    onError: (error) => {
      const msg = error.response?.data?.error || error.message || 'Attack failed'
      setRunResult({ status: 'error', message: msg })
      toast.error(msg)
    },
  })

  const launchAttack = () => {
    if (!selectedTargetId) {
      toast.error('Pick a target first')
      return
    }
    setRunResult(null)
    runMutation.mutate({
      params: runParams,
      target_id: selectedTargetId,
    })
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner w-8 h-8" />
      </div>
    )
  }

  if (error || !attack) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-dark-400">
        <AlertTriangle className="w-12 h-12 mb-4" />
        <p>Attack not found</p>
        <Link to="/attacks" className="btn-secondary mt-4">
          Back to Attacks
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <Link to="/attacks" className="btn-ghost p-2 mt-1">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-2xl font-bold text-white">{attack.name}</h1>
              <span className={`badge ${severityColors[attack.severity]}`}>
                {attack.severity}
              </span>
              {attack.is_verified && (
                <span className="badge badge-success">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Verified
                </span>
              )}
            </div>
            <p className="text-dark-400">{attack.description}</p>
          </div>
        </div>
        <button onClick={openRunModal} className="btn-primary">
          <Play className="w-4 h-4" />
          Run Attack
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Script */}
          <div className="card">
            <div className="card-header flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Code className="w-4 h-4 text-aegis-400" />
                <h2 className="font-semibold text-white">Attack Script</h2>
                <span className="text-xs text-dark-500 bg-dark-700 px-2 py-0.5 rounded">
                  {attack.script_language}
                </span>
              </div>
              <button
                onClick={() => copyToClipboard(attack.script_content)}
                className="btn-ghost btn-sm"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4">
              <SyntaxHighlighter
                language={attack.script_language}
                style={oneDark}
                customStyle={{
                  margin: 0,
                  borderRadius: '0.5rem',
                  fontSize: '0.875rem',
                }}
              >
                {attack.script_content || '# No script content'}
              </SyntaxHighlighter>
            </div>
          </div>

          {/* Payloads */}
          {attack.payloads && attack.payloads.length > 0 && (
            <div className="card">
              <div className="card-header">
                <h2 className="font-semibold text-white">Associated Payloads</h2>
              </div>
              <div className="divide-y divide-dark-800">
                {attack.payloads.map((payload) => (
                  <div key={payload.id} className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-medium text-white">{payload.name}</h3>
                      <span className="badge badge-info">{payload.payload_type}</span>
                    </div>
                    <pre className="text-sm text-dark-300 bg-dark-950 p-2 rounded overflow-x-auto">
                      {payload.content}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Details */}
          <div className="card">
            <div className="card-header">
              <h2 className="font-semibold text-white">Details</h2>
            </div>
            <div className="card-body space-y-4">
              <div>
                <p className="text-xs text-dark-500 mb-1">Attack Type</p>
                <p className="text-sm text-white flex items-center gap-2">
                  <Tag className="w-4 h-4 text-dark-400" />
                  {attack.attack_type}
                </p>
              </div>
              <div>
                <p className="text-xs text-dark-500 mb-1">Estimated Duration</p>
                <p className="text-sm text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-dark-400" />
                  {attack.estimated_duration ?? attack.timeout} seconds
                </p>
              </div>
              <div>
                <p className="text-xs text-dark-500 mb-1">Category</p>
                <p className="text-sm text-white">
                  {attack.subcategory?.main_category?.name} / {attack.subcategory?.name}
                </p>
              </div>
            </div>
          </div>

          {/* MITRE Techniques */}
          {attack.techniques && attack.techniques.length > 0 && (
            <div className="card">
              <div className="card-header">
                <h2 className="font-semibold text-white">MITRE ATT&CK</h2>
              </div>
              <div className="card-body">
                <div className="space-y-2">
                  {attack.techniques.map((technique) => (
                    <a
                      key={technique.id}
                      href={technique.reference_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block p-2 bg-dark-800 rounded-lg hover:bg-dark-700 transition-colors"
                    >
                      <p className="text-sm font-mono text-aegis-400">
                        {technique.mitre_id}
                      </p>
                      <p className="text-xs text-dark-400">{technique.name}</p>
                    </a>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Prerequisites */}
          {attack.prerequisites && (
            <div className="card">
              <div className="card-header">
                <h2 className="font-semibold text-white">Prerequisites</h2>
              </div>
              <div className="card-body">
                <p className="text-sm text-dark-300">{attack.prerequisites}</p>
              </div>
            </div>
          )}

          {/* Remediation */}
          {attack.remediation && (
            <div className="card">
              <div className="card-header">
                <h2 className="font-semibold text-white">Remediation</h2>
              </div>
              <div className="card-body">
                <p className="text-sm text-dark-300">{attack.remediation}</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {showRunModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-dark-700 flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-white">Run Attack</h2>
                <p className="text-sm text-dark-400">{attack.name}</p>
              </div>
              <button
                onClick={() => setShowRunModal(false)}
                className="btn-ghost btn-sm"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Target
                </label>
                {targets.length === 0 ? (
                  <div className="p-4 bg-dark-800 rounded-lg text-sm text-dark-400">
                    No registered targets yet.{' '}
                    <Link to="/targets" className="text-aegis-400">Add a target</Link> first.
                  </div>
                ) : (
                  <select
                    value={selectedTargetId}
                    onChange={(e) => setSelectedTargetId(e.target.value)}
                    className="input w-full"
                  >
                    <option value="">— Select a target —</option>
                    {targets.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name} {t.host ? `(${t.host}${t.port ? `:${t.port}` : ''})` : ''}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {Object.keys(schemaProps).length > 0 && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Parameters
                  </label>
                  <div className="space-y-3">
                    {Object.entries(schemaProps).map(([name, prop]) => {
                      const t = paramFieldType(prop)
                      const rawValue = runParams[name] ?? prop.default ?? (t === 'array' ? [] : t === 'boolean' ? false : '')
                      const setVal = (v) => setRunParams({ ...runParams, [name]: v })
                      const numericMin = prop.minimum ?? prop.min
                      const numericMax = prop.maximum ?? prop.max
                      return (
                        <div key={name} className="space-y-1">
                          <label className="block text-xs text-dark-300 font-medium">
                            {prop.title || name}
                            {numericMin !== undefined && numericMax !== undefined && (t === 'integer' || t === 'number') && (
                              <span className="text-dark-500 font-normal"> ({numericMin}–{numericMax})</span>
                            )}
                          </label>
                          {prop.description && (
                            <p className="text-xs text-dark-500">{prop.description}</p>
                          )}
                          {t === 'boolean' ? (
                            <select
                              value={String(rawValue)}
                              onChange={(e) => setVal(e.target.value === 'true')}
                              className="input w-full"
                            >
                              <option value="false">false</option>
                              <option value="true">true</option>
                            </select>
                          ) : t === 'enum' || prop.enum ? (
                            <select
                              value={rawValue}
                              onChange={(e) => setVal(e.target.value)}
                              className="input w-full"
                            >
                              {(prop.enum || []).map((opt) => (
                                <option key={opt} value={opt}>{opt}</option>
                              ))}
                            </select>
                          ) : t === 'integer' || t === 'number' ? (
                            <input
                              type="number"
                              min={numericMin}
                              max={numericMax}
                              step={t === 'integer' ? 1 : 'any'}
                              value={rawValue}
                              onChange={(e) => setVal(e.target.value === '' ? '' : Number(e.target.value))}
                              className="input w-full"
                            />
                          ) : t === 'array' ? (
                            <textarea
                              rows={3}
                              placeholder="One value per line (leave blank for default)"
                              value={arrayToText(Array.isArray(rawValue) ? rawValue : [])}
                              onChange={(e) => setVal(textToArray(e.target.value))}
                              className="input w-full font-mono text-sm"
                            />
                          ) : (
                            <input
                              type="text"
                              value={rawValue}
                              onChange={(e) => setVal(e.target.value)}
                              className="input w-full"
                            />
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {runResult && (() => {
                const findingsCount = Array.isArray(runResult.findings) ? runResult.findings.length : 0
                const isError = runResult.status === 'error' || runResult.status === 'failed'
                const ranOk = runResult.status === 'success' || runResult.status === 'completed' || runResult.status === 'validated'
                const hasFindings = ranOk && findingsCount > 0
                const cleanNoFindings = ranOk && findingsCount === 0 && runResult.status !== 'validated'
                const boxClass = isError
                  ? 'border-red-500 bg-red-500/10'
                  : hasFindings
                    ? 'border-emerald-500 bg-emerald-500/10'
                    : cleanNoFindings
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-yellow-500 bg-yellow-500/10'
                const label = isError
                  ? 'ERROR'
                  : hasFindings
                    ? `VULNERABILITIES FOUND (${findingsCount})`
                    : cleanNoFindings
                      ? 'NO VULNERABILITIES DETECTED'
                      : (runResult.status || 'finished').toString().toUpperCase()
                return (
                <div className={`p-4 rounded-lg border ${boxClass}`}>
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="w-4 h-4 text-white" />
                    <span className="text-sm font-medium text-white">
                      {label}
                    </span>
                  </div>
                  {runResult.message && (
                    <p className="text-sm text-dark-300 mb-3">{runResult.message}</p>
                  )}
                  {Array.isArray(runResult.findings) && runResult.findings.length > 0 && (
                    <div className="space-y-2">
                      {runResult.findings.map((f, i) => (
                        <div key={i} className="text-xs bg-dark-950 rounded p-2">
                          <div className="flex items-center justify-between">
                            <span className="font-medium text-white">{f.title}</span>
                            <span className={`badge badge-${f.severity || 'info'}`}>
                              {f.severity}
                            </span>
                          </div>
                          {f.description && (
                            <p className="text-dark-400 mt-1">{f.description}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                  {runResult.output && (
                    <pre className="text-xs text-dark-300 bg-dark-950 p-2 rounded overflow-x-auto mt-2 max-h-64">
                      {typeof runResult.output === 'string' ? runResult.output : JSON.stringify(runResult.output, null, 2)}
                    </pre>
                  )}
                </div>
                )
              })()}
            </div>

            <div className="p-6 border-t border-dark-700 flex items-center justify-end gap-2">
              <button
                onClick={() => setShowRunModal(false)}
                className="btn-secondary"
                disabled={runMutation.isPending}
              >
                Close
              </button>
              <button
                onClick={launchAttack}
                disabled={runMutation.isPending || !selectedTargetId || targets.length === 0}
                className="btn-primary"
              >
                {runMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Running…
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Launch
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
