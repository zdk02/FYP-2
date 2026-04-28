import { useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { X, Play, Loader2, Info } from 'lucide-react'
import toast from 'react-hot-toast'
import { scannersApi, targetsApi } from '../../services/api'
import FindingsTable from './FindingsTable'


function ParamField({ name, spec, value, onChange }) {
  const type = spec?.type || 'string'
  const enums = spec?.enum
  const commonProps = {
    id: `param-${name}`,
    value: value ?? (spec?.default ?? ''),
    onChange: (e) =>
      onChange(name, type === 'integer' || type === 'number'
        ? Number(e.target.value) : e.target.value),
    className: 'input',
  }
  return (
    <div>
      <label htmlFor={`param-${name}`}
             className="block text-xs text-dark-400 mb-1">
        {name}
        {spec?.description && (
          <span className="text-dark-500 ml-2 normal-case">
            — {spec.description}
          </span>
        )}
      </label>
      {type === 'boolean' ? (
        <input id={`param-${name}`} type="checkbox" checked={!!value}
               onChange={(e) => onChange(name, e.target.checked)}
               className="h-4 w-4" />
      ) : enums ? (
        <select {...commonProps} className="input appearance-none">
          {enums.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
      ) : (
        <input {...commonProps}
               type={type === 'integer' || type === 'number' ? 'number' : 'text'} />
      )}
    </div>
  )
}


export default function RunModal({ pluginId, scanner, onClose }) {
  const configSchema = scanner?.config_schema || {}
  const defaults = scanner?.default_config || {}

  // Load existing targets so the user can pick rather than re-type
  const { data: targetsData } = useQuery({
    queryKey: ['targets-for-scanner'],
    queryFn: () => targetsApi.getAll({ limit: 100 }),
  })
  const allTargets = targetsData?.targets || []

  const [target, setTarget] = useState({
    host: 'localhost',
    port: 0,
    protocol: 'http',
    base_url: '',
  })
  const [targetId, setTargetId] = useState('')
  const [params, setParams] = useState(() => {
    const initial = {}
    for (const [k, spec] of Object.entries(configSchema)) {
      initial[k] = defaults[k] ?? spec?.default ??
        (spec?.type === 'boolean' ? false : '')
    }
    return initial
  })
  const [dryRun, setDryRun] = useState(false)
  const [result, setResult] = useState(null)

  const pickTarget = (id) => {
    setTargetId(id)
    const t = allTargets.find(x => x.id === id)
    if (t) {
      setTarget({
        host: t.host || 'localhost',
        port: t.port || 0,
        protocol: t.protocol || 'http',
        base_url: t.base_url || '',
        auth_config: t.auth_config,
        target_id: t.id,
      })
    }
  }

  const runMutation = useMutation({
    mutationFn: () => scannersApi.run(pluginId, {
      target, params, dry_run: dryRun,
    }),
    onSuccess: (data) => {
      setResult(data)
      if (data.status === 'error') {
        toast.error('Scanner returned an error')
      } else if (data.status === 'timeout') {
        toast.error('Scanner timed out')
      } else {
        toast.success(
          `Scanner ${data.status} — ${data.findings?.length || 0} findings`)
      }
    },
    onError: (err) =>
      toast.error(err?.response?.data?.error || 'Failed to run scanner'),
  })

  const setParam = (k, v) => setParams((p) => ({ ...p, [k]: v }))
  const schemaEntries = useMemo(() =>
    Object.entries(configSchema), [configSchema])

  const isStdio = target.protocol === 'stdio'

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 overflow-auto bg-black/60">
      <div className="w-full max-w-4xl bg-dark-900 border border-dark-700 rounded-xl shadow-2xl my-10">
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-800">
          <div>
            <h2 className="text-lg font-semibold text-white">Run Scanner</h2>
            <p className="text-xs text-dark-400">{scanner?.name}</p>
          </div>
          <button onClick={onClose}
                  className="text-dark-400 hover:text-white p-1 rounded">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-4 space-y-6">
          {/* Scanner scope explainer */}
          <div className="flex items-start gap-2 bg-aegis-900/20 border border-aegis-700/30 rounded-lg p-3 text-xs text-dark-200">
            <Info className="w-4 h-4 text-aegis-400 shrink-0 mt-0.5" />
            <div>
              <b className="text-aegis-400">What this scanner does:</b>{' '}
              Checks the <b>local host</b> for installed MCP clients (Claude
              Code, Cursor, Windsurf, etc.) and cross-references their versions
              against 28 known CVEs. If you supply a target below, it will also
              do light remote probing (HTTP paths, WebSocket banner,
              server headers). Unlike attacks, this scanner doesn't need
              the target to respond to MCP calls.
            </div>
          </div>

          {/* Existing target picker */}
          {allTargets.length > 0 && (
            <div>
              <label className="block text-xs text-dark-400 mb-1">
                Pick an existing target (optional)
              </label>
              <select className="input appearance-none"
                      value={targetId}
                      onChange={(e) => pickTarget(e.target.value)}>
                <option value="">— manual entry below —</option>
                {allTargets.map(t => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.protocol === 'stdio'
                      ? 'stdio'
                      : `${t.host}${t.port ? ':' + t.port : ''}`})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Target fields */}
          <div>
            <div className="text-xs uppercase tracking-wide text-dark-500 mb-2">
              Target
            </div>
            {isStdio ? (
              <div className="space-y-2">
                <div className="bg-dark-800/50 border border-dark-700 rounded-lg px-3 py-2 text-sm">
                  <span className="text-dark-400">Transport:</span>{' '}
                  <span className="text-aegis-400 font-medium">stdio</span>
                  <span className="text-dark-500 text-xs ml-2">
                    (no host/port — subprocess spawn)
                  </span>
                </div>
                <div>
                  <label className="text-xs text-dark-400">Spawn command</label>
                  <input className="input font-mono text-xs"
                         value={target.base_url || ''}
                         onChange={(e) => setTarget((t) =>
                           ({ ...t, base_url: e.target.value }))}
                         placeholder="stdio:npx -y @modelcontextprotocol/server-filesystem C:/temp" />
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="text-xs text-dark-400">Host</label>
                  <input className="input" value={target.host}
                         onChange={(e) => setTarget((t) =>
                           ({ ...t, host: e.target.value }))} />
                </div>
                <div>
                  <label className="text-xs text-dark-400">Port</label>
                  <input type="number" className="input" value={target.port}
                         onChange={(e) => setTarget((t) =>
                           ({ ...t, port: Number(e.target.value) }))} />
                </div>
                <div>
                  <label className="text-xs text-dark-400">Protocol</label>
                  <select className="input appearance-none"
                          value={target.protocol}
                          onChange={(e) => setTarget((t) =>
                            ({ ...t, protocol: e.target.value, base_url: '' }))}>
                    <option value="http">HTTP</option>
                    <option value="https">HTTPS</option>
                    <option value="sse">SSE</option>
                    <option value="ws">WebSocket (ws)</option>
                    <option value="wss">WebSocket TLS (wss)</option>
                    <option value="stdio">stdio (subprocess)</option>
                    <option value="tcp">TCP</option>
                  </select>
                </div>
              </div>
            )}
            <p className="text-[11px] text-dark-500 mt-2">
              Tip: pick the target with <b>client_hint</b> below if you only
              want to check a specific client (e.g. <code>claude_code</code>).
            </p>
          </div>

          {/* Params */}
          {schemaEntries.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-wide text-dark-500 mb-2">
                Parameters
              </div>
              <div className="grid grid-cols-2 gap-3">
                {schemaEntries.map(([name, spec]) => (
                  <ParamField key={name} name={name} spec={spec}
                              value={params[name]} onChange={setParam} />
                ))}
              </div>
            </div>
          )}

          {/* Controls */}
          <div className="flex items-center gap-3">
            <label className="inline-flex items-center gap-2 text-sm text-dark-300">
              <input type="checkbox" checked={dryRun}
                     onChange={(e) => setDryRun(e.target.checked)} />
              Dry run (validate only)
            </label>
            <button onClick={() => runMutation.mutate()}
                    disabled={runMutation.isPending}
                    className="btn btn-primary ml-auto">
              {runMutation.isPending ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Running...</>
              ) : (
                <><Play className="w-4 h-4" /> Run Scanner</>
              )}
            </button>
          </div>

          {/* Results */}
          {result && (
            <div className="space-y-3 border-t border-dark-800 pt-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-dark-400">
                  Status: <span className="text-white font-medium">{result.status}</span>
                  {result.duration_ms !== undefined && (
                    <span className="ml-3">Duration: {result.duration_ms}ms</span>
                  )}
                </div>
                <div className="text-xs text-dark-400">
                  {result.findings?.length || 0} findings ·{' '}
                  {result.evidence?.length || 0} evidence items
                </div>
              </div>
              <FindingsTable findings={result.findings || []} />
              {result.execution_log?.length > 0 && (
                <details className="bg-dark-950 rounded-lg p-3">
                  <summary className="cursor-pointer text-xs text-dark-400">
                    Execution log ({result.execution_log.length} lines)
                  </summary>
                  <pre className="mt-2 text-[11px] text-dark-300 whitespace-pre-wrap leading-relaxed">
                    {result.execution_log.join('\n')}
                  </pre>
                </details>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
