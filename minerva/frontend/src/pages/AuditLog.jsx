import { useEffect, useState } from 'react'
import { ScrollText, ShieldCheck, AlertTriangle, RefreshCw } from 'lucide-react'
import { auditApi } from '../services/api'

export default function AuditLog() {
  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [filter, setFilter] = useState({ action: '', engagement_id: '' })
  const [verifyResult, setVerifyResult] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const params = {}
      if (filter.action) params.action = filter.action
      if (filter.engagement_id) params.engagement_id = filter.engagement_id
      const data = await auditApi.list({ ...params, limit: 500 })
      setEntries(data.entries || [])
      setTotal(data.total || 0)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const verify = async () => {
    setVerifyResult(null)
    const r = await auditApi.verify()
    setVerifyResult(r)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ScrollText className="w-6 h-6" /> Audit Log
          </h1>
          <p className="text-sm text-dark-400">
            Tamper-evident hash-chained log. Every action is sha256-linked to the previous one.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={verify} className="btn btn-primary flex items-center gap-2">
            <ShieldCheck className="w-4 h-4" /> Verify integrity
          </button>
          <button onClick={load} className="btn btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
        </div>
      </div>

      {verifyResult && (
        <div className={`p-4 rounded border ${verifyResult.ok
            ? 'bg-emerald-900/30 border-emerald-700 text-emerald-100'
            : 'bg-red-900/30 border-red-700 text-red-100'}`}>
          <div className="flex items-center gap-2 font-semibold">
            {verifyResult.ok ? (
              <>
                <ShieldCheck className="w-5 h-5" />
                Chain intact — verified {verifyResult.verified} entries
              </>
            ) : (
              <>
                <AlertTriangle className="w-5 h-5" />
                CHAIN BROKEN at sequence {verifyResult.first_break_at}
              </>
            )}
          </div>
          {verifyResult.breaks?.length > 0 && (
            <div className="mt-2 text-xs">
              <pre className="overflow-x-auto">
                {JSON.stringify(verifyResult.breaks, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      <div className="card p-3">
        <div className="flex gap-2">
          <input className="input flex-1" placeholder="Filter by action (e.g. attack_completed)"
            value={filter.action}
            onChange={(e) => setFilter({ ...filter, action: e.target.value })}
            onKeyDown={(e) => { if (e.key === 'Enter') load() }} />
          <input className="input flex-1" placeholder="Filter by engagement ID"
            value={filter.engagement_id}
            onChange={(e) => setFilter({ ...filter, engagement_id: e.target.value })}
            onKeyDown={(e) => { if (e.key === 'Enter') load() }} />
          <button onClick={load} className="btn btn-secondary">Apply</button>
        </div>
      </div>

      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-dark-400 border-b border-dark-800">
              <th className="text-left py-2 px-3">#</th>
              <th className="text-left py-2 px-3">When</th>
              <th className="text-left py-2 px-3">Action</th>
              <th className="text-left py-2 px-3">Resource</th>
              <th className="text-left py-2 px-3">Engagement</th>
              <th className="text-left py-2 px-3">User</th>
              <th className="text-left py-2 px-3">Hash</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id} className="border-b border-dark-900 hover:bg-dark-900/40">
                <td className="py-1.5 px-3 text-dark-400 font-mono text-xs">{e.sequence}</td>
                <td className="py-1.5 px-3 text-dark-300 font-mono text-xs">
                  {e.created_at ? e.created_at.replace('T', ' ').split('.')[0] : ''}
                </td>
                <td className="py-1.5 px-3 text-white">{e.action}</td>
                <td className="py-1.5 px-3 text-dark-300">
                  {e.resource_type}
                  {e.resource_id && (
                    <span className="text-dark-500 font-mono text-xs"> / {e.resource_id.slice(0, 8)}</span>
                  )}
                </td>
                <td className="py-1.5 px-3 text-dark-400 font-mono text-xs">
                  {e.engagement_id ? e.engagement_id.slice(0, 8) : '—'}
                </td>
                <td className="py-1.5 px-3 text-dark-400 font-mono text-xs">
                  {e.user_id ? e.user_id.slice(0, 8) : 'system'}
                </td>
                <td className="py-1.5 px-3 text-dark-500 font-mono text-xs">
                  {e.entry_hash ? e.entry_hash.slice(0, 12) : '—'}
                </td>
              </tr>
            ))}
            {entries.length === 0 && !loading && (
              <tr>
                <td colSpan="7" className="text-center py-8 text-dark-400">
                  No audit entries.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="text-xs text-dark-400">
        Showing {entries.length} of {total} entries.
      </div>
    </div>
  )
}
