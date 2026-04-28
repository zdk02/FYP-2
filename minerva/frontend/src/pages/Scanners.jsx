import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ShieldCheck,
  Search,
  Database,
  Users,
  AlertTriangle,
  Tag,
  Play,
  ChevronRight,
} from 'lucide-react'
import { scannersApi } from '../services/api'

const severityColors = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

export default function Scanners() {
  const [search, setSearch] = useState('')

  const { data: scanners = [], isLoading } = useQuery({
    queryKey: ['scanners'],
    queryFn: scannersApi.list,
  })

  const filtered = scanners.filter((s) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      (s.name || '').toLowerCase().includes(q) ||
      (s.description || '').toLowerCase().includes(q) ||
      (s.tags || []).some((t) => String(t).toLowerCase().includes(q))
    )
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-aegis-400" />
            Vulnerability Scanners
          </h1>
          <p className="text-dark-400 text-sm mt-1">
            YAML-driven scanners for MCP clients, servers, and related attack surfaces.
          </p>
        </div>
        <div className="flex items-center gap-2 bg-dark-800 rounded-lg px-3 py-2 w-80">
          <Search className="w-4 h-4 text-dark-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search scanners..."
            className="bg-transparent border-none outline-none text-sm text-white placeholder-dark-500 w-full"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="text-dark-400 text-sm">Loading scanners...</div>
      ) : filtered.length === 0 ? (
        <div className="card">
          <div className="card-body text-center text-dark-400">
            <Database className="w-10 h-10 mx-auto mb-2 opacity-50" />
            <p>No scanner plugins installed.</p>
            <p className="text-xs mt-2">
              Drop a plugin folder into{' '}
              <code className="text-aegis-400">backend/plugins/scanners/</code>.
            </p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((s) => (
            <ScannerCard key={s.id} scanner={s} />
          ))}
        </div>
      )}
    </div>
  )
}

function ScannerCard({ scanner }) {
  const sev = (scanner.severity || 'info').toLowerCase()
  return (
    <div className="card hover:border-aegis-500/60 transition-colors">
      <div className="card-body space-y-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="font-semibold text-white truncate">{scanner.name}</h3>
            <p className="text-xs text-dark-400">
              v{scanner.version || '?'} · {scanner.author || 'unknown author'}
            </p>
          </div>
          <span className={`badge ${severityColors[sev] || 'badge-info'} shrink-0`}>
            {sev}
          </span>
        </div>
        <p className="text-sm text-dark-300 line-clamp-3">
          {scanner.description || 'No description.'}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {(scanner.tags || []).slice(0, 5).map((t) => (
            <span
              key={t}
              className="text-[10px] px-1.5 py-0.5 bg-dark-800 text-dark-300 rounded inline-flex items-center gap-1"
            >
              <Tag className="w-2.5 h-2.5" />
              {t}
            </span>
          ))}
        </div>
        <div className="grid grid-cols-3 gap-2 pt-2 border-t border-dark-800 text-center">
          <div>
            <div className="text-lg font-semibold text-white">
              {scanner.client_count ?? 0}
            </div>
            <div className="text-[10px] text-dark-500 flex items-center justify-center gap-1">
              <Users className="w-3 h-3" /> clients
            </div>
          </div>
          <div>
            <div className="text-lg font-semibold text-white">
              {scanner.cve_count ?? 0}
            </div>
            <div className="text-[10px] text-dark-500 flex items-center justify-center gap-1">
              <AlertTriangle className="w-3 h-3" /> CVEs
            </div>
          </div>
          <div>
            <div className="text-lg font-semibold text-white capitalize truncate">
              {scanner.pillar || '—'}
            </div>
            <div className="text-[10px] text-dark-500">pillar</div>
          </div>
        </div>
        <div className="flex items-center gap-2 pt-2">
          <Link
            to={`/scanners/${scanner.id}`}
            className="btn btn-secondary btn-sm flex-1 justify-center"
          >
            <ChevronRight className="w-4 h-4" /> Open
          </Link>
          <Link
            to={`/scanners/${scanner.id}?run=1`}
            className="btn btn-primary btn-sm flex-1 justify-center"
          >
            <Play className="w-4 h-4" /> Run
          </Link>
        </div>
      </div>
    </div>
  )
}
