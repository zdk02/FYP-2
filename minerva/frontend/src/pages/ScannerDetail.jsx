import { useEffect, useState } from 'react'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft,
  ShieldCheck,
  Play,
  AlertTriangle,
  Users,
  ChevronDown,
  ChevronRight,
  Tag,
  BookOpen,
  ExternalLink,
} from 'lucide-react'
import { scannersApi } from '../services/api'
import RunModal from '../components/scanners/RunModal'

const severityColors = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

function ClientAccordion({ client }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-dark-800 rounded-lg">
      <button
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-dark-800/50"
        onClick={() => setOpen((v) => !v)}
      >
        {open ? (
          <ChevronDown className="w-4 h-4 text-dark-400" />
        ) : (
          <ChevronRight className="w-4 h-4 text-dark-400" />
        )}
        <div className="flex-1 min-w-0">
          <div className="text-white text-sm truncate">
            {client.display_name}{' '}
            <span className="text-dark-500 text-xs">({client.key})</span>
          </div>
          <div className="text-[11px] text-dark-500">
            {client.vendor} · {client.type}
          </div>
        </div>
        <span className="text-xs text-dark-400">
          {client.cves_count} CVE{client.cves_count === 1 ? '' : 's'}
        </span>
      </button>
      {open && <ClientCveList pluginId={client.pluginId} clientKey={client.key} />}
    </div>
  )
}

function ClientCveList({ pluginId, clientKey }) {
  const { data, isLoading } = useQuery({
    queryKey: ['scanner-client', pluginId, clientKey],
    queryFn: () => scannersApi.getClient(pluginId, clientKey),
  })
  if (isLoading) {
    return <div className="px-3 py-2 text-xs text-dark-400">Loading...</div>
  }
  const cves = data?.cves || []
  if (!cves.length) {
    return <div className="px-3 py-2 text-xs text-dark-500">No CVEs.</div>
  }
  return (
    <div className="px-3 pb-3 space-y-1">
      {cves.map((c) => {
        const sev = String(c.severity || 'info').toLowerCase()
        const cveLink = c.id?.startsWith('CVE-')
          ? `https://nvd.nist.gov/vuln/detail/${c.id}`
          : null
        return (
          <div
            key={c.id}
            className="flex items-start gap-2 px-2 py-1.5 rounded bg-dark-900/60"
          >
            <span className={`badge ${severityColors[sev]} shrink-0`}>{sev}</span>
            <div className="min-w-0 flex-1">
              <div className="text-xs text-white">
                {cveLink ? (
                  <a
                    href={cveLink}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-aegis-400 hover:underline inline-flex items-center gap-1 mr-2"
                  >
                    {c.id}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ) : (
                  <span className="font-mono text-dark-300 mr-2">{c.id}</span>
                )}
                {c.title}
              </div>
              {c.description && (
                <div className="text-[11px] text-dark-400 mt-0.5 line-clamp-2">
                  {c.description}
                </div>
              )}
            </div>
            {c.cvss != null && (
              <div className="text-[11px] text-dark-400 shrink-0">
                CVSS {c.cvss}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

export default function ScannerDetail() {
  const { pluginId } = useParams()
  const [searchParams, setSearchParams] = useSearchParams()
  const [runOpen, setRunOpen] = useState(false)

  const { data: scanner, isLoading } = useQuery({
    queryKey: ['scanner', pluginId],
    queryFn: () => scannersApi.get(pluginId),
  })

  const { data: clients = [] } = useQuery({
    queryKey: ['scanner-clients', pluginId],
    queryFn: () => scannersApi.listClients(pluginId),
  })

  useEffect(() => {
    if (searchParams.get('run') === '1') {
      setRunOpen(true)
      setSearchParams({}, { replace: true })
    }
  }, [searchParams, setSearchParams])

  if (isLoading) {
    return <div className="text-dark-400">Loading...</div>
  }
  if (!scanner) {
    return (
      <div className="card">
        <div className="card-body text-dark-400">Scanner not found.</div>
      </div>
    )
  }

  const sev = (scanner.severity || 'info').toLowerCase()

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/scanners"
          className="inline-flex items-center gap-1 text-xs text-dark-400 hover:text-white"
        >
          <ArrowLeft className="w-3 h-3" /> Back to scanners
        </Link>
      </div>

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-aegis-400" />
            {scanner.name}
          </h1>
          <p className="text-dark-400 text-sm mt-1">
            v{scanner.version} · {scanner.author} ·{' '}
            <span className={`badge ${severityColors[sev]} ml-1`}>{sev}</span>
          </p>
          <p className="text-sm text-dark-300 mt-3 max-w-3xl whitespace-pre-line">
            {scanner.description}
          </p>
          <div className="flex flex-wrap gap-1.5 mt-3">
            {(scanner.tags || []).map((t) => (
              <span
                key={t}
                className="text-[10px] px-1.5 py-0.5 bg-dark-800 text-dark-300 rounded inline-flex items-center gap-1"
              >
                <Tag className="w-2.5 h-2.5" /> {t}
              </span>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setRunOpen(true)}
            className="btn btn-primary"
          >
            <Play className="w-4 h-4" /> Run Scanner
          </button>
          <Link
            to="/admin/scanners"
            className="btn btn-secondary"
            title="Admin — add/edit CVEs, clients, globals"
          >
            Manage CVE Database
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1 space-y-4">
          <div className="card">
            <div className="card-body space-y-3">
              <Stat label="Clients tracked" value={scanner.client_count} icon={Users} />
              <Stat label="CVEs tracked" value={scanner.cve_count} icon={AlertTriangle} />
              <Stat label="Pillar" value={scanner.pillar || '—'} />
              <Stat label="Schema version" value={scanner.schema_version || '—'} />
            </div>
          </div>

          {scanner.mitre_attack && (
            <div className="card">
              <div className="card-body space-y-2">
                <div className="text-xs uppercase tracking-wide text-dark-500">
                  MITRE ATT&CK
                </div>
                <div className="text-sm text-dark-300">
                  <div>
                    Tactics:{' '}
                    <span className="text-white font-mono">
                      {(scanner.mitre_attack.tactics || []).join(', ') || '—'}
                    </span>
                  </div>
                  <div>
                    Techniques:{' '}
                    <span className="text-white font-mono">
                      {(scanner.mitre_attack.techniques || []).join(', ') || '—'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="xl:col-span-2 space-y-4">
          <div className="card">
            <div className="card-header flex items-center gap-2">
              <Users className="w-4 h-4 text-aegis-400" />
              <span className="font-medium text-white">Tracked Clients & CVEs</span>
            </div>
            <div className="card-body space-y-2">
              {clients.length === 0 ? (
                <div className="text-sm text-dark-400">No clients loaded.</div>
              ) : (
                clients.map((c) => (
                  <ClientAccordion
                    key={c.key}
                    client={{ ...c, pluginId }}
                  />
                ))
              )}
            </div>
          </div>

          {scanner.readme && (
            <div className="card">
              <div className="card-header flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-aegis-400" />
                <span className="font-medium text-white">README</span>
              </div>
              <div className="card-body">
                <pre className="text-[11px] text-dark-300 whitespace-pre-wrap leading-relaxed">
                  {scanner.readme}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>

      {runOpen && (
        <RunModal
          pluginId={pluginId}
          scanner={scanner}
          onClose={() => setRunOpen(false)}
        />
      )}
    </div>
  )
}

function Stat({ label, value, icon: Icon }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2 text-xs text-dark-400">
        {Icon && <Icon className="w-3.5 h-3.5" />}
        {label}
      </div>
      <div className="text-sm font-medium text-white">{value}</div>
    </div>
  )
}
