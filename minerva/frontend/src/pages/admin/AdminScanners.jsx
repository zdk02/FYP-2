import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  Database,
  Search,
  Plus,
  Pencil,
  Trash2,
  Users,
  AlertTriangle,
  Archive,
  RotateCcw,
  Copy,
  ExternalLink,
  X,
} from 'lucide-react'
import { scannersApi } from '../../services/api'
import CveModal from '../../components/scanners/CveModal'
import ClientModal from '../../components/scanners/ClientModal'
import GlobalsPanel from '../../components/scanners/GlobalsPanel'

const severityColors = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

const statColor = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  info: 'text-dark-300',
}

const TABS = [
  { id: 'cves', label: 'CVEs', icon: AlertTriangle },
  { id: 'clients', label: 'Clients', icon: Users },
  { id: 'globals', label: 'Globals', icon: Database },
  { id: 'backups', label: 'Backups', icon: Archive },
]

function errMsg(err) {
  return (
    err?.response?.data?.error ||
    err?.response?.data?.message ||
    err?.message ||
    'Operation failed'
  )
}

export default function AdminScanners() {
  const qc = useQueryClient()
  const [pluginId, setPluginId] = useState(null)
  const [tab, setTab] = useState('cves')

  const { data: scanners = [] } = useQuery({
    queryKey: ['scanners'],
    queryFn: scannersApi.list,
  })

  useEffect(() => {
    if (scanners.length && !pluginId) {
      setPluginId(scanners[0].id)
    }
  }, [scanners, pluginId])

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Database className="w-6 h-6 text-aegis-400" />
            CVE Database
          </h1>
          <p className="text-dark-400 text-sm mt-1">
            Edit YAML-backed scanner plugins. Changes are written atomically with
            rolling backups.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-dark-400">Plugin</label>
          <select
            className="input appearance-none min-w-[220px]"
            value={pluginId || ''}
            onChange={(e) => setPluginId(e.target.value)}
          >
            {scanners.length === 0 && <option value="">(no plugins)</option>}
            {scanners.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.id})
              </option>
            ))}
          </select>
        </div>
      </div>

      {!pluginId ? (
        <div className="card">
          <div className="card-body text-dark-400">Select a plugin to manage.</div>
        </div>
      ) : (
        <>
          <div className="border-b border-dark-800 flex gap-1 flex-wrap">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`px-3 py-2 text-sm rounded-t-lg border-b-2 inline-flex items-center gap-2 transition-colors ${
                  tab === t.id
                    ? 'border-aegis-500 text-white'
                    : 'border-transparent text-dark-400 hover:text-white'
                }`}
              >
                <t.icon className="w-4 h-4" />
                {t.label}
              </button>
            ))}
          </div>

          {tab === 'cves' && <CvesTab pluginId={pluginId} qc={qc} />}
          {tab === 'clients' && <ClientsTab pluginId={pluginId} qc={qc} />}
          {tab === 'globals' && <GlobalsTab pluginId={pluginId} qc={qc} />}
          {tab === 'backups' && <BackupsTab pluginId={pluginId} qc={qc} />}
        </>
      )}
    </div>
  )
}

// ------------------------------------------------------------------
// CVEs tab
// ------------------------------------------------------------------

function CvesTab({ pluginId, qc }) {
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [clientFilter, setClientFilter] = useState('')
  const [editing, setEditing] = useState(null) // {clientKey, cve?}
  const [confirmDel, setConfirmDel] = useState(null)

  const { data: cves = [], isLoading } = useQuery({
    queryKey: ['scanner-cves', pluginId, { search, sevFilter, clientFilter }],
    queryFn: () =>
      scannersApi.listCves(pluginId, {
        search: search || undefined,
        severity: sevFilter || undefined,
        client: clientFilter || undefined,
      }),
  })

  const { data: clients = [] } = useQuery({
    queryKey: ['scanner-clients', pluginId],
    queryFn: () => scannersApi.listClients(pluginId),
  })

  const { data: checkTypes = [] } = useQuery({
    queryKey: ['scanner-check-types', pluginId],
    queryFn: () => scannersApi.checkTypes(pluginId),
  })

  const createMut = useMutation({
    mutationFn: ({ clientKey, cve }) =>
      scannersApi.createCve(pluginId, clientKey, cve),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-cves', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner-clients', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanners'] })
      toast.success('CVE created')
      setEditing(null)
    },
    onError: (e) => toast.error(errMsg(e)),
  })

  const updateMut = useMutation({
    mutationFn: ({ clientKey, cveId, cve }) =>
      scannersApi.updateCve(pluginId, clientKey, cveId, cve),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-cves', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner-clients', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner', pluginId] })
      toast.success('CVE updated')
      setEditing(null)
    },
    onError: (e) => toast.error(errMsg(e)),
  })

  const deleteMut = useMutation({
    mutationFn: ({ clientKey, cveId }) =>
      scannersApi.deleteCve(pluginId, clientKey, cveId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-cves', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner-clients', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanners'] })
      toast.success('CVE deleted')
      setConfirmDel(null)
    },
    onError: (e) => toast.error(errMsg(e)),
  })

  const openCreate = () => {
    setEditing({
      isNew: true,
      clientKey: clientFilter || clients[0]?.key || '',
      cve: null,
    })
  }

  const openEdit = async (row) => {
    try {
      const cve = await scannersApi.getCve(pluginId, row.client_key, row.cve_id)
      setEditing({ isNew: false, clientKey: row.client_key, cve })
    } catch (e) {
      toast.error(errMsg(e))
    }
  }

  const stats = useMemo(() => {
    const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const c of cves) {
      const k = String(c.severity || 'info').toLowerCase()
      if (s[k] !== undefined) s[k]++
    }
    return s
  }, [cves])

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {Object.entries(stats).map(([sev, n]) => (
          <div key={sev} className="card">
            <div className="card-body text-center py-3">
              <div className={`text-lg font-semibold ${statColor[sev] || 'text-white'}`}>
                {n}
              </div>
              <div className="text-[10px] uppercase tracking-wide text-dark-500">
                {sev}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-2 bg-dark-800 rounded-lg px-3 py-2 min-w-[240px] flex-1 max-w-md">
          <Search className="w-4 h-4 text-dark-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search CVE id, title, description..."
            className="bg-transparent border-none outline-none text-sm text-white placeholder-dark-500 w-full"
          />
        </div>
        <select
          className="input appearance-none max-w-[180px]"
          value={clientFilter}
          onChange={(e) => setClientFilter(e.target.value)}
        >
          <option value="">All clients</option>
          {clients.map((c) => (
            <option key={c.key} value={c.key}>
              {c.display_name}
            </option>
          ))}
        </select>
        <select
          className="input appearance-none max-w-[140px]"
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
        >
          <option value="">All severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
        <button
          onClick={openCreate}
          className="btn btn-primary"
          disabled={!clients.length}
        >
          <Plus className="w-4 h-4" /> Add CVE
        </button>
      </div>

      <div className="card">
        <div className="card-body overflow-x-auto">
          {isLoading ? (
            <div className="text-dark-400 text-sm">Loading...</div>
          ) : cves.length === 0 ? (
            <div className="text-dark-400 text-sm py-6 text-center">
              No CVEs match the filters.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-dark-500 border-b border-dark-800">
                <tr>
                  <th className="py-2 pr-3">CVE</th>
                  <th className="py-2 pr-3">Severity</th>
                  <th className="py-2 pr-3">Client</th>
                  <th className="py-2 pr-3">Title</th>
                  <th className="py-2 pr-3">CVSS</th>
                  <th className="py-2 pr-3">Checks</th>
                  <th className="py-2 pr-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {cves.map((c) => {
                  const sev = String(c.severity || 'info').toLowerCase()
                  const cveLink = c.cve_id?.startsWith('CVE-')
                    ? `https://nvd.nist.gov/vuln/detail/${c.cve_id}`
                    : null
                  return (
                    <tr
                      key={`${c.client_key}:${c.cve_id}`}
                      className="border-b border-dark-800/60 hover:bg-dark-800/30"
                    >
                      <td className="py-2 pr-3 font-mono text-xs">
                        {cveLink ? (
                          <a
                            href={cveLink}
                            target="_blank"
                            rel="noreferrer"
                            className="text-aegis-400 hover:underline inline-flex items-center gap-1"
                          >
                            {c.cve_id}
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        ) : (
                          c.cve_id
                        )}
                      </td>
                      <td className="py-2 pr-3">
                        <span className={`badge ${severityColors[sev]}`}>
                          {sev}
                        </span>
                      </td>
                      <td className="py-2 pr-3 text-dark-300">
                        {c.client_display_name}
                        <div className="text-[10px] text-dark-500 font-mono">
                          {c.client_key}
                        </div>
                      </td>
                      <td className="py-2 pr-3 text-white">{c.title}</td>
                      <td className="py-2 pr-3 text-dark-300">{c.cvss ?? '—'}</td>
                      <td className="py-2 pr-3 text-xs text-dark-400">
                        env: {c.env_checks_count} · active: {c.active_checks_count}
                      </td>
                      <td className="py-2 pr-3 text-right">
                        <div className="inline-flex items-center gap-1">
                          <button
                            onClick={() => openEdit(c)}
                            className="btn btn-ghost btn-sm"
                            title="Edit"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() =>
                              setConfirmDel({
                                clientKey: c.client_key,
                                cveId: c.cve_id,
                                title: c.title,
                              })
                            }
                            className="btn btn-ghost btn-sm text-red-400"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <CveModal
        open={!!editing}
        isNew={editing?.isNew}
        initial={editing?.cve}
        checkTypes={checkTypes}
        isSaving={createMut.isPending || updateMut.isPending}
        onClose={() => setEditing(null)}
        onSave={(cve) => {
          if (editing?.isNew) {
            createMut.mutate({ clientKey: editing.clientKey, cve })
          } else {
            updateMut.mutate({
              clientKey: editing.clientKey,
              cveId: editing.cve.id,
              cve,
            })
          }
        }}
      />

      {confirmDel && (
        <ConfirmModal
          title="Delete CVE"
          message={`Delete ${confirmDel.cveId} — "${confirmDel.title}"? A backup of the YAML is created automatically.`}
          onCancel={() => setConfirmDel(null)}
          onConfirm={() =>
            deleteMut.mutate({
              clientKey: confirmDel.clientKey,
              cveId: confirmDel.cveId,
            })
          }
          isPending={deleteMut.isPending}
        />
      )}
    </div>
  )
}

// ------------------------------------------------------------------
// Clients tab
// ------------------------------------------------------------------

function ClientsTab({ pluginId, qc }) {
  const [editing, setEditing] = useState(null)
  const [confirmDel, setConfirmDel] = useState(null)

  const { data: clients = [], isLoading } = useQuery({
    queryKey: ['scanner-clients', pluginId],
    queryFn: () => scannersApi.listClients(pluginId),
  })

  const createMut = useMutation({
    mutationFn: (data) => scannersApi.createClient(pluginId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-clients', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanners'] })
      toast.success('Client created')
      setEditing(null)
    },
    onError: (e) => toast.error(errMsg(e)),
  })
  const updateMut = useMutation({
    mutationFn: ({ key, data }) => scannersApi.updateClient(pluginId, key, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-clients', pluginId] })
      toast.success('Client updated')
      setEditing(null)
    },
    onError: (e) => toast.error(errMsg(e)),
  })
  const deleteMut = useMutation({
    mutationFn: (key) => scannersApi.deleteClient(pluginId, key),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-clients', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner-cves', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanners'] })
      toast.success('Client deleted')
      setConfirmDel(null)
    },
    onError: (e) => toast.error(errMsg(e)),
  })

  const openCreate = () => setEditing({ isNew: true, client: null })
  const openEdit = async (c) => {
    try {
      const full = await scannersApi.getClient(pluginId, c.key)
      setEditing({ isNew: false, client: full })
    } catch (e) {
      toast.error(errMsg(e))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <button onClick={openCreate} className="btn btn-primary">
          <Plus className="w-4 h-4" /> Add Client
        </button>
      </div>

      <div className="card">
        <div className="card-body">
          {isLoading ? (
            <div className="text-sm text-dark-400">Loading...</div>
          ) : clients.length === 0 ? (
            <div className="text-sm text-dark-400 py-6 text-center">
              No clients yet.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-dark-500 border-b border-dark-800">
                <tr>
                  <th className="py-2 pr-3">Key</th>
                  <th className="py-2 pr-3">Display</th>
                  <th className="py-2 pr-3">Vendor</th>
                  <th className="py-2 pr-3">Type</th>
                  <th className="py-2 pr-3">CVEs</th>
                  <th className="py-2 pr-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => (
                  <tr
                    key={c.key}
                    className="border-b border-dark-800/60 hover:bg-dark-800/30"
                  >
                    <td className="py-2 pr-3 font-mono text-xs text-dark-300">
                      {c.key}
                    </td>
                    <td className="py-2 pr-3 text-white">{c.display_name}</td>
                    <td className="py-2 pr-3 text-dark-300">{c.vendor}</td>
                    <td className="py-2 pr-3 text-dark-300">{c.type}</td>
                    <td className="py-2 pr-3 text-dark-300">{c.cves_count}</td>
                    <td className="py-2 pr-3 text-right">
                      <div className="inline-flex items-center gap-1">
                        <button
                          onClick={() => openEdit(c)}
                          className="btn btn-ghost btn-sm"
                          title="Edit"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() =>
                            setConfirmDel({ key: c.key, display: c.display_name, count: c.cves_count })
                          }
                          className="btn btn-ghost btn-sm text-red-400"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <ClientModal
        open={!!editing}
        isNew={editing?.isNew}
        initial={editing?.client}
        isSaving={createMut.isPending || updateMut.isPending}
        onClose={() => setEditing(null)}
        onSave={(form) => {
          if (editing?.isNew) {
            createMut.mutate(form)
          } else {
            const { key, ...rest } = form
            updateMut.mutate({ key: editing.client.key, data: rest })
          }
        }}
      />

      {confirmDel && (
        <ConfirmModal
          title="Delete client"
          message={`Delete "${confirmDel.display}" and its ${confirmDel.count} CVE(s)? A backup is created automatically.`}
          onCancel={() => setConfirmDel(null)}
          onConfirm={() => deleteMut.mutate(confirmDel.key)}
          isPending={deleteMut.isPending}
        />
      )}
    </div>
  )
}

// ------------------------------------------------------------------
// Globals tab
// ------------------------------------------------------------------

function GlobalsTab({ pluginId, qc }) {
  const { data: globals } = useQuery({
    queryKey: ['scanner-globals', pluginId],
    queryFn: () => scannersApi.getGlobals(pluginId),
  })
  const mut = useMutation({
    mutationFn: (data) => scannersApi.updateGlobals(pluginId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-globals', pluginId] })
      toast.success('Globals saved')
    },
    onError: (e) => toast.error(errMsg(e)),
  })
  return (
    <GlobalsPanel
      globals={globals}
      onSave={(v) => mut.mutate(v)}
      isSaving={mut.isPending}
    />
  )
}

// ------------------------------------------------------------------
// Backups tab
// ------------------------------------------------------------------

function BackupsTab({ pluginId, qc }) {
  const { data: backups = [], isLoading } = useQuery({
    queryKey: ['scanner-backups', pluginId],
    queryFn: () => scannersApi.listBackups(pluginId),
  })
  const [confirmRestore, setConfirmRestore] = useState(null)
  const mut = useMutation({
    mutationFn: (filename) => scannersApi.restore(pluginId, filename),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scanner-backups', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner-cves', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner-clients', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner-globals', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanner', pluginId] })
      qc.invalidateQueries({ queryKey: ['scanners'] })
      toast.success('Restored')
      setConfirmRestore(null)
    },
    onError: (e) => toast.error(errMsg(e)),
  })

  return (
    <div className="space-y-4">
      <p className="text-xs text-dark-400">
        Every write creates a timestamped backup. Restoring overwrites the current
        file (and creates a backup of it first).
      </p>
      <div className="card">
        <div className="card-body">
          {isLoading ? (
            <div className="text-sm text-dark-400">Loading...</div>
          ) : backups.length === 0 ? (
            <div className="text-sm text-dark-400 py-6 text-center">
              No backups yet.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-dark-500 border-b border-dark-800">
                <tr>
                  <th className="py-2 pr-3">Filename</th>
                  <th className="py-2 pr-3">Created</th>
                  <th className="py-2 pr-3">Size</th>
                  <th className="py-2 pr-3 text-right"></th>
                </tr>
              </thead>
              <tbody>
                {backups.map((b) => (
                  <tr
                    key={b.filename}
                    className="border-b border-dark-800/60 hover:bg-dark-800/30"
                  >
                    <td className="py-2 pr-3 font-mono text-xs text-dark-300">
                      {b.filename}
                    </td>
                    <td className="py-2 pr-3 text-dark-300">{b.created_at}</td>
                    <td className="py-2 pr-3 text-dark-300">{b.size} B</td>
                    <td className="py-2 pr-3 text-right">
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => setConfirmRestore(b.filename)}
                      >
                        <RotateCcw className="w-4 h-4" /> Restore
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {confirmRestore && (
        <ConfirmModal
          title="Restore backup"
          message={`Restore ${confirmRestore}? Current file will be backed up first.`}
          onCancel={() => setConfirmRestore(null)}
          onConfirm={() => mut.mutate(confirmRestore)}
          isPending={mut.isPending}
        />
      )}
    </div>
  )
}

// ------------------------------------------------------------------
// Confirm modal
// ------------------------------------------------------------------

function ConfirmModal({ title, message, onCancel, onConfirm, isPending }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60">
      <div className="w-full max-w-md bg-dark-900 border border-dark-700 rounded-xl shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-800">
          <h3 className="text-white font-semibold">{title}</h3>
          <button
            type="button"
            onClick={onCancel}
            className="text-dark-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-4 text-sm text-dark-300">{message}</div>
        <div className="px-6 py-4 border-t border-dark-800 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="btn btn-secondary"
            disabled={isPending}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="btn btn-danger"
            disabled={isPending}
          >
            {isPending ? 'Working...' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}
