import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Search,
  Target,
  Server,
  Cloud,
  Globe,
  MoreVertical,
  Edit,
  Trash2,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  ExternalLink,
} from 'lucide-react'
import { targetsApi } from '../services/api'
import { useAuthStore } from '../stores/authStore'
import toast from 'react-hot-toast'

const typeIcons = {
  mcp_server: Server,
  acp_server: Server,
  llm_api: Cloud,
  rest_api: Globe,
  graphql_api: Globe,
  websocket: Globe,
  grpc: Server,
  rag_system: Server,
  vector_db: Server,
  agent_orchestrator: Cloud,
  custom: Target,
}

const statusColors = {
  online: 'text-emerald-400',
  offline: 'text-red-400',
  unknown: 'text-dark-500',
}

function TargetCard({ target, onEdit, onDelete, onTest }) {
  const [showMenu, setShowMenu] = useState(false)
  const Icon = typeIcons[target.target_type] || Target

  return (
    <div className="card p-4 hover:border-dark-600 transition-all">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-dark-800 flex items-center justify-center">
            <Icon className="w-5 h-5 text-aegis-400" />
          </div>
          <div>
            <h3 className="font-medium text-white">{target.name}</h3>
            <p className="text-xs text-dark-500">{target.target_type.replace(/_/g, ' ')}</p>
          </div>
        </div>
        <div className="relative">
          <button
            onClick={() => setShowMenu(!showMenu)}
            className="p-1 text-dark-400 hover:text-white rounded"
          >
            <MoreVertical className="w-4 h-4" />
          </button>
          {showMenu && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setShowMenu(false)} />
              <div className="absolute right-0 mt-1 w-36 bg-dark-800 border border-dark-700 rounded-lg shadow-xl z-20 py-1">
                <button
                  onClick={() => { onTest(target); setShowMenu(false) }}
                  className="w-full px-3 py-2 text-left text-sm text-dark-300 hover:bg-dark-700 flex items-center gap-2"
                >
                  <Play className="w-4 h-4" />
                  Test Connection
                </button>
                <button
                  onClick={() => { onEdit(target); setShowMenu(false) }}
                  className="w-full px-3 py-2 text-left text-sm text-dark-300 hover:bg-dark-700 flex items-center gap-2"
                >
                  <Edit className="w-4 h-4" />
                  Edit
                </button>
                <button
                  onClick={() => { onDelete(target); setShowMenu(false) }}
                  className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-dark-700 flex items-center gap-2"
                >
                  <Trash2 className="w-4 h-4" />
                  Delete
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="space-y-2 mb-4">
        <div className="flex items-center gap-2 text-sm">
          <Globe className="w-4 h-4 text-dark-500" />
          <span className="text-dark-300 truncate">{target.host}</span>
          {target.port && <span className="text-dark-500">:{target.port}</span>}
        </div>
        {target.base_url && (
          <div className="flex items-center gap-2 text-sm">
            <ExternalLink className="w-4 h-4 text-dark-500" />
            <a 
              href={target.base_url} 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-aegis-400 hover:text-aegis-300 truncate"
            >
              {target.base_url}
            </a>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-2">
          <span className={`flex items-center gap-1 ${statusColors[target.status] || statusColors.unknown}`}>
            {target.status === 'online' ? (
              <CheckCircle className="w-3 h-3" />
            ) : target.status === 'offline' ? (
              <XCircle className="w-3 h-3" />
            ) : (
              <Clock className="w-3 h-3" />
            )}
            {target.status || 'Unknown'}
          </span>
        </div>
        {target.last_tested_at && (
          <span className="text-dark-500">
            Tested {new Date(target.last_tested_at).toLocaleDateString()}
          </span>
        )}
      </div>
    </div>
  )
}

function TargetModal({ target, onClose, onSave }) {
  const parseAuth = (raw) => {
    if (!raw) return { type: 'none' }
    if (typeof raw === 'object') return raw
    try { return JSON.parse(raw) } catch { return { type: 'none' } }
  }
  const initialAuth = target?.auth_config
    ? parseAuth(target.auth_config)
    : { type: 'none' }

  const [formData, setFormData] = useState(target || {
    name: '',
    target_type: 'mcp_server',
    host: '',
    port: '',
    base_url: '',
    protocol: 'http',
    description: '',
    auth_type: 'none',
  })
  const [authConfig, setAuthConfig] = useState(initialAuth)

  const handleSubmit = (e) => {
    e.preventDefault()
    // Serialize auth_config based on chosen type
    const out = { ...formData, auth_type: authConfig.type || 'none' }
    if (authConfig.type && authConfig.type !== 'none') {
      out.auth_config = JSON.stringify(authConfig)
    } else {
      out.auth_config = JSON.stringify({ type: 'none' })
    }
    onSave(out)
  }

  const setAuth = (k, v) => setAuthConfig((a) => ({ ...a, [k]: v }))
  const changeAuthType = (t) => {
    // Reset fields when switching auth type
    setAuthConfig({ type: t })
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="card-header flex items-center justify-between">
          <h2 className="font-semibold text-white">
            {target ? 'Edit Target' : 'Add Target'}
          </h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white">
            <XCircle className="w-5 h-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="card-body space-y-4">
          <div>
            <label className="label">Name</label>
            <input
              type="text"
              className="input"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              required
            />
          </div>

          <div>
            <label className="label">Target Type</label>
            <select
              className="select"
              value={formData.target_type}
              onChange={(e) => setFormData({ ...formData, target_type: e.target.value })}
            >
              <option value="mcp_server">MCP Server</option>
              <option value="acp_server">ACP Server</option>
              <option value="llm_api">LLM API</option>
              <option value="rest_api">REST API</option>
              <option value="graphql_api">GraphQL API</option>
              <option value="websocket">WebSocket</option>
              <option value="grpc">gRPC</option>
              <option value="rag_system">RAG System</option>
              <option value="vector_db">Vector Database</option>
              <option value="agent_orchestrator">Agent Orchestrator</option>
              <option value="custom">Custom</option>
            </select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">
                Host {formData.protocol === 'stdio' ? (
                  <span className="text-dark-500 text-xs">(not used for stdio)</span>
                ) : null}
              </label>
              <input
                type="text"
                className="input"
                placeholder={formData.protocol === 'stdio' ? 'localhost' : 'api.example.com'}
                value={formData.host}
                onChange={(e) => setFormData({ ...formData, host: e.target.value })}
                required={formData.protocol !== 'stdio'}
              />
            </div>
            <div>
              <label className="label">
                Port {formData.protocol === 'stdio' ? (
                  <span className="text-dark-500 text-xs">(not used for stdio)</span>
                ) : null}
              </label>
              <input
                type="number"
                className="input"
                placeholder={formData.protocol === 'stdio' ? '0' : '443'}
                value={formData.port}
                onChange={(e) => setFormData({ ...formData, port: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="label">
              Base URL {formData.protocol === 'stdio' ? (
                <span className="text-red-400 text-xs">* required for stdio — put the spawn command here</span>
              ) : null}
            </label>
            <input
              type={formData.protocol === 'stdio' ? 'text' : 'url'}
              className="input"
              placeholder={formData.protocol === 'stdio'
                ? 'stdio:npx -y @modelcontextprotocol/server-everything'
                : 'https://api.example.com/v1'}
              value={formData.base_url}
              onChange={(e) => setFormData({ ...formData, base_url: e.target.value })}
              required={formData.protocol === 'stdio'}
            />
          </div>

          <div>
            <label className="label">Protocol / Transport</label>
            <select
              className="select"
              value={formData.protocol}
              onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
            >
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
              <option value="sse">SSE (Server-Sent Events)</option>
              <option value="ws">WebSocket (ws)</option>
              <option value="wss">WebSocket TLS (wss)</option>
              <option value="stdio">stdio (subprocess — local MCP server)</option>
              <option value="grpc">gRPC</option>
            </select>
            {formData.protocol === 'stdio' && (
              <p className="text-xs text-dark-400 mt-1.5 leading-relaxed">
                For <code>stdio</code>, leave Host/Port blank and put the
                full spawn command in <b>Base URL</b> as{' '}
                <code>stdio:&lt;cmd&gt;</code>. Example:{' '}
                <code className="text-aegis-400 text-[11px]">
                  stdio:npx -y @modelcontextprotocol/server-everything
                </code>
              </p>
            )}
            {formData.protocol === 'sse' && (
              <p className="text-xs text-dark-400 mt-1.5">
                Base URL should point at the SSE endpoint (often <code>/sse</code>).
              </p>
            )}
          </div>

          <div className="border-t border-dark-800 pt-4 space-y-3">
            <div className="text-xs uppercase tracking-wide text-dark-500">
              Authentication
            </div>
            <div>
              <label className="label">Auth Type</label>
              <select
                className="select"
                value={authConfig.type || 'none'}
                onChange={(e) => changeAuthType(e.target.value)}
              >
                <option value="none">None</option>
                <option value="bearer">Bearer Token</option>
                <option value="api_key">API Key (header)</option>
                <option value="basic">HTTP Basic</option>
                <option value="oauth2">OAuth2 / JWT</option>
                <option value="custom">Custom Headers</option>
              </select>
            </div>

            {(authConfig.type === 'bearer' || authConfig.type === 'oauth2') && (
              <div>
                <label className="label">Token</label>
                <input
                  type="password"
                  className="input font-mono"
                  placeholder="eyJhbGciOi... or sk-..."
                  value={authConfig.token || ''}
                  onChange={(e) => setAuth('token', e.target.value)}
                />
              </div>
            )}

            {authConfig.type === 'api_key' && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Header Name</label>
                  <input
                    type="text"
                    className="input font-mono"
                    placeholder="X-API-Key"
                    value={authConfig.header || ''}
                    onChange={(e) => setAuth('header', e.target.value)}
                  />
                </div>
                <div>
                  <label className="label">Header Value</label>
                  <input
                    type="password"
                    className="input font-mono"
                    value={authConfig.value || ''}
                    onChange={(e) => setAuth('value', e.target.value)}
                  />
                </div>
              </div>
            )}

            {authConfig.type === 'basic' && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Username</label>
                  <input
                    type="text"
                    className="input"
                    value={authConfig.username || ''}
                    onChange={(e) => setAuth('username', e.target.value)}
                  />
                </div>
                <div>
                  <label className="label">Password</label>
                  <input
                    type="password"
                    className="input"
                    value={authConfig.password || ''}
                    onChange={(e) => setAuth('password', e.target.value)}
                  />
                </div>
              </div>
            )}

            {authConfig.type === 'custom' && (
              <div>
                <label className="label">Headers (JSON object)</label>
                <textarea
                  className="textarea font-mono text-xs"
                  rows={4}
                  placeholder='{"X-Signature":"...", "X-Tenant-Id":"..."}'
                  value={JSON.stringify(authConfig.headers || {}, null, 2)}
                  onChange={(e) => {
                    try {
                      setAuth('headers', JSON.parse(e.target.value))
                    } catch {
                      // ignore parse errors during typing
                    }
                  }}
                />
              </div>
            )}
          </div>

          <div>
            <label className="label">Description</label>
            <textarea
              className="textarea"
              rows={3}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <button type="button" onClick={onClose} className="btn-secondary">
              Cancel
            </button>
            <button type="submit" className="btn-primary">
              {target ? 'Save Changes' : 'Add Target'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Targets() {
  const queryClient = useQueryClient()
  const { isAdmin } = useAuthStore()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [editTarget, setEditTarget] = useState(null)

  const { data, isLoading } = useQuery({
    queryKey: ['targets', { search, target_type: typeFilter }],
    queryFn: () => targetsApi.getAll({
      search: search || undefined,
      target_type: typeFilter || undefined,
    }),
  })

  const createMutation = useMutation({
    mutationFn: (data) => targetsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries(['targets'])
      setModalOpen(false)
      toast.success('Target created successfully')
    },
    onError: (err) => {
      toast.error(err.response?.data?.error || 'Failed to create target')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => targetsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries(['targets'])
      setEditTarget(null)
      toast.success('Target updated successfully')
    },
    onError: (err) => {
      toast.error(err.response?.data?.error || 'Failed to update target')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => targetsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries(['targets'])
      toast.success('Target deleted successfully')
    },
    onError: (err) => {
      toast.error(err.response?.data?.error || 'Failed to delete target')
    },
  })

  const testMutation = useMutation({
    mutationFn: (id) => targetsApi.test(id),
    onSuccess: (data) => {
      queryClient.invalidateQueries(['targets'])
      if (data.success) {
        const bits = []
        if (data.server_info?.name) bits.push(data.server_info.name)
        if (data.protocol_version) bits.push(`v${data.protocol_version}`)
        if (typeof data.tools_count === 'number') {
          bits.push(`${data.tools_count} tools`)
        }
        toast.success(`MCP OK — ${bits.join(' · ') || 'handshake complete'}`,
                      { duration: 6000 })
      } else {
        toast.error(data.message || 'MCP handshake failed',
                    { duration: 6000 })
      }
    },
    onError: (err) => {
      toast.error(err?.response?.data?.message
                  || err?.response?.data?.error
                  || 'Connection test failed')
    },
  })

  const targets = data?.targets || []

  const handleSave = (data) => {
    if (editTarget) {
      updateMutation.mutate({ id: editTarget.id, data })
    } else {
      createMutation.mutate(data)
    }
  }

  const handleDelete = (target) => {
    if (confirm(`Delete target "${target.name}"?`)) {
      deleteMutation.mutate(target.id)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Targets</h1>
          <p className="text-dark-400 mt-1">
            {targets.length} targets configured
          </p>
        </div>
        <button onClick={() => setModalOpen(true)} className="btn-primary">
          <Plus className="w-4 h-4" />
          Add Target
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
          <input
            type="text"
            placeholder="Search targets..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input pl-10"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="select w-48"
        >
          <option value="">All Types</option>
          <option value="mcp_server">MCP Server</option>
          <option value="acp_server">ACP Server</option>
          <option value="llm_api">LLM API</option>
          <option value="rest_api">REST API</option>
          <option value="graphql_api">GraphQL API</option>
          <option value="rag_system">RAG System</option>
        </select>
      </div>

      {/* Target Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="spinner w-8 h-8" />
        </div>
      ) : targets.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-dark-400">
          <Target className="w-12 h-12 mb-4" />
          <p>No targets found</p>
          <button onClick={() => setModalOpen(true)} className="btn-primary mt-4">
            <Plus className="w-4 h-4" />
            Add Your First Target
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {targets.map((target) => (
            <TargetCard
              key={target.id}
              target={target}
              onEdit={setEditTarget}
              onDelete={handleDelete}
              onTest={(t) => testMutation.mutate(t.id)}
            />
          ))}
        </div>
      )}

      {/* Modal */}
      {(modalOpen || editTarget) && (
        <TargetModal
          target={editTarget}
          onClose={() => {
            setModalOpen(false)
            setEditTarget(null)
          }}
          onSave={handleSave}
        />
      )}
    </div>
  )
}
