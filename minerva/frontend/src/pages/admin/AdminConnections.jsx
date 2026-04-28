import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Plug, Plus, Edit2, Trash2, Search, Play, CheckCircle2,
  Loader2, Server, Globe, Database, Cloud, Code, XCircle,
  Terminal, Copy
} from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { connectionsApi } from '../../services/api'
import toast from 'react-hot-toast'

const connectionTypes = [
  { id: 'mcp_server', name: 'MCP Server', icon: Server, color: 'bg-blue-500/20 text-blue-400' },
  { id: 'rest_api', name: 'REST API', icon: Globe, color: 'bg-green-500/20 text-green-400' },
  { id: 'graphql', name: 'GraphQL', icon: Database, color: 'bg-purple-500/20 text-purple-400' },
  { id: 'websocket', name: 'WebSocket', icon: Plug, color: 'bg-orange-500/20 text-orange-400' },
  { id: 'cloud_service', name: 'Cloud Service', icon: Cloud, color: 'bg-cyan-500/20 text-cyan-400' },
  { id: 'custom', name: 'Custom', icon: Code, color: 'bg-gray-500/20 text-gray-400' },
]

const authMethods = [
  { id: 'none', name: 'None' },
  { id: 'api_key', name: 'API Key' },
  { id: 'bearer_token', name: 'Bearer Token' },
  { id: 'basic_auth', name: 'Basic Auth' },
  { id: 'oauth2', name: 'OAuth 2.0' },
  { id: 'mtls', name: 'Mutual TLS' },
  { id: 'custom', name: 'Custom' },
]

export default function AdminConnections() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editingConnection, setEditingConnection] = useState(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(null)
  const [previewConnection, setPreviewConnection] = useState(null)
  const [testingConnection, setTestingConnection] = useState(null)
  
  const [form, setForm] = useState({
    name: '',
    description: '',
    connection_type: 'mcp_server',
    auth_method: 'none',
    config_template: '{}',
    script: '',
    validation_script: '',
  })

  const { data: connections, isLoading } = useQuery({
    queryKey: ['connections'],
    queryFn: () => connectionsApi.getAll(),
  })

  const createMutation = useMutation({
    mutationFn: connectionsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['connections'] })
      closeModal()
      toast.success('Connection created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create connection')
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => connectionsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['connections'] })
      closeModal()
      toast.success('Connection updated successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to update connection')
  })

  const deleteMutation = useMutation({
    mutationFn: connectionsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['connections'] })
      setShowDeleteConfirm(null)
      toast.success('Connection deleted successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete connection')
  })

  const testMutation = useMutation({
    mutationFn: connectionsApi.test,
    onSuccess: (data) => {
      setTestingConnection(null)
      if (data.success) {
        toast.success('Connection test successful')
      } else {
        toast.error(`Connection test failed: ${data.error}`)
      }
    },
    onError: (error) => {
      setTestingConnection(null)
      toast.error(error.response?.data?.error || 'Connection test failed')
    }
  })

  const openCreate = () => {
    setEditingConnection(null)
    setForm({
      name: '',
      description: '',
      connection_type: 'mcp_server',
      auth_method: 'none',
      config_template: '{\n  "host": "",\n  "port": 8080\n}',
      script: '# Connection script\nimport requests\n\ndef connect(config):\n    """Establish connection to target"""\n    pass\n\ndef disconnect():\n    """Close connection"""\n    pass',
      validation_script: '# Validation script\ndef validate(config):\n    """Validate configuration"""\n    return True',
    })
    setShowModal(true)
  }

  const openEdit = (connection) => {
    setEditingConnection(connection)
    setForm({
      name: connection.name,
      description: connection.description || '',
      connection_type: connection.connection_type,
      auth_method: connection.auth_method,
      config_template: connection.config_template || '{}',
      script: connection.script || '',
      validation_script: connection.validation_script || '',
    })
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingConnection(null)
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editingConnection) {
      updateMutation.mutate({ id: editingConnection.id, data: form })
    } else {
      createMutation.mutate(form)
    }
  }

  const handleTest = (connection) => {
    setTestingConnection(connection.id)
    testMutation.mutate(connection.id)
  }

  const copyToClipboard = (content) => {
    navigator.clipboard.writeText(content)
    toast.success('Copied to clipboard')
  }

  const filteredConnections = (Array.isArray(connections) ? connections : []).filter(connection => {
    const matchesSearch = 
      connection.name.toLowerCase().includes(search.toLowerCase()) ||
      (connection.description?.toLowerCase().includes(search.toLowerCase()) || false)
    const matchesType = !typeFilter || connection.connection_type === typeFilter
    return matchesSearch && matchesType
  }) || []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Plug className="w-8 h-8 text-aegis-blue" />
            Connection Scripts
          </h1>
          <p className="text-gray-400 mt-1">Manage connection scripts for different target types</p>
        </div>
        <button onClick={openCreate} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add Connection
        </button>
      </div>

      {/* Filters */}
      <div className="card p-4">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search connections..."
              className="input pl-10 w-full"
            />
          </div>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="input"
          >
            <option value="">All Types</option>
            {connectionTypes.map((type) => (
              <option key={type.id} value={type.id}>{type.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Connections Grid */}
      {isLoading ? (
        <div className="card p-12 text-center">
          <Loader2 className="w-8 h-8 animate-spin text-aegis-blue mx-auto" />
        </div>
      ) : filteredConnections.length === 0 ? (
        <div className="card p-12 text-center">
          <Plug className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No connection scripts found</p>
          <button onClick={openCreate} className="btn-primary mt-4">
            Create First Connection
          </button>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {filteredConnections.map((connection) => {
            const typeConfig = connectionTypes.find(t => t.id === connection.connection_type) || connectionTypes[connectionTypes.length - 1]
            const TypeIcon = typeConfig.icon
            const authConfig = authMethods.find(a => a.id === connection.auth_method) || authMethods[0]
            
            return (
              <div key={connection.id} className="card p-5">
                <div className="flex items-start gap-4">
                  <div className={`p-3 rounded-lg ${typeConfig.color.split(' ')[0]}`}>
                    <TypeIcon className={`w-6 h-6 ${typeConfig.color.split(' ')[1]}`} />
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-semibold text-white">{connection.name}</h3>
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${typeConfig.color}`}>
                        {typeConfig.name}
                      </span>
                    </div>
                    
                    {connection.description && (
                      <p className="text-sm text-gray-400 mb-3">{connection.description}</p>
                    )}

                    <div className="flex items-center gap-4 text-xs text-gray-500">
                      <span className="flex items-center gap-1">
                        <Terminal className="w-3 h-3" />
                        {authConfig.name}
                      </span>
                      {connection.last_tested && (
                        <span className="flex items-center gap-1">
                          {connection.last_test_success ? (
                            <CheckCircle2 className="w-3 h-3 text-green-400" />
                          ) : (
                            <XCircle className="w-3 h-3 text-red-400" />
                          )}
                          Last test: {connection.last_test_success ? 'Passed' : 'Failed'}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 mt-4 pt-4 border-t border-dark-700">
                  <button
                    onClick={() => setPreviewConnection(connection)}
                    className="btn-secondary text-sm flex-1 flex items-center justify-center gap-2"
                  >
                    <Code className="w-4 h-4" />
                    View Script
                  </button>
                  <button
                    onClick={() => handleTest(connection)}
                    disabled={testingConnection === connection.id}
                    className="btn-secondary text-sm flex items-center gap-2"
                  >
                    {testingConnection === connection.id ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Play className="w-4 h-4" />
                    )}
                    Test
                  </button>
                  <button
                    onClick={() => openEdit(connection)}
                    className="p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                    title="Edit"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setShowDeleteConfirm(connection)}
                    className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                    title="Delete"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-dark-700">
              <h2 className="text-xl font-semibold text-white">
                {editingConnection ? 'Edit Connection Script' : 'Add Connection Script'}
              </h2>
            </div>
            
            <form onSubmit={handleSubmit} className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Name</label>
                  <input
                    type="text"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    className="input w-full"
                    placeholder="MCP Server Connection"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Connection Type</label>
                  <select
                    value={form.connection_type}
                    onChange={(e) => setForm({ ...form, connection_type: e.target.value })}
                    className="input w-full"
                  >
                    {connectionTypes.map((type) => (
                      <option key={type.id} value={type.id}>{type.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                  <input
                    type="text"
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                    className="input w-full"
                    placeholder="Connection for MCP protocol servers"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Auth Method</label>
                  <select
                    value={form.auth_method}
                    onChange={(e) => setForm({ ...form, auth_method: e.target.value })}
                    className="input w-full"
                  >
                    {authMethods.map((method) => (
                      <option key={method.id} value={method.id}>{method.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Configuration Template (JSON)</label>
                <textarea
                  value={form.config_template}
                  onChange={(e) => setForm({ ...form, config_template: e.target.value })}
                  className="input w-full font-mono text-sm"
                  placeholder="{}"
                  rows={5}
                />
                <p className="text-xs text-gray-500 mt-1">JSON template for connection configuration</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Connection Script (Python)</label>
                <textarea
                  value={form.script}
                  onChange={(e) => setForm({ ...form, script: e.target.value })}
                  className="input w-full font-mono text-sm"
                  placeholder="# Connection implementation"
                  rows={12}
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Validation Script (Optional)</label>
                <textarea
                  value={form.validation_script}
                  onChange={(e) => setForm({ ...form, validation_script: e.target.value })}
                  className="input w-full font-mono text-sm"
                  placeholder="# Validation implementation"
                  rows={6}
                />
              </div>

              <div className="flex gap-3 pt-4">
                <button type="button" onClick={closeModal} className="btn-secondary flex-1">
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                  className="btn-primary flex-1 flex items-center justify-center gap-2"
                >
                  {(createMutation.isPending || updateMutation.isPending) ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    editingConnection ? 'Update Connection' : 'Create Connection'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {previewConnection && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-dark-700 flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-white">{previewConnection.name}</h2>
                <p className="text-sm text-gray-400 mt-1">{previewConnection.description}</p>
              </div>
              <button
                onClick={() => copyToClipboard(previewConnection.script)}
                className="btn-secondary flex items-center gap-2"
              >
                <Copy className="w-4 h-4" />
                Copy Script
              </button>
            </div>
            
            <div className="p-6 space-y-6">
              {/* Config Template */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 mb-2">Configuration Template</h3>
                <SyntaxHighlighter
                  language="json"
                  style={oneDark}
                  customStyle={{
                    background: 'rgb(13, 17, 23)',
                    borderRadius: '0.5rem',
                    padding: '1rem',
                    fontSize: '0.875rem',
                  }}
                >
                  {previewConnection.config_template || '{}'}
                </SyntaxHighlighter>
              </div>

              {/* Connection Script */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 mb-2">Connection Script</h3>
                <SyntaxHighlighter
                  language="python"
                  style={oneDark}
                  customStyle={{
                    background: 'rgb(13, 17, 23)',
                    borderRadius: '0.5rem',
                    padding: '1rem',
                    fontSize: '0.875rem',
                  }}
                  showLineNumbers
                >
                  {previewConnection.script || '# No script defined'}
                </SyntaxHighlighter>
              </div>

              {/* Validation Script */}
              {previewConnection.validation_script && (
                <div>
                  <h3 className="text-sm font-medium text-gray-300 mb-2">Validation Script</h3>
                  <SyntaxHighlighter
                    language="python"
                    style={oneDark}
                    customStyle={{
                      background: 'rgb(13, 17, 23)',
                      borderRadius: '0.5rem',
                      padding: '1rem',
                      fontSize: '0.875rem',
                    }}
                  >
                    {previewConnection.validation_script}
                  </SyntaxHighlighter>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-dark-700">
              <button
                onClick={() => setPreviewConnection(null)}
                className="btn-secondary w-full"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-md p-6">
            <h2 className="text-xl font-semibold text-white mb-2">Delete Connection</h2>
            <p className="text-gray-400 mb-6">
              Are you sure you want to delete <span className="text-white font-medium">{showDeleteConfirm.name}</span>?
              Targets using this connection type may be affected.
            </p>
            <div className="flex gap-3">
              <button onClick={() => setShowDeleteConfirm(null)} className="btn-secondary flex-1">
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(showDeleteConfirm.id)}
                disabled={deleteMutation.isPending}
                className="btn-primary bg-red-500 hover:bg-red-600 flex-1 flex items-center justify-center gap-2"
              >
                {deleteMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Deleting...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-4 h-4" />
                    Delete
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
