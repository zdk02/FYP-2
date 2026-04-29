import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  FileCode2, Plus, Edit2, Trash2, Copy, Search,
  Loader2, Code, Tag, AlertTriangle, CheckCircle
} from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { payloadsApi } from '../../services/api'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

const payloadTypes = [
  { id: 'injection', name: 'Injection', color: 'bg-red-500/20 text-red-400' },
  { id: 'exfiltration', name: 'Exfiltration', color: 'bg-purple-500/20 text-purple-400' },
  { id: 'manipulation', name: 'Manipulation', color: 'bg-orange-500/20 text-orange-400' },
  { id: 'bypass', name: 'Bypass', color: 'bg-blue-500/20 text-blue-400' },
  { id: 'probe', name: 'Probe', color: 'bg-green-500/20 text-green-400' },
  { id: 'custom', name: 'Custom', color: 'bg-gray-500/20 text-gray-400' },
]

export default function AdminPayloads() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editingPayload, setEditingPayload] = useState(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(null)
  const [previewPayload, setPreviewPayload] = useState(null)
  
  const [form, setForm] = useState({
    name: '',
    description: '',
    payload_type: 'custom',
    content: '',
    variables: [],
  })

  const { data: payloads, isLoading } = useQuery({
    queryKey: ['payloads'],
    queryFn: () => payloadsApi.getAll(),
  })

  const createMutation = useMutation({
    mutationFn: payloadsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['payloads'] })
      closeModal()
      toast.success('Payload created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create payload')
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => payloadsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['payloads'] })
      closeModal()
      toast.success('Payload updated successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to update payload')
  })

  const deleteMutation = useMutation({
    mutationFn: payloadsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['payloads'] })
      setShowDeleteConfirm(null)
      toast.success('Payload deleted successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete payload')
  })

  const openCreate = () => {
    setEditingPayload(null)
    setForm({ name: '', description: '', payload_type: 'custom', content: '', variables: [] })
    setShowModal(true)
  }

  const openEdit = (payload) => {
    setEditingPayload(payload)
    setForm({
      name: payload.name,
      description: payload.description || '',
      payload_type: payload.payload_type,
      content: payload.content,
      variables: payload.variables || [],
    })
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingPayload(null)
    setForm({ name: '', description: '', payload_type: 'custom', content: '', variables: [] })
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editingPayload) {
      updateMutation.mutate({ id: editingPayload.id, data: form })
    } else {
      createMutation.mutate(form)
    }
  }

  const copyToClipboard = (content) => {
    navigator.clipboard.writeText(content)
    toast.success('Copied to clipboard')
  }

  const filteredPayloads = (Array.isArray(payloads) ? payloads : []).filter(payload => {
    const matchesSearch = 
      payload.name.toLowerCase().includes(search.toLowerCase()) ||
      payload.content.toLowerCase().includes(search.toLowerCase())
    const knownTypes = new Set(payloadTypes.filter(t => t.id !== 'custom').map(t => t.id))
    const matchesType = !typeFilter
      || payload.payload_type === typeFilter
      || (typeFilter === 'custom' && (!payload.payload_type || !knownTypes.has(payload.payload_type)))
    return matchesSearch && matchesType
  }) || []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <FileCode2 className="w-8 h-8 text-aegis-blue" />
            Payload Management
          </h1>
          <p className="text-gray-400 mt-1">Manage attack payloads and injection strings</p>
        </div>
        <button onClick={openCreate} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add Payload
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
              placeholder="Search payloads..."
              className="input pl-10 w-full"
            />
          </div>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="input"
          >
            <option value="">All Types</option>
            {payloadTypes.map((type) => (
              <option key={type.id} value={type.id}>{type.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Payloads Grid */}
      {isLoading ? (
        <div className="card p-12 text-center">
          <Loader2 className="w-8 h-8 animate-spin text-aegis-blue mx-auto" />
        </div>
      ) : filteredPayloads.length === 0 ? (
        <div className="card p-12 text-center">
          <FileCode2 className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No payloads found</p>
          <button onClick={openCreate} className="btn-primary mt-4">
            Create First Payload
          </button>
        </div>
      ) : (
        <div className="grid gap-4">
          {filteredPayloads.map((payload) => {
            const typeConfig = payloadTypes.find(t => t.id === payload.payload_type) || payloadTypes[payloadTypes.length - 1]
            return (
              <div key={payload.id} className="card p-4">
                <div className="flex items-start gap-4">
                  <div className="p-2 bg-dark-800 rounded-lg">
                    <Code className="w-5 h-5 text-aegis-blue" />
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-semibold text-white">{payload.name}</h3>
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${typeConfig.color}`}>
                        {typeConfig.name}
                      </span>
                    </div>
                    
                    {payload.description && (
                      <p className="text-sm text-gray-400 mb-3">{payload.description}</p>
                    )}
                    
                    {/* Preview */}
                    <div className="relative bg-dark-950 rounded-lg overflow-hidden">
                      <div className="p-3 font-mono text-sm text-gray-300 truncate">
                        {payload.content.substring(0, 100)}{payload.content.length > 100 ? '...' : ''}
                      </div>
                      <button
                        onClick={() => setPreviewPayload(payload)}
                        className="absolute right-2 top-2 text-xs text-gray-500 hover:text-white"
                      >
                        Expand
                      </button>
                    </div>

                    {/* Variables */}
                    {payload.variables?.length > 0 && (
                      <div className="flex items-center gap-2 mt-3">
                        <Tag className="w-4 h-4 text-gray-500" />
                        <div className="flex flex-wrap gap-1">
                          {payload.variables.map((v, i) => (
                            <span key={i} className="px-2 py-0.5 bg-dark-800 rounded text-xs text-gray-400">
                              {`{{${v}}}`}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => copyToClipboard(payload.content)}
                      className="p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                      title="Copy Payload"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => openEdit(payload)}
                      className="p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                      title="Edit Payload"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setShowDeleteConfirm(payload)}
                      className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                      title="Delete Payload"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-dark-700">
              <h2 className="text-xl font-semibold text-white">
                {editingPayload ? 'Edit Payload' : 'Add New Payload'}
              </h2>
            </div>
            
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Name</label>
                  <input
                    type="text"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    className="input w-full"
                    placeholder="Payload name"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Type</label>
                  <select
                    value={form.payload_type}
                    onChange={(e) => setForm({ ...form, payload_type: e.target.value })}
                    className="input w-full"
                  >
                    {payloadTypes.map((type) => (
                      <option key={type.id} value={type.id}>{type.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  className="input w-full"
                  placeholder="Brief description of the payload"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Payload Content</label>
                <textarea
                  value={form.content}
                  onChange={(e) => setForm({ ...form, content: e.target.value })}
                  className="input w-full font-mono text-sm"
                  placeholder="Enter payload content..."
                  rows={10}
                  required
                />
                <p className="text-xs text-gray-500 mt-1">
                  Use {"{{variable_name}}"} syntax for dynamic variables
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Variables (comma-separated)</label>
                <input
                  type="text"
                  value={form.variables?.join(', ') || ''}
                  onChange={(e) => setForm({ 
                    ...form, 
                    variables: e.target.value.split(',').map(v => v.trim()).filter(Boolean)
                  })}
                  className="input w-full"
                  placeholder="target_url, api_key, user_input"
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
                    editingPayload ? 'Update Payload' : 'Create Payload'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {previewPayload && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-dark-700 flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-white">{previewPayload.name}</h2>
                <p className="text-sm text-gray-400 mt-1">{previewPayload.description}</p>
              </div>
              <button
                onClick={() => copyToClipboard(previewPayload.content)}
                className="btn-secondary flex items-center gap-2"
              >
                <Copy className="w-4 h-4" />
                Copy
              </button>
            </div>
            
            <div className="p-6">
              <SyntaxHighlighter
                language="text"
                style={oneDark}
                customStyle={{
                  background: 'rgb(13, 17, 23)',
                  borderRadius: '0.5rem',
                  padding: '1rem',
                  fontSize: '0.875rem',
                }}
                wrapLongLines
              >
                {previewPayload.content}
              </SyntaxHighlighter>
            </div>

            <div className="p-6 border-t border-dark-700">
              <button
                onClick={() => setPreviewPayload(null)}
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
            <h2 className="text-xl font-semibold text-white mb-2">Delete Payload</h2>
            <p className="text-gray-400 mb-6">
              Are you sure you want to delete <span className="text-white font-medium">{showDeleteConfirm.name}</span>?
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
