import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Target, Plus, Edit2, Trash2, Search, ExternalLink,
  Loader2, Shield, Link2, CheckCircle
} from 'lucide-react'
import { techniquesApi } from '../../services/api'
import toast from 'react-hot-toast'

const tacticColors = {
  'reconnaissance': 'bg-blue-500/20 text-blue-400',
  'resource-development': 'bg-purple-500/20 text-purple-400',
  'initial-access': 'bg-red-500/20 text-red-400',
  'execution': 'bg-orange-500/20 text-orange-400',
  'persistence': 'bg-yellow-500/20 text-yellow-400',
  'privilege-escalation': 'bg-pink-500/20 text-pink-400',
  'defense-evasion': 'bg-green-500/20 text-green-400',
  'credential-access': 'bg-cyan-500/20 text-cyan-400',
  'discovery': 'bg-indigo-500/20 text-indigo-400',
  'lateral-movement': 'bg-teal-500/20 text-teal-400',
  'collection': 'bg-emerald-500/20 text-emerald-400',
  'command-and-control': 'bg-rose-500/20 text-rose-400',
  'exfiltration': 'bg-violet-500/20 text-violet-400',
  'impact': 'bg-red-600/20 text-red-500',
}

const tactics = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
]

export default function AdminTechniques() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editingTechnique, setEditingTechnique] = useState(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(null)
  
  const [form, setForm] = useState({
    technique_id: '',
    name: '',
    tactic: '',
    description: '',
    url: '',
    detection: '',
    mitigation: '',
  })

  const { data: techniques, isLoading } = useQuery({
    queryKey: ['techniques'],
    queryFn: () => techniquesApi.getAll(),
  })

  const createMutation = useMutation({
    mutationFn: techniquesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['techniques'] })
      closeModal()
      toast.success('Technique created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create technique')
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => techniquesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['techniques'] })
      closeModal()
      toast.success('Technique updated successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to update technique')
  })

  const deleteMutation = useMutation({
    mutationFn: techniquesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['techniques'] })
      setShowDeleteConfirm(null)
      toast.success('Technique deleted successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete technique')
  })

  const openCreate = () => {
    setEditingTechnique(null)
    setForm({
      technique_id: '',
      name: '',
      tactic: '',
      description: '',
      url: '',
      detection: '',
      mitigation: '',
    })
    setShowModal(true)
  }

  const openEdit = (technique) => {
    setEditingTechnique(technique)
    setForm({
      technique_id: technique.technique_id,
      name: technique.name,
      tactic: technique.tactic,
      description: technique.description || '',
      url: technique.url || '',
      detection: technique.detection || '',
      mitigation: technique.mitigation || '',
    })
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingTechnique(null)
    setForm({
      technique_id: '',
      name: '',
      tactic: '',
      description: '',
      url: '',
      detection: '',
      mitigation: '',
    })
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editingTechnique) {
      updateMutation.mutate({ id: editingTechnique.id, data: form })
    } else {
      createMutation.mutate(form)
    }
  }

  const filteredTechniques = (Array.isArray(techniques) ? techniques : []).filter(technique => {
    const matchesSearch = 
      technique.name.toLowerCase().includes(search.toLowerCase()) ||
      technique.technique_id.toLowerCase().includes(search.toLowerCase())
    const matchesTactic = !tacticFilter || technique.tactic === tacticFilter
    return matchesSearch && matchesTactic
  }) || []

  // Group techniques by tactic
  const groupedTechniques = filteredTechniques.reduce((acc, technique) => {
    const tactic = technique.tactic || 'other'
    if (!acc[tactic]) acc[tactic] = []
    acc[tactic].push(technique)
    return acc
  }, {})

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Target className="w-8 h-8 text-aegis-blue" />
            MITRE ATT&CK Techniques
          </h1>
          <p className="text-gray-400 mt-1">Manage attack techniques and tactics mapping</p>
        </div>
        <button onClick={openCreate} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add Technique
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
              placeholder="Search techniques..."
              className="input pl-10 w-full"
            />
          </div>
          <select
            value={tacticFilter}
            onChange={(e) => setTacticFilter(e.target.value)}
            className="input"
          >
            <option value="">All Tactics</option>
            {tactics.map((tactic) => (
              <option key={tactic} value={tactic}>
                {tactic.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="text-2xl font-bold text-white">{(Array.isArray(techniques) ? techniques.length : 0) || 0}</div>
          <div className="text-sm text-gray-400">Total Techniques</div>
        </div>
        <div className="card p-4">
          <div className="text-2xl font-bold text-white">
            {Object.keys(groupedTechniques).length}
          </div>
          <div className="text-sm text-gray-400">Tactics Covered</div>
        </div>
        <div className="card p-4">
          <div className="text-2xl font-bold text-white">
            {(Array.isArray(techniques) ? techniques : []).filter(t => t.detection).length || 0}
          </div>
          <div className="text-sm text-gray-400">With Detection</div>
        </div>
        <div className="card p-4">
          <div className="text-2xl font-bold text-white">
            {(Array.isArray(techniques) ? techniques : []).filter(t => t.mitigation).length || 0}
          </div>
          <div className="text-sm text-gray-400">With Mitigation</div>
        </div>
      </div>

      {/* Techniques List */}
      {isLoading ? (
        <div className="card p-12 text-center">
          <Loader2 className="w-8 h-8 animate-spin text-aegis-blue mx-auto" />
        </div>
      ) : Object.keys(groupedTechniques).length === 0 ? (
        <div className="card p-12 text-center">
          <Target className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No techniques found</p>
          <button onClick={openCreate} className="btn-primary mt-4">
            Add First Technique
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          {Object.entries(groupedTechniques).map(([tactic, tacticTechniques]) => (
            <div key={tactic} className="card overflow-hidden">
              <div className="p-4 border-b border-dark-700 bg-dark-800/50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${tacticColors[tactic] || 'bg-gray-500/20 text-gray-400'}`}>
                      {tactic.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                    </span>
                    <span className="text-sm text-gray-400">
                      {tacticTechniques.length} technique{tacticTechniques.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                </div>
              </div>
              
              <div className="divide-y divide-dark-700">
                {tacticTechniques.map((technique) => (
                  <div key={technique.id} className="p-4 hover:bg-dark-800/30">
                    <div className="flex items-start gap-4">
                      <div className="p-2 bg-dark-800 rounded-lg">
                        <Shield className="w-5 h-5 text-aegis-blue" />
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-1">
                          <span className="font-mono text-sm text-aegis-blue">{technique.technique_id}</span>
                          <h3 className="font-semibold text-white">{technique.name}</h3>
                        </div>
                        
                        {technique.description && (
                          <p className="text-sm text-gray-400 line-clamp-2 mb-2">{technique.description}</p>
                        )}

                        <div className="flex items-center gap-4 text-xs">
                          {technique.detection && (
                            <span className="flex items-center gap-1 text-green-400">
                              <CheckCircle className="w-3 h-3" />
                              Detection
                            </span>
                          )}
                          {technique.mitigation && (
                            <span className="flex items-center gap-1 text-blue-400">
                              <CheckCircle className="w-3 h-3" />
                              Mitigation
                            </span>
                          )}
                          {technique.url && (
                            <a 
                              href={technique.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 text-gray-400 hover:text-white"
                            >
                              <ExternalLink className="w-3 h-3" />
                              MITRE
                            </a>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => openEdit(technique)}
                          className="p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                          title="Edit Technique"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setShowDeleteConfirm(technique)}
                          className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                          title="Delete Technique"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-dark-700">
              <h2 className="text-xl font-semibold text-white">
                {editingTechnique ? 'Edit Technique' : 'Add New Technique'}
              </h2>
            </div>
            
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Technique ID</label>
                  <input
                    type="text"
                    value={form.technique_id}
                    onChange={(e) => setForm({ ...form, technique_id: e.target.value })}
                    className="input w-full font-mono"
                    placeholder="T1595"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Tactic</label>
                  <select
                    value={form.tactic}
                    onChange={(e) => setForm({ ...form, tactic: e.target.value })}
                    className="input w-full"
                    required
                  >
                    <option value="">Select Tactic</option>
                    {tactics.map((tactic) => (
                      <option key={tactic} value={tactic}>
                        {tactic.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="input w-full"
                  placeholder="Active Scanning"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  className="input w-full"
                  placeholder="Describe the technique..."
                  rows={3}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">MITRE URL</label>
                <input
                  type="url"
                  value={form.url}
                  onChange={(e) => setForm({ ...form, url: e.target.value })}
                  className="input w-full"
                  placeholder="https://attack.mitre.org/techniques/T1595/"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Detection</label>
                <textarea
                  value={form.detection}
                  onChange={(e) => setForm({ ...form, detection: e.target.value })}
                  className="input w-full"
                  placeholder="How to detect this technique..."
                  rows={2}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Mitigation</label>
                <textarea
                  value={form.mitigation}
                  onChange={(e) => setForm({ ...form, mitigation: e.target.value })}
                  className="input w-full"
                  placeholder="How to mitigate this technique..."
                  rows={2}
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
                    editingTechnique ? 'Update Technique' : 'Create Technique'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-md p-6">
            <h2 className="text-xl font-semibold text-white mb-2">Delete Technique</h2>
            <p className="text-gray-400 mb-6">
              Are you sure you want to delete <span className="text-white font-medium">{showDeleteConfirm.technique_id} - {showDeleteConfirm.name}</span>?
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
