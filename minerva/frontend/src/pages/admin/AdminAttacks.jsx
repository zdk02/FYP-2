import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Crosshair, Plus, Edit2, Trash2, Search, Shield, Code,
  AlertTriangle, Clock, Tag, Copy, X, Check, Settings2,
  GripVertical, ChevronUp, ChevronDown, Play, Terminal
} from 'lucide-react'
import { attacksApi, categoriesApi, payloadsApi, techniquesApi, targetsApi } from '../../services/api'
import toast from 'react-hot-toast'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'

const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const attackTypes = ['injection', 'extraction', 'manipulation', 'bypass', 'reconnaissance', 'exploitation', 'persistence', 'exfiltration']
const scriptLanguages = ['python', 'javascript', 'bash', 'powershell', 'ruby']
const parameterTypes = [
  { value: 'string', label: 'String' },
  { value: 'number', label: 'Number' },
  { value: 'boolean', label: 'Boolean (Yes/No)' },
  { value: 'select', label: 'Dropdown Select' },
  { value: 'text', label: 'Multi-line Text' },
  { value: 'password', label: 'Password (Hidden)' },
  { value: 'url', label: 'URL' },
  { value: 'file', label: 'File Path' },
]

const severityColors = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
  info: 'bg-gray-500/20 text-gray-400',
}

const defaultScriptTemplate = `#!/usr/bin/env python3
"""
Attack Script Template
======================
Parameters defined in the Parameters tab are passed via the 'params' dictionary.
"""

def execute(target, params, context):
    """
    Main execution function called by AEGIS.
    
    Args:
        target (dict): Target configuration
            - host: Target hostname or IP
            - port: Target port number  
            - protocol: Protocol (http, https, ws, etc.)
            - base_url: Full base URL
            - auth: Authentication details if configured
            
        params (dict): User-configurable parameters
            Access your defined parameters like:
            - params.get('param_name', 'default_value')
            
        context (dict): Execution context
            - campaign_id: Current campaign ID
            - execution_id: This execution's ID
            - logger: Logging function
    
    Returns:
        dict: Execution results
            - success (bool): Whether attack succeeded
            - findings (list): List of findings/vulnerabilities
            - evidence (list): Screenshots, responses, etc.
            - logs (list): Execution logs
    """
    results = {
        "success": False,
        "findings": [],
        "evidence": [],
        "logs": []
    }
    
    # Example: Access parameters
    # timeout = params.get('timeout', 30)
    # payload = params.get('payload', 'default')
    # verbose = params.get('verbose', False)
    
    try:
        # ===== YOUR ATTACK LOGIC HERE =====
        
        results["logs"].append(f"Attacking {target['host']}:{target['port']}")
        
        # Example finding:
        # results["findings"].append({
        #     "title": "Vulnerability Found",
        #     "severity": "high",
        #     "description": "Description of the issue",
        #     "evidence": "Proof of vulnerability",
        #     "remediation": "How to fix it"
        # })
        
        results["success"] = True
        
    except Exception as e:
        results["logs"].append(f"Error: {str(e)}")
        results["success"] = False
    
    return results
`

const emptyParameter = {
  name: '',
  type: 'string',
  default_value: '',
  description: '',
  required: false,
  options: '',
  min: '',
  max: '',
}

export default function AdminAttacks() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(null)
  const [showScriptModal, setShowScriptModal] = useState(null)
  const [showTestModal, setShowTestModal] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const [testParams, setTestParams] = useState({})
  const [testTarget, setTestTarget] = useState({ host: 'localhost', port: '8080', protocol: 'http' })
  const [editingAttack, setEditingAttack] = useState(null)
  const [activeTab, setActiveTab] = useState('basic')
  
  const [form, setForm] = useState({
    name: '',
    description: '',
    subcategory_id: '',
    severity: 'medium',
    attack_type: 'injection',
    script_language: 'python',
    script_content: defaultScriptTemplate,
    prerequisites: '',
    remediation: '',
    estimated_duration: 60,
    is_verified: false,
    payload_ids: [],
    technique_ids: [],
    tags: '',
    parameters: []
  })

  // Queries
  const { data: attacks, isLoading } = useQuery({
    queryKey: ['attacks'],
    queryFn: () => attacksApi.getAll({ include_script: true }),
  })

  const { data: categories } = useQuery({
    queryKey: ['categories'],
    queryFn: () => categoriesApi.getAll(),
  })

  const { data: payloads } = useQuery({
    queryKey: ['payloads'],
    queryFn: () => payloadsApi.getAll(),
  })

  const { data: techniques } = useQuery({
    queryKey: ['techniques'],
    queryFn: () => techniquesApi.getAll(),
  })

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.getAll({ limit: 100 }),
  })

  // Mutations
  const createMutation = useMutation({
    mutationFn: attacksApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attacks'] })
      closeModal()
      toast.success('Attack created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create attack')
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => attacksApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attacks'] })
      closeModal()
      toast.success('Attack updated successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to update attack')
  })

  const deleteMutation = useMutation({
    mutationFn: attacksApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attacks'] })
      setShowDeleteConfirm(null)
      toast.success('Attack deleted successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete attack')
  })

  const cloneMutation = useMutation({
    mutationFn: attacksApi.clone,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attacks'] })
      toast.success('Attack cloned successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to clone attack')
  })

  const testMutation = useMutation({
    mutationFn: ({ id, data }) => attacksApi.test(id, data),
    onSuccess: (result) => {
      setTestResult(result)
      toast.success('Attack test completed')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to test attack')
  })

  // Parse config_schema to parameters array
  const parseConfigSchema = (configSchema, defaultConfig) => {
    if (!configSchema) return []
    try {
      const schema = typeof configSchema === 'string' ? JSON.parse(configSchema) : configSchema
      const defaults = defaultConfig ? (typeof defaultConfig === 'string' ? JSON.parse(defaultConfig) : defaultConfig) : {}
      
      if (!schema.properties) return []
      
      return Object.entries(schema.properties).map(([name, prop]) => ({
        name,
        type: prop.format || (prop.type === 'integer' ? 'number' : prop.type) || 'string',
        default_value: defaults[name] !== undefined ? String(defaults[name]) : (prop.default !== undefined ? String(prop.default) : ''),
        description: prop.description || '',
        required: schema.required?.includes(name) || false,
        options: prop.enum ? prop.enum.join(', ') : '',
        min: prop.minimum !== undefined ? String(prop.minimum) : '',
        max: prop.maximum !== undefined ? String(prop.maximum) : '',
      }))
    } catch (e) {
      console.error('Failed to parse config schema:', e)
      return []
    }
  }

  // Convert parameters array to config_schema JSON
  const buildConfigSchema = (parameters) => {
    const schema = {
      type: 'object',
      properties: {},
      required: []
    }
    const defaults = {}

    parameters.forEach(param => {
      if (!param.name) return
      
      const prop = {
        type: param.type === 'number' ? 'number' : (param.type === 'boolean' ? 'boolean' : 'string'),
        description: param.description
      }
      
      if (param.type === 'select' && param.options) {
        prop.enum = param.options.split(',').map(o => o.trim()).filter(Boolean)
      }
      if (['text', 'password', 'url', 'file'].includes(param.type)) {
        prop.format = param.type
      }
      if (param.type === 'number') {
        if (param.min) prop.minimum = Number(param.min)
        if (param.max) prop.maximum = Number(param.max)
      }
      
      schema.properties[param.name] = prop
      
      if (param.required) {
        schema.required.push(param.name)
      }
      
      if (param.default_value !== '') {
        if (param.type === 'number') {
          defaults[param.name] = Number(param.default_value)
        } else if (param.type === 'boolean') {
          defaults[param.name] = param.default_value === 'true'
        } else {
          defaults[param.name] = param.default_value
        }
      }
    })

    return { config_schema: schema, default_config: defaults }
  }

  const openCreate = () => {
    setEditingAttack(null)
    setForm({
      name: '',
      description: '',
      subcategory_id: '',
      severity: 'medium',
      attack_type: 'injection',
      script_language: 'python',
      script_content: defaultScriptTemplate,
      prerequisites: '',
      remediation: '',
      estimated_duration: 60,
      is_verified: false,
      payload_ids: [],
      technique_ids: [],
      tags: '',
      parameters: [
        { name: 'timeout', type: 'number', default_value: '30', description: 'Request timeout in seconds', required: false, options: '', min: '1', max: '300' },
        { name: 'verbose', type: 'boolean', default_value: 'false', description: 'Enable verbose logging', required: false, options: '', min: '', max: '' },
      ]
    })
    setActiveTab('basic')
    setShowModal(true)
  }

  const openEdit = (attack) => {
    setEditingAttack(attack)
    const parameters = parseConfigSchema(attack.config_schema, attack.default_config)
    setForm({
      name: attack.name,
      description: attack.description || '',
      subcategory_id: attack.subcategory_id || '',
      severity: attack.severity,
      attack_type: attack.attack_type,
      script_language: attack.script_language || 'python',
      script_content: attack.script_content || defaultScriptTemplate,
      prerequisites: attack.prerequisites || '',
      remediation: attack.remediation || '',
      estimated_duration: attack.estimated_duration || 60,
      is_verified: attack.is_verified || false,
      payload_ids: attack.payloads?.map(p => p.id) || [],
      technique_ids: attack.techniques?.map(t => t.id) || [],
      tags: attack.tags?.join(', ') || '',
      parameters: parameters.length > 0 ? parameters : []
    })
    setActiveTab('basic')
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingAttack(null)
  }

  const openTest = (attack) => {
    // Parse default params from config
    let defaultParams = {}
    if (attack.default_config) {
      try {
        defaultParams = typeof attack.default_config === 'string' 
          ? JSON.parse(attack.default_config) 
          : attack.default_config
      } catch (e) {}
    }
    setTestParams(defaultParams)
    setTestTarget({ host: 'localhost', port: '8080', protocol: 'http' })
    setTestResult(null)
    setShowTestModal(attack)
  }

  const runTest = (dryRun = true) => {
    testMutation.mutate({
      id: showTestModal.id,
      data: {
        params: testParams,
        target: testTarget,
        dry_run: dryRun
      }
    })
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    
    const { config_schema, default_config } = buildConfigSchema(form.parameters)
    
    const submitData = {
      ...form,
      tags: form.tags ? form.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      config_schema: config_schema,  // Send as object, backend will JSON.dumps it
      default_config: default_config  // Send as object, backend will JSON.dumps it
    }
    delete submitData.parameters
    
    if (editingAttack) {
      updateMutation.mutate({ id: editingAttack.id, data: submitData })
    } else {
      createMutation.mutate(submitData)
    }
  }

  const addParameter = () => {
    setForm(prev => ({
      ...prev,
      parameters: [...prev.parameters, { ...emptyParameter }]
    }))
  }

  const updateParameter = (index, field, value) => {
    setForm(prev => ({
      ...prev,
      parameters: prev.parameters.map((p, i) => 
        i === index ? { ...p, [field]: value } : p
      )
    }))
  }

  const removeParameter = (index) => {
    setForm(prev => ({
      ...prev,
      parameters: prev.parameters.filter((_, i) => i !== index)
    }))
  }

  const moveParameter = (index, direction) => {
    const newIndex = index + direction
    if (newIndex < 0 || newIndex >= form.parameters.length) return
    
    setForm(prev => {
      const newParams = [...prev.parameters]
      const [removed] = newParams.splice(index, 1)
      newParams.splice(newIndex, 0, removed)
      return { ...prev, parameters: newParams }
    })
  }

  const togglePayload = (payloadId) => {
    setForm(prev => ({
      ...prev,
      payload_ids: prev.payload_ids.includes(payloadId)
        ? prev.payload_ids.filter(id => id !== payloadId)
        : [...prev.payload_ids, payloadId]
    }))
  }

  const toggleTechnique = (techniqueId) => {
    setForm(prev => ({
      ...prev,
      technique_ids: prev.technique_ids.includes(techniqueId)
        ? prev.technique_ids.filter(id => id !== techniqueId)
        : [...prev.technique_ids, techniqueId]
    }))
  }

  const allSubcategories = (Array.isArray(categories) ? categories : []).flatMap(cat => 
    (cat.subcategories || []).map(sub => ({
      ...sub,
      categoryName: cat.name
    }))
  )

  const filteredAttacks = (Array.isArray(attacks) ? attacks : []).filter(attack => {
    const matchesSearch = !search || 
      attack.name.toLowerCase().includes(search.toLowerCase()) ||
      attack.description?.toLowerCase().includes(search.toLowerCase())
    const matchesCategory = !filterCategory || attack.subcategory_id === filterCategory
    const matchesSeverity = !filterSeverity || attack.severity === filterSeverity
    return matchesSearch && matchesCategory && matchesSeverity
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Crosshair className="w-8 h-8 text-aegis-blue" />
            Attack Management
          </h1>
          <p className="text-gray-400 mt-1">Create attacks with configurable parameters</p>
        </div>
        <button onClick={openCreate} className="btn-primary">
          <Plus className="w-4 h-4" />
          New Attack
        </button>
      </div>

      {/* Filters */}
      <div className="card p-4">
        <div className="flex items-center gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
            <input
              type="text"
              placeholder="Search attacks..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-10"
            />
          </div>
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="select w-48"
          >
            <option value="">All Categories</option>
            {allSubcategories.map(sub => (
              <option key={sub.id} value={sub.id}>
                {sub.categoryName} / {sub.name}
              </option>
            ))}
          </select>
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="select w-40"
          >
            <option value="">All Severities</option>
            {severityOptions.map(sev => (
              <option key={sev} value={sev}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-4">
        {severityOptions.map(sev => {
          const count = (Array.isArray(attacks) ? attacks : []).filter(a => a.severity === sev).length
          return (
            <div key={sev} className="card p-4 text-center">
              <div className={`text-2xl font-bold ${severityColors[sev].split(' ')[1]}`}>{count}</div>
              <div className="text-sm text-dark-400 capitalize">{sev}</div>
            </div>
          )
        })}
      </div>

      {/* Attack List */}
      <div className="card overflow-hidden">
        <table className="w-full">
          <thead className="bg-dark-800">
            <tr>
              <th className="text-left p-4 text-dark-400 font-medium">Attack</th>
              <th className="text-left p-4 text-dark-400 font-medium">Category</th>
              <th className="text-left p-4 text-dark-400 font-medium">Type</th>
              <th className="text-left p-4 text-dark-400 font-medium">Severity</th>
              <th className="text-left p-4 text-dark-400 font-medium">Params</th>
              <th className="text-left p-4 text-dark-400 font-medium">Status</th>
              <th className="text-right p-4 text-dark-400 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-800">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-dark-400">
                  <div className="spinner w-6 h-6 mx-auto" />
                </td>
              </tr>
            ) : filteredAttacks.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-dark-400">
                  <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  No attacks found. Create one to get started.
                </td>
              </tr>
            ) : (
              filteredAttacks.map(attack => {
                const subcategory = allSubcategories.find(s => s.id === attack.subcategory_id)
                let paramCount = 0
                try {
                  const schema = attack.config_schema ? JSON.parse(attack.config_schema) : {}
                  paramCount = Object.keys(schema.properties || {}).length
                } catch (e) {}
                return (
                  <tr key={attack.id} className="hover:bg-dark-800/50">
                    <td className="p-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-dark-700 flex items-center justify-center">
                          <Crosshair className="w-5 h-5 text-aegis-blue" />
                        </div>
                        <div>
                          <div className="font-medium text-white">{attack.name}</div>
                          <div className="text-sm text-dark-400 truncate max-w-xs">
                            {attack.description || 'No description'}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="p-4">
                      <span className="text-sm text-dark-300">
                        {subcategory ? `${subcategory.categoryName} / ${subcategory.name}` : 'Uncategorized'}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className="badge bg-dark-700 text-dark-300">{attack.attack_type}</span>
                    </td>
                    <td className="p-4">
                      <span className={`badge ${severityColors[attack.severity]}`}>
                        {attack.severity}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className="text-sm text-dark-300 flex items-center gap-1">
                        <Settings2 className="w-3 h-3" />
                        {paramCount}
                      </span>
                    </td>
                    <td className="p-4">
                      {attack.is_verified ? (
                        <span className="badge bg-emerald-500/20 text-emerald-400">
                          <Shield className="w-3 h-3 mr-1" />
                          Verified
                        </span>
                      ) : (
                        <span className="badge bg-dark-700 text-dark-400">Draft</span>
                      )}
                    </td>
                    <td className="p-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openTest(attack)}
                          className="btn-ghost btn-sm text-emerald-400 hover:text-emerald-300"
                          title="Test Attack"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setShowScriptModal(attack)}
                          className="btn-ghost btn-sm"
                          title="View Script"
                        >
                          <Code className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => cloneMutation.mutate(attack.id)}
                          className="btn-ghost btn-sm"
                          title="Clone"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openEdit(attack)}
                          className="btn-ghost btn-sm"
                          title="Edit"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setShowDeleteConfirm(attack)}
                          className="btn-ghost btn-sm text-red-400 hover:text-red-300"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-5xl max-h-[90vh] overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-dark-700">
              <h2 className="text-lg font-semibold text-white">
                {editingAttack ? 'Edit Attack' : 'Create Attack'}
              </h2>
              <button onClick={closeModal} className="btn-ghost btn-sm">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-dark-700">
              {[
                { id: 'basic', label: 'Basic Info' },
                { id: 'parameters', label: `Parameters (${form.parameters.length})` },
                { id: 'script', label: 'Script' },
                { id: 'payloads', label: 'Payloads' },
                { id: 'techniques', label: 'Techniques' }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-3 text-sm font-medium transition-colors
                    ${activeTab === tab.id 
                      ? 'text-aegis-blue border-b-2 border-aegis-blue' 
                      : 'text-dark-400 hover:text-white'}`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <form onSubmit={handleSubmit}>
              <div className="p-4 space-y-4 max-h-[60vh] overflow-y-auto">
                {/* Basic Tab */}
                {activeTab === 'basic' && (
                  <>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="label">Name *</label>
                        <input
                          type="text"
                          className="input"
                          value={form.name}
                          onChange={(e) => setForm({ ...form, name: e.target.value })}
                          placeholder="e.g., MCP Tool Injection"
                          required
                        />
                      </div>
                      <div>
                        <label className="label">Category *</label>
                        <select
                          className="select"
                          value={form.subcategory_id}
                          onChange={(e) => setForm({ ...form, subcategory_id: e.target.value })}
                          required
                        >
                          <option value="">Select Category</option>
                          {allSubcategories.map(sub => (
                            <option key={sub.id} value={sub.id}>
                              {sub.categoryName} / {sub.name}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="label">Description</label>
                      <textarea
                        className="input min-h-[80px]"
                        value={form.description}
                        onChange={(e) => setForm({ ...form, description: e.target.value })}
                        placeholder="Describe what this attack does..."
                        rows={3}
                      />
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <label className="label">Severity</label>
                        <select
                          className="select"
                          value={form.severity}
                          onChange={(e) => setForm({ ...form, severity: e.target.value })}
                        >
                          {severityOptions.map(sev => (
                            <option key={sev} value={sev}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="label">Attack Type</label>
                        <select
                          className="select"
                          value={form.attack_type}
                          onChange={(e) => setForm({ ...form, attack_type: e.target.value })}
                        >
                          {attackTypes.map(type => (
                            <option key={type} value={type}>{type.charAt(0).toUpperCase() + type.slice(1)}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="label">Est. Duration (seconds)</label>
                        <input
                          type="number"
                          className="input"
                          value={form.estimated_duration}
                          onChange={(e) => setForm({ ...form, estimated_duration: parseInt(e.target.value) || 60 })}
                          min="1"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="label">Prerequisites</label>
                      <textarea
                        className="input"
                        value={form.prerequisites}
                        onChange={(e) => setForm({ ...form, prerequisites: e.target.value })}
                        placeholder="Required conditions for this attack..."
                        rows={2}
                      />
                    </div>

                    <div>
                      <label className="label">Remediation</label>
                      <textarea
                        className="input"
                        value={form.remediation}
                        onChange={(e) => setForm({ ...form, remediation: e.target.value })}
                        placeholder="How to fix this vulnerability..."
                        rows={2}
                      />
                    </div>

                    <div>
                      <label className="label">Tags (comma separated)</label>
                      <input
                        type="text"
                        className="input"
                        value={form.tags}
                        onChange={(e) => setForm({ ...form, tags: e.target.value })}
                        placeholder="mcp, injection, authentication"
                      />
                    </div>

                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        id="is_verified"
                        checked={form.is_verified}
                        onChange={(e) => setForm({ ...form, is_verified: e.target.checked })}
                        className="w-4 h-4 rounded border-dark-600 bg-dark-800 text-aegis-blue focus:ring-aegis-blue"
                      />
                      <label htmlFor="is_verified" className="text-sm text-dark-300">
                        Mark as verified (tested and working)
                      </label>
                    </div>
                  </>
                )}

                {/* Parameters Tab */}
                {activeTab === 'parameters' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-white font-medium">Attack Parameters</h3>
                        <p className="text-sm text-dark-400">
                          Define parameters users can customize. Access via <code className="text-aegis-blue">params.get('name', 'default')</code>
                        </p>
                      </div>
                      <button type="button" onClick={addParameter} className="btn-secondary btn-sm">
                        <Plus className="w-4 h-4" />
                        Add Parameter
                      </button>
                    </div>

                    {form.parameters.length === 0 ? (
                      <div className="text-center py-12 border border-dashed border-dark-700 rounded-lg">
                        <Settings2 className="w-12 h-12 mx-auto text-dark-600 mb-3" />
                        <p className="text-dark-400 mb-2">No parameters defined</p>
                        <button type="button" onClick={addParameter} className="btn-primary btn-sm">
                          <Plus className="w-4 h-4" />
                          Add First Parameter
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {form.parameters.map((param, index) => (
                          <div key={index} className="border border-dark-700 rounded-lg p-4 bg-dark-800/50">
                            <div className="flex items-start gap-3">
                              <div className="flex flex-col items-center gap-1 pt-2">
                                <button
                                  type="button"
                                  onClick={() => moveParameter(index, -1)}
                                  disabled={index === 0}
                                  className="p-1 text-dark-500 hover:text-white disabled:opacity-30"
                                >
                                  <ChevronUp className="w-4 h-4" />
                                </button>
                                <GripVertical className="w-4 h-4 text-dark-600" />
                                <button
                                  type="button"
                                  onClick={() => moveParameter(index, 1)}
                                  disabled={index === form.parameters.length - 1}
                                  className="p-1 text-dark-500 hover:text-white disabled:opacity-30"
                                >
                                  <ChevronDown className="w-4 h-4" />
                                </button>
                              </div>

                              <div className="flex-1 grid grid-cols-12 gap-3">
                                <div className="col-span-3">
                                  <label className="label text-xs">Name *</label>
                                  <input
                                    type="text"
                                    className="input text-sm"
                                    value={param.name}
                                    onChange={(e) => updateParameter(index, 'name', e.target.value.replace(/\s/g, '_'))}
                                    placeholder="param_name"
                                  />
                                </div>
                                <div className="col-span-2">
                                  <label className="label text-xs">Type</label>
                                  <select
                                    className="select text-sm"
                                    value={param.type}
                                    onChange={(e) => updateParameter(index, 'type', e.target.value)}
                                  >
                                    {parameterTypes.map(t => (
                                      <option key={t.value} value={t.value}>{t.label}</option>
                                    ))}
                                  </select>
                                </div>
                                <div className="col-span-3">
                                  <label className="label text-xs">Default Value</label>
                                  {param.type === 'boolean' ? (
                                    <select
                                      className="select text-sm"
                                      value={param.default_value}
                                      onChange={(e) => updateParameter(index, 'default_value', e.target.value)}
                                    >
                                      <option value="false">False</option>
                                      <option value="true">True</option>
                                    </select>
                                  ) : param.type === 'select' ? (
                                    <select
                                      className="select text-sm"
                                      value={param.default_value}
                                      onChange={(e) => updateParameter(index, 'default_value', e.target.value)}
                                    >
                                      <option value="">Select...</option>
                                      {param.options.split(',').map(o => o.trim()).filter(Boolean).map(opt => (
                                        <option key={opt} value={opt}>{opt}</option>
                                      ))}
                                    </select>
                                  ) : (
                                    <input
                                      type={param.type === 'number' ? 'number' : 'text'}
                                      className="input text-sm"
                                      value={param.default_value}
                                      onChange={(e) => updateParameter(index, 'default_value', e.target.value)}
                                      placeholder="Default..."
                                    />
                                  )}
                                </div>
                                <div className="col-span-4">
                                  <label className="label text-xs">Description</label>
                                  <input
                                    type="text"
                                    className="input text-sm"
                                    value={param.description}
                                    onChange={(e) => updateParameter(index, 'description', e.target.value)}
                                    placeholder="What does this do?"
                                  />
                                </div>

                                {param.type === 'select' && (
                                  <div className="col-span-6">
                                    <label className="label text-xs">Options (comma separated)</label>
                                    <input
                                      type="text"
                                      className="input text-sm"
                                      value={param.options}
                                      onChange={(e) => updateParameter(index, 'options', e.target.value)}
                                      placeholder="opt1, opt2, opt3"
                                    />
                                  </div>
                                )}
                                {param.type === 'number' && (
                                  <>
                                    <div className="col-span-3">
                                      <label className="label text-xs">Min</label>
                                      <input
                                        type="number"
                                        className="input text-sm"
                                        value={param.min}
                                        onChange={(e) => updateParameter(index, 'min', e.target.value)}
                                      />
                                    </div>
                                    <div className="col-span-3">
                                      <label className="label text-xs">Max</label>
                                      <input
                                        type="number"
                                        className="input text-sm"
                                        value={param.max}
                                        onChange={(e) => updateParameter(index, 'max', e.target.value)}
                                      />
                                    </div>
                                  </>
                                )}

                                <div className="col-span-12 flex items-center gap-4 mt-1">
                                  <label className="flex items-center gap-2 text-sm text-dark-400">
                                    <input
                                      type="checkbox"
                                      checked={param.required}
                                      onChange={(e) => updateParameter(index, 'required', e.target.checked)}
                                      className="w-3 h-3 rounded border-dark-600 bg-dark-800 text-aegis-blue"
                                    />
                                    Required
                                  </label>
                                </div>
                              </div>

                              <button
                                type="button"
                                onClick={() => removeParameter(index)}
                                className="p-2 text-dark-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {form.parameters.length > 0 && (
                      <div className="mt-6 p-4 bg-dark-800 rounded-lg border border-dark-700">
                        <h4 className="text-sm font-medium text-white mb-2">Usage in Script:</h4>
                        <pre className="text-xs text-dark-300 font-mono overflow-x-auto">
{form.parameters.map(p => p.name ? `${p.name} = params.get('${p.name}', ${
  p.type === 'number' ? (p.default_value || '0') :
  p.type === 'boolean' ? (p.default_value === 'true' ? 'True' : 'False') :
  `'${p.default_value || ''}'`
})` : '').filter(Boolean).join('\n')}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* Script Tab */}
                {activeTab === 'script' && (
                  <>
                    <div>
                      <label className="label">Script Language</label>
                      <select
                        className="select w-48"
                        value={form.script_language}
                        onChange={(e) => setForm({ ...form, script_language: e.target.value })}
                      >
                        {scriptLanguages.map(lang => (
                          <option key={lang} value={lang}>{lang.charAt(0).toUpperCase() + lang.slice(1)}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="label">Script Content</label>
                      <textarea
                        className="input font-mono text-sm min-h-[400px]"
                        value={form.script_content}
                        onChange={(e) => setForm({ ...form, script_content: e.target.value })}
                        spellCheck={false}
                      />
                    </div>
                  </>
                )}

                {/* Payloads Tab */}
                {activeTab === 'payloads' && (
                  <div className="space-y-2">
                    <p className="text-sm text-dark-400 mb-4">Select payloads for this attack:</p>
                    {(Array.isArray(payloads) ? payloads : []).length === 0 ? (
                      <p className="text-dark-500 text-center py-8">No payloads available.</p>
                    ) : (
                      <div className="grid grid-cols-2 gap-2 max-h-[400px] overflow-y-auto">
                        {(Array.isArray(payloads) ? payloads : []).map(payload => (
                          <button
                            key={payload.id}
                            type="button"
                            onClick={() => togglePayload(payload.id)}
                            className={`p-3 rounded-lg border text-left transition-colors
                              ${form.payload_ids.includes(payload.id)
                                ? 'border-aegis-blue bg-aegis-blue/10'
                                : 'border-dark-700 hover:border-dark-600'}`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-medium text-white">{payload.name}</span>
                              {form.payload_ids.includes(payload.id) && (
                                <Check className="w-4 h-4 text-aegis-blue" />
                              )}
                            </div>
                            <span className="text-xs text-dark-400">{payload.payload_type}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Techniques Tab */}
                {activeTab === 'techniques' && (
                  <div className="space-y-2">
                    <p className="text-sm text-dark-400 mb-4">Select MITRE ATT&CK techniques:</p>
                    {(Array.isArray(techniques) ? techniques : []).length === 0 ? (
                      <p className="text-dark-500 text-center py-8">No techniques available.</p>
                    ) : (
                      <div className="grid grid-cols-2 gap-2 max-h-[400px] overflow-y-auto">
                        {(Array.isArray(techniques) ? techniques : []).map(technique => (
                          <button
                            key={technique.id}
                            type="button"
                            onClick={() => toggleTechnique(technique.id)}
                            className={`p-3 rounded-lg border text-left transition-colors
                              ${form.technique_ids.includes(technique.id)
                                ? 'border-aegis-blue bg-aegis-blue/10'
                                : 'border-dark-700 hover:border-dark-600'}`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-aegis-blue text-sm">{technique.mitre_id}</span>
                              {form.technique_ids.includes(technique.id) && (
                                <Check className="w-4 h-4 text-aegis-blue" />
                              )}
                            </div>
                            <span className="text-sm text-white">{technique.name}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="flex justify-end gap-3 p-4 border-t border-dark-700">
                <button type="button" onClick={closeModal} className="btn-secondary">
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="btn-primary"
                  disabled={createMutation.isPending || updateMutation.isPending}
                >
                  {(createMutation.isPending || updateMutation.isPending) ? (
                    <div className="spinner w-4 h-4" />
                  ) : editingAttack ? 'Update Attack' : 'Create Attack'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Script Preview Modal */}
      {showScriptModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-4xl max-h-[80vh] overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-dark-700">
              <div>
                <h2 className="text-lg font-semibold text-white">{showScriptModal.name}</h2>
                <span className="text-sm text-dark-400">{showScriptModal.script_language}</span>
              </div>
              <button onClick={() => setShowScriptModal(null)} className="btn-ghost btn-sm">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 overflow-auto max-h-[60vh]">
              <SyntaxHighlighter
                language={showScriptModal.script_language || 'python'}
                style={oneDark}
                customStyle={{ margin: 0, borderRadius: '0.5rem', fontSize: '0.875rem' }}
              >
                {showScriptModal.script_content || '# No script content'}
              </SyntaxHighlighter>
            </div>
          </div>
        </div>
      )}

      {/* Delete Modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 p-6 max-w-md w-full">
            <h3 className="text-lg font-semibold text-white mb-2">Delete Attack</h3>
            <p className="text-dark-400 mb-4">
              Are you sure you want to delete <span className="text-white font-medium">{showDeleteConfirm.name}</span>?
            </p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowDeleteConfirm(null)} className="btn-secondary">
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(showDeleteConfirm.id)}
                className="btn-primary bg-red-600 hover:bg-red-700"
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? <div className="spinner w-4 h-4" /> : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Test Attack Modal */}
      {showTestModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-3xl max-h-[85vh] overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-dark-700">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center">
                  <Play className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-white">Test Attack</h2>
                  <p className="text-sm text-dark-400">{showTestModal.name}</p>
                </div>
              </div>
              <button onClick={() => setShowTestModal(null)} className="btn-ghost btn-sm">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 space-y-4 max-h-[60vh] overflow-y-auto">
              {/* Target Configuration */}
              <div className="space-y-3">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  Target Configuration
                </h3>
                {testTarget.protocol === 'stdio' ? (
                  <div className="bg-dark-800/50 border border-dark-700 rounded-lg px-3 py-2 text-sm">
                    <span className="text-dark-400">Transport:</span>{' '}
                    <span className="text-aegis-400 font-medium">stdio</span>
                    <span className="text-dark-500 text-xs ml-2">
                      (no host/port — spawns a subprocess)
                    </span>
                  </div>
                ) : (
                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <label className="label text-xs">Host</label>
                      <input
                        type="text"
                        className="input text-sm"
                        value={testTarget.host}
                        onChange={(e) => setTestTarget({ ...testTarget, host: e.target.value })}
                        placeholder="localhost"
                      />
                    </div>
                    <div>
                      <label className="label text-xs">Port</label>
                      <input
                        type="text"
                        className="input text-sm"
                        value={testTarget.port}
                        onChange={(e) => setTestTarget({ ...testTarget, port: e.target.value })}
                        placeholder="8080"
                      />
                    </div>
                    <div>
                      <label className="label text-xs">Protocol</label>
                      <select
                        className="select text-sm"
                        value={testTarget.protocol}
                        onChange={(e) => setTestTarget({ ...testTarget, protocol: e.target.value })}
                      >
                        <option value="http">HTTP</option>
                        <option value="https">HTTPS</option>
                        <option value="sse">SSE</option>
                        <option value="ws">WebSocket</option>
                        <option value="wss">WebSocket Secure</option>
                      </select>
                    </div>
                  </div>
                )}
                
                {/* Quick select from existing targets */}
                {targets?.targets?.length > 0 && (
                  <div>
                    <label className="label text-xs">Or select existing target</label>
                    <select
                      className="select text-sm"
                      onChange={(e) => {
                        const t = targets.targets.find(t => t.id === e.target.value)
                        if (t) {
                          // IMPORTANT: copy base_url + auth_config too, not
                          // just host/port/protocol. Otherwise stdio / SSE /
                          // authenticated targets break.
                          setTestTarget({
                            host: t.host || 'localhost',
                            port: String(t.port || 0),
                            protocol: t.protocol || 'http',
                            base_url: t.base_url || '',
                            auth_config: t.auth_config || undefined,
                            target_id: t.id,
                          })
                        }
                      }}
                    >
                      <option value="">-- Select a target --</option>
                      {targets.targets.map(t => (
                        <option key={t.id} value={t.id}>
                          {t.name} ({t.protocol === 'stdio'
                            ? 'stdio'
                            : `${t.host}${t.port ? ':' + t.port : ''}`})
                        </option>
                      ))}
                    </select>
                    {testTarget.base_url?.startsWith('stdio:') && (
                      <p className="text-xs text-dark-400 mt-1.5">
                        stdio target — spawn:{' '}
                        <code className="text-aegis-400">
                          {testTarget.base_url}
                        </code>
                      </p>
                    )}
                  </div>
                )}
              </div>

              {/* Parameters */}
              <div className="space-y-3">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <Settings2 className="w-4 h-4" />
                  Attack Parameters
                </h3>
                {(() => {
                  let schema = {}
                  try {
                    schema = showTestModal.config_schema 
                      ? (typeof showTestModal.config_schema === 'string' 
                          ? JSON.parse(showTestModal.config_schema) 
                          : showTestModal.config_schema)
                      : {}
                  } catch (e) {}
                  
                  const properties = schema.properties || {}
                  const paramNames = Object.keys(properties)
                  
                  if (paramNames.length === 0) {
                    return (
                      <p className="text-sm text-dark-500 italic">No configurable parameters for this attack.</p>
                    )
                  }
                  
                  const arrToText = (v) => Array.isArray(v) ? v.join('\n') : ''
                  const textToArr = (t) => String(t || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)
                  return (
                    <div className="grid grid-cols-2 gap-3">
                      {paramNames.map(name => {
                        const prop = properties[name]
                        const t = prop.type || (prop.enum ? 'enum' : 'string')
                        const numericMin = prop.minimum ?? prop.min
                        const numericMax = prop.maximum ?? prop.max
                        const isNumeric = t === 'integer' || t === 'number'
                        return (
                          <div key={name} className={t === 'array' ? 'col-span-2' : ''}>
                            <label className="label text-xs">
                              {prop.title || name}
                              {schema.required?.includes(name) && <span className="text-red-400 ml-1">*</span>}
                              {isNumeric && numericMin !== undefined && numericMax !== undefined && (
                                <span className="text-dark-500 ml-1 font-normal">({numericMin}–{numericMax})</span>
                              )}
                            </label>
                            {t === 'boolean' ? (
                              <select
                                className="select text-sm"
                                value={String(testParams[name] ?? prop.default ?? false)}
                                onChange={(e) => setTestParams({ ...testParams, [name]: e.target.value === 'true' })}
                              >
                                <option value="false">False</option>
                                <option value="true">True</option>
                              </select>
                            ) : prop.enum ? (
                              <select
                                className="select text-sm"
                                value={testParams[name] ?? prop.default ?? ''}
                                onChange={(e) => setTestParams({ ...testParams, [name]: e.target.value })}
                              >
                                {prop.enum.map(opt => (
                                  <option key={opt} value={opt}>{opt}</option>
                                ))}
                              </select>
                            ) : t === 'array' ? (
                              <textarea
                                rows={3}
                                className="input text-sm font-mono w-full"
                                placeholder="One value per line"
                                value={arrToText(testParams[name] ?? prop.default ?? [])}
                                onChange={(e) => setTestParams({ ...testParams, [name]: textToArr(e.target.value) })}
                              />
                            ) : (
                              <input
                                type={isNumeric ? 'number' : 'text'}
                                min={isNumeric ? numericMin : undefined}
                                max={isNumeric ? numericMax : undefined}
                                step={t === 'integer' ? 1 : (isNumeric ? 'any' : undefined)}
                                className="input text-sm"
                                value={testParams[name] ?? prop.default ?? ''}
                                onChange={(e) => setTestParams({
                                  ...testParams,
                                  [name]: isNumeric ? (e.target.value === '' ? '' : Number(e.target.value)) : e.target.value
                                })}
                                placeholder={prop.description || name}
                              />
                            )}
                            {prop.description && (
                              <p className="text-xs text-dark-500 mt-1">{prop.description}</p>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )
                })()}
              </div>

              {/* Test Result */}
              {testResult && (
                <div className="space-y-3">
                  <h3 className="text-white font-medium flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    Test Result
                  </h3>
                  <div className={`p-4 rounded-lg border ${
                    testResult.status === 'success' || testResult.status === 'validated'
                      ? 'bg-emerald-500/10 border-emerald-500/30'
                      : testResult.status === 'completed'
                      ? 'bg-blue-500/10 border-blue-500/30'
                      : testResult.status === 'error'
                      ? 'bg-red-500/10 border-red-500/30'
                      : 'bg-yellow-500/10 border-yellow-500/30'
                  }`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`text-sm font-medium ${
                        testResult.status === 'success' ? 'text-emerald-400' :
                        testResult.status === 'validated' ? 'text-emerald-400' :
                        testResult.status === 'completed' ? 'text-blue-400' :
                        testResult.status === 'error' ? 'text-red-400' :
                        'text-yellow-400'
                      }`}>
                        {testResult.status === 'success' ? '✓ Attack Successful' : 
                         testResult.status === 'validated' ? '✓ Configuration Valid' :
                         testResult.status === 'completed' ? '✓ Attack Completed' :
                         testResult.status === 'error' ? '✗ Error' : '⏳ Pending'}
                      </span>
                    </div>
                    <p className="text-sm text-dark-300 mb-3">{testResult.message}</p>
                    
                    {/* Findings */}
                    {testResult.findings && testResult.findings.length > 0 && (
                      <div className="mb-3">
                        <h4 className="text-sm font-medium text-white mb-2">
                          Findings ({testResult.findings.length})
                        </h4>
                        <div className="space-y-2">
                          {testResult.findings.map((finding, i) => (
                            <div key={i} className={`p-2 rounded border ${
                              finding.severity === 'critical' ? 'bg-red-500/10 border-red-500/30' :
                              finding.severity === 'high' ? 'bg-orange-500/10 border-orange-500/30' :
                              finding.severity === 'medium' ? 'bg-yellow-500/10 border-yellow-500/30' :
                              finding.severity === 'low' ? 'bg-blue-500/10 border-blue-500/30' :
                              'bg-gray-500/10 border-gray-500/30'
                            }`}>
                              <div className="flex items-center gap-2">
                                <span className={`text-xs px-1.5 py-0.5 rounded ${
                                  finding.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                                  finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                  finding.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                  finding.severity === 'low' ? 'bg-blue-500/20 text-blue-400' :
                                  'bg-gray-500/20 text-gray-400'
                                }`}>{finding.severity || 'info'}</span>
                                <span className="text-sm text-white font-medium">{finding.title}</span>
                              </div>
                              {finding.description && (
                                <p className="text-xs text-dark-400 mt-1">{finding.description}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Evidence */}
                    {testResult.evidence && testResult.evidence.length > 0 && (
                      <div className="mb-3">
                        <h4 className="text-sm font-medium text-white mb-2">Evidence</h4>
                        <div className="bg-dark-900 rounded p-2 font-mono text-xs text-dark-300 max-h-32 overflow-y-auto">
                          {testResult.evidence.map((ev, i) => (
                            <pre key={i} className="whitespace-pre-wrap">{JSON.stringify(ev, null, 2)}</pre>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {/* Execution Log */}
                    {testResult.execution_log && testResult.execution_log.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-white mb-2">Execution Log</h4>
                        <div className="bg-dark-900 rounded p-3 font-mono text-xs text-dark-300 max-h-48 overflow-y-auto">
                          {testResult.execution_log.map((line, i) => (
                            <div key={i} className={
                              line.includes('[ERROR]') || line.includes('[TRACEBACK]') ? 'text-red-400' :
                              line.includes('[SUCCESS]') ? 'text-emerald-400' :
                              line.includes('[WARN]') ? 'text-yellow-400' :
                              line.includes('[SCRIPT]') ? 'text-blue-400' :
                              'text-dark-300'
                            }>{line}</div>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    <div className="mt-3 text-xs text-dark-500">
                      <strong>Parameters:</strong> {JSON.stringify(testResult.parameters_used)}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-between gap-3 p-4 border-t border-dark-700">
              <button onClick={() => setShowTestModal(null)} className="btn-secondary">
                Close
              </button>
              <div className="flex gap-2">
                <button
                  onClick={() => runTest(true)}
                  className="btn-secondary"
                  disabled={testMutation.isPending}
                >
                  {testMutation.isPending ? <div className="spinner w-4 h-4" /> : 'Validate Config'}
                </button>
                <button
                  onClick={() => runTest(false)}
                  className="btn-primary bg-emerald-600 hover:bg-emerald-700"
                  disabled={testMutation.isPending}
                >
                  {testMutation.isPending ? <div className="spinner w-4 h-4" /> : (
                    <>
                      <Play className="w-4 h-4" />
                      Run Test
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
