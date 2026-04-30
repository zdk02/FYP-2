import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Target,
  Crosshair,
  Settings,
  Rocket,
} from 'lucide-react'
import { campaignsApi, targetsApi, categoriesApi, attacksApi } from '../services/api'
import toast from 'react-hot-toast'

const steps = [
  { id: 'basics', label: 'Basics', icon: Settings },
  { id: 'targets', label: 'Targets', icon: Target },
  { id: 'attacks', label: 'Attacks', icon: Crosshair },
  { id: 'review', label: 'Review', icon: Rocket },
]

export default function CampaignBuilder() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { id } = useParams()
  const [currentStep, setCurrentStep] = useState(0)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    pentest_type: 'external',
    mode: 'manual',
    scenario: 'direct',
    scope: '',
    rules_of_engagement: '',
    target_ids: [],
    attack_ids: [],
    // Scan-phase config (encoded into scope_definition on submit)
    run_scan_first: true,
    auto_select_attacks_from_scan: true,
    scan_plugins: ['client_vuln_scanner', 'server_vuln_scanner'],
  })

  // Fetch existing campaign if editing
  const { data: campaignData } = useQuery({
    queryKey: ['campaign', id],
    queryFn: () => campaignsApi.get(id),
    enabled: !!id,
  })

  // Fetch targets
  const { data: targetsData } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.getAll({ limit: 100 }),
  })

  // Fetch categories with attacks
  const { data: categoriesData } = useQuery({
    queryKey: ['categories'],
    queryFn: () => categoriesApi.getAll(true),
  })

  // Fetch flat attacks list (fallback when categorisation is empty / partial)
  const { data: attacksData } = useQuery({
    queryKey: ['attacks-flat'],
    queryFn: () => attacksApi.getAll({ limit: 200 }),
  })

  const createMutation = useMutation({
    mutationFn: (data) => campaignsApi.create(data),
    onSuccess: (res) => {
      toast.success('Campaign created successfully')
      queryClient.invalidateQueries({ queryKey: ['campaigns'] })
      const newId = res?.campaign?.id || res?.id
      if (newId) {
        navigate(`/campaigns/${newId}`)
      } else {
        navigate('/campaigns')
      }
    },
    onError: (err) => toast.error(err.response?.data?.error || 'Failed to create campaign'),
  })

  const targets = targetsData?.targets || []
  const categories = Array.isArray(categoriesData) ? categoriesData : []
  const allAttacks = Array.isArray(attacksData?.attacks)
    ? attacksData.attacks
    : (Array.isArray(attacksData) ? attacksData : [])
  const activeAttacks = allAttacks.filter(a => a.is_active !== false)

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1)
    }
  }

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
    }
  }

  const handleSubmit = () => {
    // Build the structured scope_definition so the backend can drive the
    // scan phase. Free-form text is preserved under `notes`.
    const scopePayload = {
      notes: formData.scope || '',
      phases: formData.run_scan_first ? ['scan', 'exploit'] : ['exploit'],
      scan_plugins: formData.scan_plugins,
      auto_select_attacks_from_scan: formData.auto_select_attacks_from_scan,
    }
    const submission = {
      ...formData,
      scope: scopePayload,
    }
    createMutation.mutate(submission)
  }

  const toggleTarget = (id) => {
    setFormData(prev => ({
      ...prev,
      target_ids: prev.target_ids.includes(id)
        ? prev.target_ids.filter(t => t !== id)
        : [...prev.target_ids, id]
    }))
  }

  const toggleAttack = (id) => {
    setFormData(prev => ({
      ...prev,
      attack_ids: prev.attack_ids.includes(id)
        ? prev.attack_ids.filter(a => a !== id)
        : [...prev.attack_ids, id]
    }))
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <button onClick={() => navigate('/campaigns')} className="btn-ghost p-2">
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-white">
            {id ? 'Edit Campaign' : 'New Campaign'}
          </h1>
          <p className="text-dark-400">Configure your penetration test campaign</p>
        </div>
      </div>

      {/* Steps */}
      <div className="flex items-center justify-between mb-8">
        {steps.map((step, index) => (
          <div key={step.id} className="flex items-center">
            <div
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors
                ${index === currentStep 
                  ? 'bg-aegis-600 text-white' 
                  : index < currentStep
                    ? 'bg-aegis-600/20 text-aegis-400'
                    : 'bg-dark-800 text-dark-500'}`}
            >
              {index < currentStep ? (
                <Check className="w-4 h-4" />
              ) : (
                <step.icon className="w-4 h-4" />
              )}
              <span className="text-sm font-medium">{step.label}</span>
            </div>
            {index < steps.length - 1 && (
              <div className={`w-16 h-0.5 mx-2 ${index < currentStep ? 'bg-aegis-600' : 'bg-dark-700'}`} />
            )}
          </div>
        ))}
      </div>

      {/* Step Content */}
      <div className="card">
        <div className="card-body">
          {currentStep === 0 && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Campaign Basics</h2>
              
              <div>
                <label className="label">Campaign Name</label>
                <input
                  type="text"
                  className="input"
                  placeholder="Q1 Security Audit"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>

              <div>
                <label className="label">Description</label>
                <textarea
                  className="textarea"
                  rows={3}
                  placeholder="Describe the campaign objectives..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="label">Pentest Type</label>
                  <select
                    className="select"
                    value={formData.pentest_type}
                    onChange={(e) => setFormData({ ...formData, pentest_type: e.target.value })}
                  >
                    <option value="external">External</option>
                    <option value="internal">Internal</option>
                    <option value="hybrid">Hybrid</option>
                  </select>
                </div>

                <div>
                  <label className="label">Mode</label>
                  <select
                    className="select"
                    value={formData.mode}
                    onChange={(e) => setFormData({ ...formData, mode: e.target.value })}
                  >
                    <option value="manual">Manual</option>
                    <option value="automated">Automated</option>
                    <option value="hybrid">Hybrid</option>
                  </select>
                </div>

                <div>
                  <label className="label">Scenario</label>
                  <select
                    className="select"
                    value={formData.scenario}
                    onChange={(e) => setFormData({ ...formData, scenario: e.target.value })}
                  >
                    <option value="direct">Direct Connection</option>
                    <option value="legitimate_client">Legitimate Client</option>
                    <option value="mitm">Man-in-the-Middle</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="label">Scope</label>
                <textarea
                  className="textarea"
                  rows={2}
                  placeholder="Define the scope of the engagement..."
                  value={formData.scope}
                  onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
                />
              </div>

              <div className="border border-dark-700 rounded-lg p-3 space-y-3 bg-dark-900/40">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Reconnaissance phase</h3>
                  <span className="text-[10px] uppercase tracking-wide text-dark-500">scan → exploit</span>
                </div>
                <p className="text-xs text-dark-400">
                  Run vulnerability scanners against every target <em>before</em> launching attacks.
                  Findings are recorded in the report alongside attack results.
                </p>

                <label className="flex items-start gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={formData.run_scan_first}
                    onChange={(e) =>
                      setFormData({ ...formData, run_scan_first: e.target.checked })
                    }
                  />
                  <span>
                    <span className="text-white">Run scanners first</span>
                    <span className="block text-xs text-dark-500">
                      Triggers <code>client_vuln_scanner</code> + <code>server_vuln_scanner</code> in a background thread when the campaign starts.
                    </span>
                  </span>
                </label>

                <label className="flex items-start gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={formData.auto_select_attacks_from_scan}
                    disabled={!formData.run_scan_first}
                    onChange={(e) =>
                      setFormData({ ...formData, auto_select_attacks_from_scan: e.target.checked })
                    }
                  />
                  <span>
                    <span className="text-white">Auto-select attacks from scan findings</span>
                    <span className="block text-xs text-dark-500">
                      If the scanner reports CWE-89 / CWE-918 / etc., the matching exploit attack is added to the campaign automatically.
                    </span>
                  </span>
                </label>

                {formData.run_scan_first && (
                  <div className="space-y-1">
                    <label className="text-xs text-dark-400">Scanner plugins (comma-separated)</label>
                    <input
                      type="text"
                      className="input"
                      value={(formData.scan_plugins || []).join(',')}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          scan_plugins: e.target.value
                            .split(',')
                            .map((s) => s.trim())
                            .filter(Boolean),
                        })
                      }
                      placeholder="client_vuln_scanner,server_vuln_scanner"
                    />
                  </div>
                )}
              </div>
            </div>
          )}

          {currentStep === 1 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold text-white">Select Targets</h2>
              <p className="text-sm text-dark-400">
                Selected: {formData.target_ids.length} targets
              </p>
              
              <div className="grid grid-cols-2 gap-3 max-h-96 overflow-y-auto">
                {targets.map((target) => (
                  <button
                    key={target.id}
                    onClick={() => toggleTarget(target.id)}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      formData.target_ids.includes(target.id)
                        ? 'border-aegis-500 bg-aegis-600/10'
                        : 'border-dark-700 bg-dark-800 hover:border-dark-600'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <div className={`w-4 h-4 rounded border flex items-center justify-center ${
                        formData.target_ids.includes(target.id)
                          ? 'border-aegis-500 bg-aegis-500'
                          : 'border-dark-600'
                      }`}>
                        {formData.target_ids.includes(target.id) && (
                          <Check className="w-3 h-3 text-white" />
                        )}
                      </div>
                      <span className="font-medium text-white">{target.name}</span>
                    </div>
                    <p className="text-xs text-dark-500 mt-1 ml-6">
                      {target.host}:{target.port}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {currentStep === 2 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-white">Select Attacks</h2>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setFormData({
                      ...formData,
                      attack_ids: activeAttacks.map(a => a.id),
                    })}
                    className="px-3 py-1 text-xs rounded border border-dark-600 text-white hover:border-aegis-500"
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormData({ ...formData, attack_ids: [] })}
                    className="px-3 py-1 text-xs rounded border border-dark-600 text-white hover:border-aegis-500"
                  >
                    Clear
                  </button>
                </div>
              </div>
              <p className="text-sm text-dark-400">
                Selected: {formData.attack_ids.length} of {activeAttacks.length} attacks
              </p>

              <div className="grid grid-cols-2 gap-3 max-h-96 overflow-y-auto">
                {activeAttacks.map((attack) => (
                  <button
                    key={attack.id}
                    type="button"
                    onClick={() => toggleAttack(attack.id)}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      formData.attack_ids.includes(attack.id)
                        ? 'border-aegis-500 bg-aegis-600/10'
                        : 'border-dark-700 bg-dark-800 hover:border-dark-600'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <div className={`w-4 h-4 rounded border flex items-center justify-center ${
                        formData.attack_ids.includes(attack.id)
                          ? 'border-aegis-500 bg-aegis-500'
                          : 'border-dark-600'
                      }`}>
                        {formData.attack_ids.includes(attack.id) && (
                          <Check className="w-3 h-3 text-white" />
                        )}
                      </div>
                      <span className="font-medium text-white truncate">{attack.name}</span>
                    </div>
                    {attack.severity && (
                      <p className="text-xs text-dark-500 mt-1 ml-6 capitalize">
                        {attack.severity}
                        {attack.category ? ` · ${attack.category}` : ''}
                      </p>
                    )}
                  </button>
                ))}
                {activeAttacks.length === 0 && (
                  <p className="text-xs text-dark-500 col-span-2">
                    No attacks loaded. Run <code>python -m scripts.seed_pro_attacks</code> in the backend.
                  </p>
                )}
              </div>
            </div>
          )}

          {currentStep === 3 && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Review Campaign</h2>
              
              <div className="grid grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <p className="text-xs text-dark-500">Campaign Name</p>
                    <p className="text-white">{formData.name || 'Not set'}</p>
                  </div>
                  <div>
                    <p className="text-xs text-dark-500">Type</p>
                    <p className="text-white capitalize">{formData.pentest_type}</p>
                  </div>
                  <div>
                    <p className="text-xs text-dark-500">Mode</p>
                    <p className="text-white capitalize">{formData.mode}</p>
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs text-dark-500">Targets</p>
                    <p className="text-white">{formData.target_ids.length} selected</p>
                  </div>
                  <div>
                    <p className="text-xs text-dark-500">Attacks</p>
                    <p className="text-white">{formData.attack_ids.length} selected</p>
                  </div>
                  <div>
                    <p className="text-xs text-dark-500">Scenario</p>
                    <p className="text-white capitalize">{formData.scenario.replace(/_/g, ' ')}</p>
                  </div>
                </div>
              </div>

              {formData.description && (
                <div>
                  <p className="text-xs text-dark-500">Description</p>
                  <p className="text-dark-300">{formData.description}</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="card-header flex items-center justify-between border-t border-b-0">
          <button
            onClick={handleBack}
            disabled={currentStep === 0}
            className="btn-secondary"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>

          {currentStep < steps.length - 1 ? (
            <button onClick={handleNext} className="btn-primary">
              Next
              <ArrowRight className="w-4 h-4" />
            </button>
          ) : (
            <button 
              onClick={handleSubmit} 
              disabled={createMutation.isPending}
              className="btn-primary"
            >
              {createMutation.isPending ? (
                <div className="spinner w-4 h-4" />
              ) : (
                <>
                  <Rocket className="w-4 h-4" />
                  Create Campaign
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
