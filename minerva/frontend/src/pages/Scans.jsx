import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Radar, Plus, Play, Pause, Square, Trash2, RefreshCw, 
  Globe, Server, Shield, Eye, Clock, Target, AlertTriangle,
  CheckCircle, XCircle, Loader2, ChevronDown, ChevronRight
} from 'lucide-react'
import { scansApi, targetsApi } from '../services/api'
import api from '../services/api'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

const scanTypes = [
  { id: 'network', name: 'Network Discovery', icon: Globe, description: 'Discover hosts and services on the network' },
  { id: 'port', name: 'Port Scan', icon: Server, description: 'Scan for open ports and services' },
  { id: 'vulnerability', name: 'Vulnerability Scan', icon: Shield, description: 'Identify known vulnerabilities' },
  { id: 'service', name: 'Service Detection', icon: Target, description: 'Detect service versions and configurations' },
]

const statusConfig = {
  pending: { color: 'bg-yellow-500/20 text-yellow-400', icon: Clock },
  running: { color: 'bg-blue-500/20 text-blue-400', icon: Loader2, spin: true },
  completed: { color: 'bg-green-500/20 text-green-400', icon: CheckCircle },
  failed: { color: 'bg-red-500/20 text-red-400', icon: XCircle },
  cancelled: { color: 'bg-gray-500/20 text-gray-400', icon: Square },
}

export default function Scans() {
  const queryClient = useQueryClient()
  const [showNewScan, setShowNewScan] = useState(false)
  const [selectedType, setSelectedType] = useState('network')
  const [expandedScans, setExpandedScans] = useState(new Set())
  const [newScan, setNewScan] = useState({
    name: '',
    scan_type: 'network',
    target_range: '',
    port_range: '1-1000',
    options: {}
  })

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.getAll(),
  })

  const createMutation = useMutation({
    mutationFn: scansApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setShowNewScan(false)
      setNewScan({ name: '', scan_type: 'network', target_range: '', port_range: '1-1000', options: {} })
      toast.success('Scan created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create scan')
  })

  const startMutation = useMutation({
    mutationFn: scansApi.start,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      toast.success('Scan started')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to start scan')
  })

  const stopMutation = useMutation({
    mutationFn: scansApi.stop,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      toast.success('Scan stopped')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to stop scan')
  })

  const deleteMutation = useMutation({
    mutationFn: scansApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      toast.success('Scan deleted')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete scan')
  })

  const importHostMutation = useMutation({
    mutationFn: ({ scanId, host }) =>
      api.post(`/scans/${scanId}/hosts/import`, host).then((r) => r.data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      if (data.created) {
        toast.success(`Target added: ${data.target?.host || data.target?.name}`)
      } else {
        toast(`Target already exists: ${data.target?.host || data.target?.name}`)
      }
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to import target')
  })

  const handleCreateScan = (e) => {
    e.preventDefault()
    createMutation.mutate(newScan)
  }

  const toggleExpanded = (id) => {
    const newExpanded = new Set(expandedScans)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedScans(newExpanded)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Radar className="w-8 h-8 text-aegis-blue" />
            Network Scans
          </h1>
          <p className="text-gray-400 mt-1">Discover and analyze target infrastructure</p>
        </div>
        <button
          onClick={() => setShowNewScan(true)}
          className="btn-primary flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* New Scan Modal */}
      {showNewScan && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-dark-700">
              <h2 className="text-xl font-semibold text-white">Configure New Scan</h2>
              <p className="text-gray-400 text-sm mt-1">Set up a network scan to discover targets</p>
            </div>
            
            <form onSubmit={handleCreateScan} className="p-6 space-y-6">
              {/* Scan Name */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Scan Name</label>
                <input
                  type="text"
                  value={newScan.name}
                  onChange={(e) => setNewScan({ ...newScan, name: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., Production Network Scan"
                  required
                />
              </div>

              {/* Scan Type */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-3">Scan Type</label>
                <div className="grid grid-cols-2 gap-3">
                  {scanTypes.map((type) => {
                    const Icon = type.icon
                    return (
                      <button
                        key={type.id}
                        type="button"
                        onClick={() => setNewScan({ ...newScan, scan_type: type.id })}
                        className={`p-4 rounded-lg border text-left transition-all ${
                          newScan.scan_type === type.id
                            ? 'border-aegis-blue bg-aegis-blue/10'
                            : 'border-dark-700 hover:border-dark-600'
                        }`}
                      >
                        <Icon className={`w-5 h-5 mb-2 ${
                          newScan.scan_type === type.id ? 'text-aegis-blue' : 'text-gray-400'
                        }`} />
                        <div className="font-medium text-white">{type.name}</div>
                        <div className="text-xs text-gray-500 mt-1">{type.description}</div>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Target Range */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Target Range</label>
                <input
                  type="text"
                  value={newScan.target_range}
                  onChange={(e) => setNewScan({ ...newScan, target_range: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., 192.168.1.0/24 or 10.0.0.1-10.0.0.255"
                  required
                />
                <p className="text-xs text-gray-500 mt-1">CIDR notation or IP range</p>
              </div>

              {/* Port Range (for port scan) */}
              {(newScan.scan_type === 'port' || newScan.scan_type === 'service') && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Port Range</label>
                  <input
                    type="text"
                    value={newScan.port_range}
                    onChange={(e) => setNewScan({ ...newScan, port_range: e.target.value })}
                    className="input w-full"
                    placeholder="e.g., 1-1000 or 22,80,443,8080"
                  />
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowNewScan(false)}
                  className="btn-secondary flex-1"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="btn-primary flex-1 flex items-center justify-center gap-2"
                >
                  {createMutation.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    <>
                      <Radar className="w-4 h-4" />
                      Create Scan
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Scans List */}
      <div className="card">
        <div className="p-4 border-b border-dark-700 flex items-center justify-between">
          <h2 className="font-semibold text-white">Scan History</h2>
          <button 
            onClick={() => queryClient.invalidateQueries({ queryKey: ['scans'] })}
            className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-dark-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        {isLoading ? (
          <div className="p-12 text-center">
            <Loader2 className="w-8 h-8 animate-spin text-aegis-blue mx-auto mb-3" />
            <p className="text-gray-400">Loading scans...</p>
          </div>
        ) : !scans?.scans?.length ? (
          <div className="p-12 text-center">
            <Radar className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">No scans yet</p>
            <p className="text-gray-500 text-sm mt-1">Create a new scan to discover targets</p>
          </div>
        ) : (
          <div className="divide-y divide-dark-700">
            {scans.scans.map((scan) => {
              const status = statusConfig[scan.status] || statusConfig.pending
              const StatusIcon = status.icon
              const isExpanded = expandedScans.has(scan.id)

              return (
                <div key={scan.id} className="p-4">
                  <div className="flex items-center gap-4">
                    {/* Expand Toggle */}
                    <button
                      onClick={() => toggleExpanded(scan.id)}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-5 h-5" />
                      ) : (
                        <ChevronRight className="w-5 h-5" />
                      )}
                    </button>

                    {/* Scan Type Icon */}
                    <div className="p-2 bg-dark-800 rounded-lg">
                      {scanTypes.find(t => t.id === scan.scan_type)?.icon && (
                        (() => {
                          const TypeIcon = scanTypes.find(t => t.id === scan.scan_type).icon
                          return <TypeIcon className="w-5 h-5 text-aegis-blue" />
                        })()
                      )}
                    </div>

                    {/* Scan Info */}
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-white">{scan.name}</div>
                      <div className="text-sm text-gray-400 flex items-center gap-3 mt-1">
                        <span>{scan.target_range}</span>
                        <span className="text-gray-600">•</span>
                        <span>{scanTypes.find(t => t.id === scan.scan_type)?.name}</span>
                      </div>
                    </div>

                    {/* Status */}
                    <span className={`px-2.5 py-1 rounded-full text-xs font-medium flex items-center gap-1.5 ${status.color}`}>
                      <StatusIcon className={`w-3.5 h-3.5 ${status.spin ? 'animate-spin' : ''}`} />
                      {scan.status}
                    </span>

                    {/* Results Count */}
                    {scan.results_count > 0 && (
                      <span className="text-sm text-gray-400">
                        {scan.results_count} hosts found
                      </span>
                    )}

                    {/* Actions */}
                    <div className="flex items-center gap-1">
                      {scan.status === 'pending' && (
                        <button
                          onClick={() => startMutation.mutate(scan.id)}
                          disabled={startMutation.isPending}
                          className="p-2 text-green-400 hover:bg-green-400/10 rounded-lg transition-colors"
                          title="Start Scan"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                      )}
                      {scan.status === 'running' && (
                        <button
                          onClick={() => stopMutation.mutate(scan.id)}
                          disabled={stopMutation.isPending}
                          className="p-2 text-yellow-400 hover:bg-yellow-400/10 rounded-lg transition-colors"
                          title="Stop Scan"
                        >
                          <Square className="w-4 h-4" />
                        </button>
                      )}
                      <button
                        onClick={() => deleteMutation.mutate(scan.id)}
                        disabled={deleteMutation.isPending || scan.status === 'running'}
                        className="p-2 text-red-400 hover:bg-red-400/10 rounded-lg transition-colors disabled:opacity-50"
                        title="Delete Scan"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Expanded Results */}
                  {isExpanded && scan.results && (
                    <div className="mt-4 ml-12 p-4 bg-dark-800 rounded-lg">
                      <h4 className="font-medium text-white mb-3">Discovered Hosts</h4>
                      {scan.results.hosts?.length > 0 ? (
                        <div className="space-y-2">
                          {scan.results.hosts.map((host, idx) => (
                            <div key={idx} className="flex items-center gap-4 p-3 bg-dark-900 rounded-lg">
                              <Server className="w-4 h-4 text-gray-400" />
                              <div className="flex-1">
                                <div className="text-white font-mono">{host.ip}</div>
                                {host.hostname && (
                                  <div className="text-sm text-gray-400">{host.hostname}</div>
                                )}
                              </div>
                              {host.ports && (
                                <div className="text-sm text-gray-400">
                                  {host.ports.length} open ports
                                </div>
                              )}
                              <button
                                type="button"
                                onClick={() => importHostMutation.mutate({
                                  scanId: scan.id,
                                  host: {
                                    host: host.ip || host.hostname,
                                    name: host.hostname || host.ip,
                                    port: host.ports?.[0]?.port ?? host.ports?.[0],
                                    protocol: 'http',
                                    target_type: 'generic',
                                    environment: 'external',
                                  },
                                })}
                                disabled={importHostMutation.isPending}
                                className="btn-secondary text-xs py-1 px-3 disabled:opacity-50"
                              >
                                Add as Target
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-gray-500 text-sm">No hosts discovered</p>
                      )}
                    </div>
                  )}

                  {/* Timestamp */}
                  <div className="mt-2 ml-12 text-xs text-gray-500">
                    Created {format(new Date(scan.created_at), 'MMM d, yyyy HH:mm')}
                    {scan.completed_at && (
                      <span> • Completed {format(new Date(scan.completed_at), 'MMM d, yyyy HH:mm')}</span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
