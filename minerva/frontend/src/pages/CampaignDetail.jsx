import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  Play,
  Pause,
  Square,
  FileText,
  Target,
  Crosshair,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Activity,
  Loader2,
} from 'lucide-react'
import { campaignsApi, executionsApi } from '../services/api'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

const statusColors = {
  pending: 'text-dark-400',
  running: 'text-yellow-400',
  completed: 'text-emerald-400',
  success: 'text-emerald-400',
  failed: 'text-red-400',
  error: 'text-red-400',
  cancelled: 'text-dark-500',
  skipped: 'text-dark-500',
}

const resultColors = {
  vulnerable: 'badge-critical',
  not_vulnerable: 'badge-success',
  inconclusive: 'badge-medium',
  error: 'badge-critical',
}

export default function CampaignDetail() {
  const { id } = useParams()
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['campaign', id],
    queryFn: () => campaignsApi.get(id),
    refetchInterval: (q) =>
      ['active', 'running'].includes(q.state.data?.status) ? 5000 : false,
  })

  const { data: execData } = useQuery({
    queryKey: ['campaign-executions', id],
    queryFn: () => campaignsApi.getExecutions(id, { limit: 50 }),
    refetchInterval: (q) =>
      ['active', 'running'].includes(data?.status) ? 5000 : false,
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['campaign', id] })
    queryClient.invalidateQueries({ queryKey: ['campaign-executions', id] })
    queryClient.invalidateQueries({ queryKey: ['campaigns'] })
  }

  const startMutation = useMutation({
    mutationFn: () => campaignsApi.start(id),
    onSuccess: () => { toast.success('Campaign started'); invalidate() },
    onError: (e) => toast.error(e.response?.data?.error || 'Failed to start campaign'),
  })

  const pauseMutation = useMutation({
    mutationFn: () => campaignsApi.pause(id),
    onSuccess: () => { toast.success('Campaign paused'); invalidate() },
    onError: (e) => toast.error(e.response?.data?.error || 'Failed to pause campaign'),
  })

  const resumeMutation = useMutation({
    mutationFn: () => campaignsApi.resume(id),
    onSuccess: () => { toast.success('Campaign resumed'); invalidate() },
    onError: (e) => toast.error(e.response?.data?.error || 'Failed to resume campaign'),
  })

  const stopMutation = useMutation({
    mutationFn: () => campaignsApi.stop(id),
    onSuccess: () => { toast.success('Campaign stopped'); invalidate() },
    onError: (e) => toast.error(e.response?.data?.error || 'Failed to stop campaign'),
  })

  const campaign = data
  const executions = execData?.executions || []

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner w-8 h-8" />
      </div>
    )
  }

  if (!campaign) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-dark-400">
        <AlertTriangle className="w-12 h-12 mb-4" />
        <p>Campaign not found</p>
        <Link to="/campaigns" className="btn-secondary mt-4">
          Back to Campaigns
        </Link>
      </div>
    )
  }

  const progress = campaign.total_attacks > 0
    ? Math.round((campaign.completed_attacks / campaign.total_attacks) * 100)
    : 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <Link to="/campaigns" className="btn-ghost p-2 mt-1">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">{campaign.name}</h1>
            <p className="text-dark-400 mt-1">{campaign.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {campaign.status === 'completed' && (
            <Link to={`/reports?campaign=${campaign.id}`} className="btn-secondary">
              <FileText className="w-4 h-4" />
              View Report
            </Link>
          )}
          {['draft', 'ready'].includes(campaign.status) && (
            <button
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending}
              className="btn-primary"
            >
              {startMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Start Campaign
            </button>
          )}
          {campaign.status === 'paused' && (
            <button
              onClick={() => resumeMutation.mutate()}
              disabled={resumeMutation.isPending}
              className="btn-primary"
            >
              {resumeMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Resume
            </button>
          )}
          {['running', 'active'].includes(campaign.status) && (
            <>
              <button
                onClick={() => pauseMutation.mutate()}
                disabled={pauseMutation.isPending}
                className="btn-secondary"
              >
                {pauseMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Pause className="w-4 h-4" />}
                Pause
              </button>
              <button
                onClick={() => {
                  if (window.confirm('Stop this campaign? Running attacks will be aborted.')) {
                    stopMutation.mutate()
                  }
                }}
                disabled={stopMutation.isPending}
                className="btn-danger"
              >
                {stopMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4" />}
                Stop
              </button>
            </>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-aegis-500/20 flex items-center justify-center">
              <Target className="w-5 h-5 text-aegis-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{campaign.target_count || 0}</p>
              <p className="text-xs text-dark-400">Targets</p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
              <Crosshair className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{campaign.attack_count || 0}</p>
              <p className="text-xs text-dark-400">Attacks</p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{campaign.findings_count || 0}</p>
              <p className="text-xs text-dark-400">Findings</p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center">
              <Activity className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{progress}%</p>
              <p className="text-xs text-dark-400">Complete</p>
            </div>
          </div>
        </div>
      </div>

      {/* Progress */}
      {['running', 'active'].includes(campaign.status) && (
        <div className="card p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-dark-400">Campaign Progress</span>
            <span className="text-sm text-white">
              {campaign.completed_attacks} / {campaign.total_attacks} attacks
            </span>
          </div>
          <div className="h-3 bg-dark-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-aegis-500 to-cyan-500 rounded-full transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Executions */}
      <div className="card">
        <div className="card-header">
          <h2 className="font-semibold text-white">Attack Executions</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Attack</th>
                <th>Target</th>
                <th>Status</th>
                <th>Result</th>
                <th>Duration</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {executions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center text-dark-500 py-8">
                    No executions yet
                  </td>
                </tr>
              ) : (
                executions.map((exec) => (
                  <tr key={exec.id}>
                    <td className="font-medium text-white">{exec.attack?.name}</td>
                    <td className="text-dark-300">{exec.target?.name}</td>
                    <td>
                      <span className={`flex items-center gap-1 ${statusColors[exec.status] || ''}`}>
                        {['completed', 'success'].includes(exec.status) ? (
                          <CheckCircle className="w-3 h-3" />
                        ) : ['failed', 'error', 'cancelled'].includes(exec.status) ? (
                          <XCircle className="w-3 h-3" />
                        ) : exec.status === 'running' ? (
                          <Activity className="w-3 h-3 animate-pulse" />
                        ) : (
                          <Clock className="w-3 h-3" />
                        )}
                        {exec.status}
                      </span>
                    </td>
                    <td>
                      {exec.result && (
                        <span className={`badge ${resultColors[exec.result]}`}>
                          {exec.result}
                        </span>
                      )}
                    </td>
                    <td className="text-dark-400">
                      {exec.duration ? `${exec.duration}s` : '-'}
                    </td>
                    <td className="text-dark-500">
                      {exec.started_at && format(new Date(exec.started_at), 'HH:mm:ss')}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
