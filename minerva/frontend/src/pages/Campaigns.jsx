import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Plus,
  Search,
  Rocket,
  Play,
  Pause,
  Square,
  MoreVertical,
  Edit,
  Trash2,
  Eye,
  Clock,
  Target,
  Crosshair,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react'
import { campaignsApi } from '../services/api'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

const statusColors = {
  draft: 'badge-info',
  ready: 'badge-info',
  running: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
  paused: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  completed: 'badge-success',
  failed: 'badge-critical',
  cancelled: 'bg-dark-500/20 text-dark-400 border border-dark-500/30',
}

const modeColors = {
  manual: 'badge-info',
  automated: 'badge-success',
  hybrid: 'bg-purple-500/20 text-purple-400 border border-purple-500/30',
}

function CampaignCard({ campaign, onStart, onPause, onStop, onDelete }) {
  const [showMenu, setShowMenu] = useState(false)
  
  const progress = campaign.total_attacks > 0 
    ? Math.round((campaign.completed_attacks / campaign.total_attacks) * 100)
    : 0

  return (
    <div className="card p-4 hover:border-dark-600 transition-all">
      <div className="flex items-start justify-between mb-3">
        <div>
          <Link 
            to={`/campaigns/${campaign.id}`}
            className="font-medium text-white hover:text-aegis-400 transition-colors"
          >
            {campaign.name}
          </Link>
          <p className="text-xs text-dark-500 mt-0.5">{campaign.pentest_type} test</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`badge ${statusColors[campaign.status]}`}>
            {campaign.status}
          </span>
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
                  <Link
                    to={`/campaigns/${campaign.id}`}
                    className="w-full px-3 py-2 text-left text-sm text-dark-300 hover:bg-dark-700 flex items-center gap-2"
                  >
                    <Eye className="w-4 h-4" />
                    View Details
                  </Link>
                  {campaign.status === 'draft' && (
                    <Link
                      to={`/campaigns/${campaign.id}/edit`}
                      className="w-full px-3 py-2 text-left text-sm text-dark-300 hover:bg-dark-700 flex items-center gap-2"
                    >
                      <Edit className="w-4 h-4" />
                      Edit
                    </Link>
                  )}
                  {['draft', 'ready'].includes(campaign.status) && (
                    <button
                      onClick={() => { onStart(campaign); setShowMenu(false) }}
                      className="w-full px-3 py-2 text-left text-sm text-emerald-400 hover:bg-dark-700 flex items-center gap-2"
                    >
                      <Play className="w-4 h-4" />
                      Start
                    </button>
                  )}
                  {campaign.status === 'running' && (
                    <button
                      onClick={() => { onPause(campaign); setShowMenu(false) }}
                      className="w-full px-3 py-2 text-left text-sm text-yellow-400 hover:bg-dark-700 flex items-center gap-2"
                    >
                      <Pause className="w-4 h-4" />
                      Pause
                    </button>
                  )}
                  {['running', 'paused'].includes(campaign.status) && (
                    <button
                      onClick={() => { onStop(campaign); setShowMenu(false) }}
                      className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-dark-700 flex items-center gap-2"
                    >
                      <Square className="w-4 h-4" />
                      Stop
                    </button>
                  )}
                  <button
                    onClick={() => { onDelete(campaign); setShowMenu(false) }}
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
      </div>

      <p className="text-sm text-dark-400 line-clamp-2 mb-4">
        {campaign.description || 'No description'}
      </p>

      {/* Progress Bar */}
      {campaign.status === 'running' && (
        <div className="mb-4">
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="text-dark-400">Progress</span>
            <span className="text-white">{progress}%</span>
          </div>
          <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-aegis-500 to-cyan-500 rounded-full transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="flex items-center gap-4 text-xs text-dark-500">
        <span className="flex items-center gap-1">
          <Target className="w-3 h-3" />
          {campaign.target_count || 0} targets
        </span>
        <span className="flex items-center gap-1">
          <Crosshair className="w-3 h-3" />
          {campaign.attack_count || 0} attacks
        </span>
        <span className={`badge text-[10px] ${modeColors[campaign.mode]}`}>
          {campaign.mode}
        </span>
      </div>

      {/* Dates */}
      <div className="flex items-center justify-between mt-4 pt-4 border-t border-dark-800 text-xs text-dark-500">
        <span className="flex items-center gap-1">
          <Clock className="w-3 h-3" />
          Created {format(new Date(campaign.created_at), 'MMM d, yyyy')}
        </span>
        {campaign.started_at && (
          <span>
            Started {format(new Date(campaign.started_at), 'MMM d, HH:mm')}
          </span>
        )}
      </div>
    </div>
  )
}

export default function Campaigns() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['campaigns', { search, status: statusFilter }],
    queryFn: () => campaignsApi.getAll({
      search: search || undefined,
      status: statusFilter || undefined,
    }),
  })

  const startMutation = useMutation({
    mutationFn: (id) => campaignsApi.start(id),
    onSuccess: () => {
      queryClient.invalidateQueries(['campaigns'])
      toast.success('Campaign started')
    },
    onError: (err) => toast.error(err.response?.data?.error || 'Failed to start campaign'),
  })

  const pauseMutation = useMutation({
    mutationFn: (id) => campaignsApi.pause(id),
    onSuccess: () => {
      queryClient.invalidateQueries(['campaigns'])
      toast.success('Campaign paused')
    },
    onError: (err) => toast.error(err.response?.data?.error || 'Failed to pause campaign'),
  })

  const stopMutation = useMutation({
    mutationFn: (id) => campaignsApi.stop(id),
    onSuccess: () => {
      queryClient.invalidateQueries(['campaigns'])
      toast.success('Campaign stopped')
    },
    onError: (err) => toast.error(err.response?.data?.error || 'Failed to stop campaign'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => campaignsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries(['campaigns'])
      toast.success('Campaign deleted')
    },
    onError: (err) => toast.error(err.response?.data?.error || 'Failed to delete campaign'),
  })

  const campaigns = data?.campaigns || []

  const handleDelete = (campaign) => {
    if (confirm(`Delete campaign "${campaign.name}"?`)) {
      deleteMutation.mutate(campaign.id)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Campaigns</h1>
          <p className="text-dark-400 mt-1">
            {campaigns.length} campaigns
          </p>
        </div>
        <Link to="/campaigns/new" className="btn-primary">
          <Plus className="w-4 h-4" />
          New Campaign
        </Link>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
          <input
            type="text"
            placeholder="Search campaigns..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input pl-10"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="select w-40"
        >
          <option value="">All Status</option>
          <option value="draft">Draft</option>
          <option value="ready">Ready</option>
          <option value="running">Running</option>
          <option value="paused">Paused</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
      </div>

      {/* Campaign Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="spinner w-8 h-8" />
        </div>
      ) : campaigns.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-dark-400">
          <Rocket className="w-12 h-12 mb-4" />
          <p>No campaigns found</p>
          <Link to="/campaigns/new" className="btn-primary mt-4">
            <Plus className="w-4 h-4" />
            Create Your First Campaign
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {campaigns.map((campaign) => (
            <CampaignCard
              key={campaign.id}
              campaign={campaign}
              onStart={(c) => startMutation.mutate(c.id)}
              onPause={(c) => pauseMutation.mutate(c.id)}
              onStop={(c) => stopMutation.mutate(c.id)}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}
    </div>
  )
}
