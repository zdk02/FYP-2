import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Crosshair,
  Target,
  Rocket,
  FileText,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  ArrowRight,
  Shield,
  Zap,
} from 'lucide-react'
import { dashboardApi } from '../services/api'

function StatCard({ title, value, icon: Icon, change, color = 'aegis' }) {
  const colorClasses = {
    aegis: 'from-aegis-500 to-cyan-500 shadow-aegis-500/25',
    red: 'from-red-500 to-orange-500 shadow-red-500/25',
    green: 'from-emerald-500 to-green-500 shadow-emerald-500/25',
    yellow: 'from-yellow-500 to-amber-500 shadow-yellow-500/25',
  }

  return (
    <div className="card p-6">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-dark-400 mb-1">{title}</p>
          <p className="text-3xl font-bold text-white">{value}</p>
          {change && (
            <p className={`text-sm mt-1 ${change >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
              <TrendingUp className="w-3 h-3 inline mr-1" />
              {change >= 0 ? '+' : ''}{change}% from last month
            </p>
          )}
        </div>
        <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${colorClasses[color]} 
                        flex items-center justify-center shadow-lg`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  )
}

function ActivityItem({ action, target, time, status }) {
  const statusIcons = {
    success: <CheckCircle className="w-4 h-4 text-emerald-400" />,
    warning: <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    error: <AlertTriangle className="w-4 h-4 text-red-400" />,
    pending: <Clock className="w-4 h-4 text-dark-400 animate-pulse" />,
  }

  return (
    <div className="flex items-center gap-3 py-3 border-b border-dark-800 last:border-0">
      {statusIcons[status] || <Activity className="w-4 h-4 text-dark-400" />}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white truncate">{action}</p>
        <p className="text-xs text-dark-500">{target}</p>
      </div>
      <span className="text-xs text-dark-500">{time}</span>
    </div>
  )
}

function QuickAction({ title, description, icon: Icon, to, color }) {
  return (
    <Link
      to={to}
      className="card p-4 hover:border-dark-600 transition-colors group"
    >
      <div className="flex items-start gap-3">
        <div className={`w-10 h-10 rounded-lg bg-${color}-500/20 flex items-center justify-center`}>
          <Icon className={`w-5 h-5 text-${color}-400`} />
        </div>
        <div className="flex-1">
          <h3 className="font-medium text-white group-hover:text-aegis-400 transition-colors">
            {title}
          </h3>
          <p className="text-sm text-dark-400 mt-0.5">{description}</p>
        </div>
        <ArrowRight className="w-4 h-4 text-dark-600 group-hover:text-aegis-400 transition-colors" />
      </div>
    </Link>
  )
}

export default function Dashboard() {
  const { data: statsData } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: dashboardApi.getStats,
    refetchInterval: 30000,
  })

  const { data: activityData } = useQuery({
    queryKey: ['dashboard-activity'],
    queryFn: dashboardApi.getRecentActivity,
    refetchInterval: 30000,
  })

  const stats = {
    totalAttacks: statsData?.total_attacks ?? 0,
    activeTargets: statsData?.active_targets ?? 0,
    runningCampaigns: statsData?.running_campaigns ?? 0,
    reportsGenerated: statsData?.reports_generated ?? 0,
  }

  const recentActivity = activityData?.activity ?? []

  const sev = statsData?.severity_breakdown ?? {}
  const severityBreakdown = [
    { label: 'Critical', count: sev.critical ?? 0, color: 'red' },
    { label: 'High', count: sev.high ?? 0, color: 'orange' },
    { label: 'Medium', count: sev.medium ?? 0, color: 'yellow' },
    { label: 'Low', count: sev.low ?? 0, color: 'blue' },
  ]
  const severityMax = Math.max(1, ...severityBreakdown.map((s) => s.count))

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-dark-400 mt-1">Welcome back! Here's your security testing overview.</p>
        </div>
        <Link to="/campaigns/new" className="btn-primary">
          <Rocket className="w-4 h-4" />
          New Campaign
        </Link>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Attacks"
          value={stats.totalAttacks}
          icon={Crosshair}
          color="aegis"
        />
        <StatCard
          title="Active Targets"
          value={stats.activeTargets}
          icon={Target}
          color="green"
        />
        <StatCard
          title="Running Campaigns"
          value={stats.runningCampaigns}
          icon={Rocket}
          color="yellow"
        />
        <StatCard
          title="Reports Generated"
          value={stats.reportsGenerated}
          icon={FileText}
          color="red"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity */}
        <div className="lg:col-span-2 card">
          <div className="card-header flex items-center justify-between">
            <h2 className="font-semibold text-white">Recent Activity</h2>
            <Link to="/campaigns" className="text-sm text-aegis-400 hover:text-aegis-300">
              View all
            </Link>
          </div>
          <div className="card-body">
            {recentActivity.length === 0 ? (
              <p className="text-sm text-dark-500 py-6 text-center">No activity yet</p>
            ) : (
              recentActivity.map((item, index) => (
                <ActivityItem key={index} {...item} />
              ))
            )}
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="card">
          <div className="card-header">
            <h2 className="font-semibold text-white">Findings by Severity</h2>
          </div>
          <div className="card-body space-y-4">
            {severityBreakdown.map((item) => (
              <div key={item.label} className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full bg-${item.color}-500`} />
                <span className="text-sm text-dark-300 flex-1">{item.label}</span>
                <span className="text-sm font-medium text-white">{item.count}</span>
                <div className="w-24 h-2 bg-dark-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full bg-${item.color}-500 rounded-full`}
                    style={{ width: `${(item.count / severityMax) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <QuickAction
            title="New Campaign"
            description="Start a penetration test"
            icon={Rocket}
            to="/campaigns/new"
            color="aegis"
          />
          <QuickAction
            title="Add Target"
            description="Register a new target system"
            icon={Target}
            to="/targets"
            color="emerald"
          />
          <QuickAction
            title="Run Scan"
            description="Discover network assets"
            icon={Zap}
            to="/scans"
            color="yellow"
          />
          <QuickAction
            title="Browse Attacks"
            description="Explore attack library"
            icon={Shield}
            to="/attacks"
            color="purple"
          />
        </div>
      </div>
    </div>
  )
}
