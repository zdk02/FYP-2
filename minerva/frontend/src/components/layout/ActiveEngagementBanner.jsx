import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, ShieldAlert, ShieldX, AlertTriangle, Power } from 'lucide-react'
import { useEngagementStore } from '../../stores/engagementStore'

/**
 * The active-engagement banner. Visible on every page.
 *
 * Green (AUTHORIZED) — engagement is active, not killed, has scope and budget.
 * Yellow — degraded (paused / quota near-exhausted / safe-mode / dry-run / killed).
 * Red (NO ENGAGEMENT) — no active default engagement; every attack run will be rejected by the preflight gate.
 */
export default function ActiveEngagementBanner() {
  const { active, refreshActive } = useEngagementStore()
  const [tick, setTick] = useState(0)

  useEffect(() => {
    refreshActive()
    const t = setInterval(() => setTick((x) => x + 1), 15000)
    return () => clearInterval(t)
  }, [refreshActive, tick])

  if (active === undefined) return null

  if (!active) {
    return (
      <div className="px-4 py-2 bg-red-900/40 border-b border-red-700 text-red-100 text-sm flex items-center gap-3">
        <ShieldX className="w-4 h-4" />
        <span className="font-semibold">NO ACTIVE ENGAGEMENT</span>
        <span className="text-red-200/80">All attack runs will be rejected by the preflight gate.</span>
        <Link to="/engagements" className="ml-auto underline hover:text-white">
          Create or activate one →
        </Link>
      </div>
    )
  }

  const used = active.current_requests || 0
  const budget = active.max_requests || 0
  const usedPct = budget > 0 ? Math.round((used / budget) * 100) : 0
  const allowlist = (active.authorized_targets || []).slice(0, 3).join(', ')
    + (active.authorized_targets && active.authorized_targets.length > 3
       ? ` +${active.authorized_targets.length - 3}` : '')

  if (active.is_killed) {
    return (
      <div className="px-4 py-2 bg-red-900/40 border-b border-red-700 text-red-100 text-sm flex items-center gap-3">
        <Power className="w-4 h-4" />
        <span className="font-semibold">KILLED — {active.name}</span>
        <span className="text-red-200/80">Global kill switch engaged. No attacks will run.</span>
        <Link to="/engagements" className="ml-auto underline hover:text-white">
          Manage →
        </Link>
      </div>
    )
  }

  const degraded =
    active.safe_mode ||
    active.dry_run_default ||
    active.status !== 'active' ||
    usedPct >= 90

  const cls = degraded
    ? 'bg-amber-900/40 border-amber-700 text-amber-100'
    : 'bg-emerald-900/40 border-emerald-700 text-emerald-100'
  const Icon = degraded ? ShieldAlert : Shield

  return (
    <div className={`px-4 py-2 border-b text-sm flex items-center gap-3 ${cls}`}>
      <Icon className="w-4 h-4" />
      <span className="font-semibold">
        {degraded ? 'AUTHORIZED (degraded)' : 'AUTHORIZED'}
      </span>
      <span className="text-white/80">{active.name}</span>
      <span className="opacity-60">·</span>
      <span className="opacity-80 truncate max-w-[20rem]" title={(active.authorized_targets || []).join(', ')}>
        Scope: {allowlist || '(none)'}
      </span>
      <span className="opacity-60">·</span>
      <span className="opacity-80">
        Budget: {used.toLocaleString()}/{budget.toLocaleString()} ({usedPct}%)
      </span>
      {active.safe_mode && (
        <>
          <span className="opacity-60">·</span>
          <span className="px-1.5 py-0.5 rounded bg-amber-800/60 text-amber-100 text-xs">SAFE MODE</span>
        </>
      )}
      {active.dry_run_default && (
        <>
          <span className="opacity-60">·</span>
          <span className="px-1.5 py-0.5 rounded bg-blue-800/60 text-blue-100 text-xs">DRY-RUN</span>
        </>
      )}
      {active.signed_off_by && (
        <>
          <span className="opacity-60">·</span>
          <span className="opacity-80 truncate max-w-[14rem]" title={active.signed_off_by}>
            Signed: {active.signed_off_by}
          </span>
        </>
      )}
      <Link to="/engagements" className="ml-auto underline hover:text-white">
        Manage →
      </Link>
    </div>
  )
}
