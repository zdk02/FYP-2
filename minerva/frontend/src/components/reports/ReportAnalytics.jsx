import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, RadialBarChart, RadialBar,
  Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  LineChart, Line,
} from 'recharts'

const SEV_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  info:     '#6b7280',
}

const CONF_COLORS = {
  confirmed: '#10b981',
  high:      '#3b82f6',
  medium:    '#a855f7',
  low:       '#6b7280',
}

const RISK_GRADE_COLORS = {
  A: '#10b981',
  B: '#22c55e',
  C: '#eab308',
  D: '#f97316',
  E: '#ef4444',
  F: '#dc2626',
}

const tipStyle = {
  contentStyle: {
    background: '#0f172a',
    border: '1px solid #334155',
    borderRadius: 8,
    fontSize: 12,
  },
  labelStyle: { color: '#cbd5e1' },
  itemStyle: { color: '#e2e8f0' },
}

function Card({ title, subtitle, children, className = '' }) {
  return (
    <div className={`card p-4 ${className}`}>
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        {subtitle && <p className="text-xs text-dark-500 mt-0.5">{subtitle}</p>}
      </div>
      {children}
    </div>
  )
}

function Kpi({ label, value, suffix, accent = 'aegis' }) {
  const accentClass = {
    aegis: 'text-aegis-400',
    red: 'text-red-400',
    orange: 'text-orange-400',
    yellow: 'text-yellow-400',
    emerald: 'text-emerald-400',
    blue: 'text-blue-400',
    purple: 'text-purple-400',
  }[accent] || 'text-aegis-400'
  return (
    <div className="card p-4 flex flex-col">
      <span className="text-xs text-dark-500 mb-1">{label}</span>
      <span className="text-2xl font-bold text-white">
        {value}
        {suffix && <span className="text-sm text-dark-400 ml-1">{suffix}</span>}
      </span>
    </div>
  )
}

function RiskGauge({ grade, score }) {
  const color = RISK_GRADE_COLORS[grade] || '#9ca3af'
  const data = [{ name: 'risk', value: score, fill: color }]
  return (
    <Card title="Risk grade" subtitle="CVSS-weighted, severity × confidence aggregated">
      <div className="relative" style={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            innerRadius="65%" outerRadius="100%"
            data={data} startAngle={90} endAngle={-270}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
            <RadialBar background={{ fill: '#1e293b' }} dataKey="value" cornerRadius={6} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-5xl font-bold" style={{ color }}>{grade}</span>
          <span className="text-sm text-dark-400 mt-1">risk score {score}/100</span>
        </div>
      </div>
    </Card>
  )
}

function SeverityDonut({ data }) {
  const filtered = (data || []).filter(d => d.count > 0)
  if (!filtered.length) return null
  return (
    <Card title="Severity distribution" subtitle="Findings broken out by impact">
      <div style={{ height: 220 }}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={filtered} dataKey="count" nameKey="key"
                 cx="50%" cy="50%" innerRadius={50} outerRadius={85}
                 paddingAngle={2}>
              {filtered.map((d) => (
                <Cell key={d.key} fill={SEV_COLORS[d.key] || '#6b7280'} />
              ))}
            </Pie>
            <Tooltip {...tipStyle} formatter={(v, n) => [`${v}`, n]} />
            <Legend wrapperStyle={{ fontSize: 11, color: '#cbd5e1' }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function ConfidenceDonut({ data }) {
  const filtered = (data || []).filter(d => d.count > 0)
  if (!filtered.length) return null
  return (
    <Card title="Confidence distribution" subtitle="confirmed = OOB / canary-proof; lower = heuristic">
      <div style={{ height: 220 }}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={filtered} dataKey="count" nameKey="key"
                 cx="50%" cy="50%" innerRadius={50} outerRadius={85}
                 paddingAngle={2}>
              {filtered.map((d) => (
                <Cell key={d.key} fill={CONF_COLORS[d.key] || '#6b7280'} />
              ))}
            </Pie>
            <Tooltip {...tipStyle} />
            <Legend wrapperStyle={{ fontSize: 11, color: '#cbd5e1' }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function SeverityConfidenceMatrix({ data }) {
  if (!data?.length) return null
  return (
    <Card title="Severity × confidence" subtitle="High count + confirmed = the issues to fix today">
      <div className="overflow-x-auto -mx-2">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-dark-500">
              <th className="text-left p-2">severity ↓ / confidence →</th>
              <th className="text-right p-2">confirmed</th>
              <th className="text-right p-2">high</th>
              <th className="text-right p-2">medium</th>
              <th className="text-right p-2">low</th>
              <th className="text-right p-2 text-dark-300">total</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.severity} className="border-t border-dark-800">
                <td className="p-2">
                  <span className="inline-flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full"
                          style={{ background: SEV_COLORS[row.severity] }} />
                    <span className="capitalize text-dark-200">{row.severity}</span>
                  </span>
                </td>
                {['confirmed', 'high', 'medium', 'low'].map((c) => (
                  <td key={c} className={`text-right p-2 ${heatClass(row[c], data)}`}>
                    {row[c] || 0}
                  </td>
                ))}
                <td className="text-right p-2 font-medium text-white">{row.total}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function heatClass(v, allRows) {
  if (!v) return 'text-dark-600'
  const max = Math.max(...allRows.flatMap(r =>
    ['confirmed','high','medium','low'].map(c => r[c] || 0)))
  if (!max) return 'text-dark-600'
  const ratio = v / max
  if (ratio >= 0.66) return 'text-red-400 font-semibold'
  if (ratio >= 0.33) return 'text-orange-400 font-medium'
  return 'text-dark-300'
}

function HorizontalBarChart({ title, subtitle, data, dataKey, nameKey, color = '#3b82f6' }) {
  if (!data?.length) return null
  // Recharts horizontal bar chart needs vertical layout
  return (
    <Card title={title} subtitle={subtitle}>
      <div style={{ height: Math.max(140, data.length * 26 + 40) }}>
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical"
                    margin={{ left: 8, right: 24, top: 8, bottom: 8 }}>
            <CartesianGrid stroke="#1e293b" horizontal={false} />
            <XAxis type="number" stroke="#64748b" fontSize={11} />
            <YAxis type="category" dataKey={nameKey} stroke="#94a3b8"
                   fontSize={11} width={150} interval={0} />
            <Tooltip {...tipStyle} />
            <Bar dataKey={dataKey} fill={color} radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function StackedSeverityBars({ title, subtitle, data, nameKey }) {
  if (!data?.length) return null
  return (
    <Card title={title} subtitle={subtitle}>
      <div style={{ height: Math.max(160, data.length * 28 + 40) }}>
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical"
                    margin={{ left: 8, right: 24, top: 8, bottom: 8 }}>
            <CartesianGrid stroke="#1e293b" horizontal={false} />
            <XAxis type="number" stroke="#64748b" fontSize={11} />
            <YAxis type="category" dataKey={nameKey} stroke="#94a3b8"
                   fontSize={11} width={150} interval={0} />
            <Tooltip {...tipStyle} />
            <Legend wrapperStyle={{ fontSize: 11, color: '#cbd5e1' }} />
            {['critical','high','medium','low'].map(sev => (
              <Bar key={sev} dataKey={sev} stackId="sev"
                   fill={SEV_COLORS[sev]} radius={[0, 0, 0, 0]} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function CvssHistogram({ data }) {
  if (!data?.length || data.every(d => !d.count)) return null
  return (
    <Card title="CVSS score distribution" subtitle="Where vulns sit on the 0–10 scale">
      <div style={{ height: 180 }}>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ left: -8, right: 8, top: 8, bottom: 8 }}>
            <CartesianGrid stroke="#1e293b" vertical={false} />
            <XAxis dataKey="bucket" stroke="#64748b" fontSize={11} />
            <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
            <Tooltip {...tipStyle} />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((d, i) => {
                const bucket = d.bucket
                const color =
                  bucket === '9-10' ? '#dc2626' :
                  bucket === '7-8.9' ? '#f97316' :
                  bucket === '5-6.9' ? '#eab308' :
                  bucket === '3-4.9' ? '#3b82f6' : '#6b7280'
                return <Cell key={i} fill={color} />
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function ConfirmationSplit({ data }) {
  if (!data) return null
  const items = [
    { name: 'Confirmed (OOB / canary)', value: data.confirmed, fill: '#10b981' },
    { name: 'Heuristic',                 value: data.heuristic, fill: '#64748b' },
  ].filter(x => x.value > 0)
  if (!items.length) return null
  return (
    <Card title="Evidence quality"
          subtitle={`${data.confirmed_pct}% of findings carry direct proof of impact`}>
      <div style={{ height: 200 }}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={items} dataKey="value" nameKey="name"
                 cx="50%" cy="50%" innerRadius={45} outerRadius={80}
                 paddingAngle={2}>
              {items.map((d, i) => <Cell key={i} fill={d.fill} />)}
            </Pie>
            <Tooltip {...tipStyle} />
            <Legend wrapperStyle={{ fontSize: 11, color: '#cbd5e1' }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function FindingsTimeline({ data }) {
  if (!data?.length) return null
  // Pivot: ts -> { critical, high, medium, low }
  const buckets = {}
  for (const e of data) {
    const slot = (buckets[e.ts] = buckets[e.ts] || { ts: e.ts })
    slot[e.severity] = (slot[e.severity] || 0) + e.count
  }
  const series = Object.values(buckets).sort((a, b) => a.ts.localeCompare(b.ts))
  return (
    <Card title="Findings over time" subtitle="When each finding fired during the campaign">
      <div style={{ height: 220 }}>
        <ResponsiveContainer>
          <LineChart data={series} margin={{ left: -8, right: 8, top: 8, bottom: 8 }}>
            <CartesianGrid stroke="#1e293b" />
            <XAxis dataKey="ts" stroke="#64748b" fontSize={10}
                   tickFormatter={(v) => v?.slice(11) || v} />
            <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
            <Tooltip {...tipStyle} />
            <Legend wrapperStyle={{ fontSize: 11, color: '#cbd5e1' }} />
            {['critical','high','medium','low'].map(sev => (
              <Line key={sev} type="monotone" dataKey={sev}
                    stroke={SEV_COLORS[sev]} strokeWidth={2} dot={false} />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function MitreRadar({ data }) {
  if (!data?.length || data.length < 3) return null
  return (
    <Card title="MITRE ATT&CK coverage" subtitle="Techniques exercised by this campaign">
      <div style={{ height: 240 }}>
        <ResponsiveContainer>
          <RadarChart data={data}>
            <PolarGrid stroke="#1e293b" />
            <PolarAngleAxis dataKey="mitre_id" stroke="#94a3b8" fontSize={10} />
            <PolarRadiusAxis stroke="#475569" fontSize={9} />
            <Radar name="Findings" dataKey="count"
                   stroke="#0ea5e9" fill="#0ea5e9" fillOpacity={0.4} />
            <Tooltip {...tipStyle} />
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

export default function ReportAnalytics({ analytics, risk }) {
  if (!analytics) return null
  const k = analytics.kpis || {}
  return (
    <div className="space-y-6">
      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <Kpi label="Findings" value={k.total_findings ?? 0} accent="aegis" />
        <Kpi label="Critical" value={k.critical ?? 0} accent="red" />
        <Kpi label="High" value={k.high ?? 0} accent="orange" />
        <Kpi label="Confirmed" value={`${k.confirmed_pct ?? 0}`} suffix="%" accent="emerald" />
        <Kpi label="Max CVSS" value={k.max_cvss ?? 0} accent="purple" />
        <Kpi label="Tools hit" value={k.unique_tools_affected ?? 0} accent="blue" />
      </div>

      {/* Risk + distributions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {risk && <RiskGauge grade={risk.grade} score={risk.score ?? 0} />}
        <SeverityDonut data={analytics.severity_distribution} />
        <ConfidenceDonut data={analytics.confidence_distribution} />
      </div>

      {/* Matrix + CVSS histogram + confirmation */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <SeverityConfidenceMatrix data={analytics.severity_confidence_matrix} />
        <CvssHistogram data={analytics.cvss_histogram} />
        <ConfirmationSplit data={analytics.confirmation_split} />
      </div>

      {/* Attack effectiveness + top tools */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <StackedSeverityBars
          title="Attack effectiveness"
          subtitle="Findings each attack produced, stacked by severity"
          data={(analytics.attack_effectiveness || []).slice(0, 12).map(a => ({
            name: (a.attack_name || a.attack_id || '').slice(0, 38), ...a,
          }))}
          nameKey="name"
        />
        <StackedSeverityBars
          title="Top vulnerable tools"
          subtitle="Which MCP tools surfaced the most findings"
          data={(analytics.top_vulnerable_tools || []).map(t => ({
            name: t.tool, ...t,
          }))}
          nameKey="name"
        />
      </div>

      {/* Categories + CWE + targets */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <HorizontalBarChart
          title="Findings by category" subtitle="Vulnerability classes encountered"
          data={analytics.category_distribution || []}
          dataKey="count" nameKey="category" color="#3b82f6"
        />
        <HorizontalBarChart
          title="CWE distribution" subtitle="MITRE CWE identifiers"
          data={analytics.cwe_distribution || []}
          dataKey="count" nameKey="cwe" color="#a855f7"
        />
        <HorizontalBarChart
          title="Most-impacted targets" subtitle="Targets with the most findings"
          data={(analytics.target_ranking || []).slice(0, 10).map(t => ({
            target: t.target.length > 28 ? t.target.slice(0, 25) + '…' : t.target,
            count: t.findings,
          }))}
          dataKey="count" nameKey="target" color="#ef4444"
        />
      </div>

      {/* Timeline + MITRE radar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <FindingsTimeline data={analytics.findings_timeline} />
        <MitreRadar data={analytics.mitre_coverage} />
      </div>
    </div>
  )
}
