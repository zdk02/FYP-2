import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'

const severityBadge = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

const confidenceBadge = {
  confirmed: 'bg-emerald-500/20 text-emerald-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
}

export default function FindingsTable({ findings = [] }) {
  const [expanded, setExpanded] = useState({})

  if (!findings.length) {
    return (
      <div className="text-sm text-dark-400 text-center py-6 border border-dashed border-dark-700 rounded-lg">
        No findings.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase tracking-wide text-dark-500 border-b border-dark-800">
          <tr>
            <th className="py-2 pr-2 w-6"></th>
            <th className="py-2 pr-2">Severity</th>
            <th className="py-2 pr-2">Confidence</th>
            <th className="py-2 pr-2">CVE</th>
            <th className="py-2 pr-2">Client</th>
            <th className="py-2 pr-2">Title</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, idx) => {
            const sev = String(f.severity || 'info').toLowerCase()
            const conf = String(f.confidence || 'low').toLowerCase()
            const isOpen = !!expanded[idx]
            const cve = f.cve || f.cve_id
            const cveLink = cve && cve.startsWith('CVE-')
              ? `https://nvd.nist.gov/vuln/detail/${cve}`
              : null
            return (
              <Fragment key={idx}>
                <tr
                  className="border-b border-dark-800/60 hover:bg-dark-800/30"
                >
                  <td className="py-2 pr-2">
                    <button
                      onClick={() => setExpanded((p) => ({ ...p, [idx]: !p[idx] }))}
                      className="text-dark-400 hover:text-white"
                    >
                      {isOpen ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </button>
                  </td>
                  <td className="py-2 pr-2">
                    <span className={`badge ${severityBadge[sev] || 'badge-info'}`}>
                      {sev}
                    </span>
                  </td>
                  <td className="py-2 pr-2">
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                        confidenceBadge[conf] || 'bg-dark-700 text-dark-300'
                      }`}
                    >
                      {conf}
                    </span>
                  </td>
                  <td className="py-2 pr-2 font-mono text-xs">
                    {cveLink ? (
                      <a
                        href={cveLink}
                        target="_blank"
                        rel="noreferrer"
                        className="text-aegis-400 hover:underline inline-flex items-center gap-1"
                      >
                        {cve}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span>{cve || '—'}</span>
                    )}
                  </td>
                  <td className="py-2 pr-2 text-dark-300">{f.client || '—'}</td>
                  <td className="py-2 pr-2 text-white">{f.title}</td>
                </tr>
                {isOpen && (
                  <tr className="border-b border-dark-800">
                    <td></td>
                    <td colSpan={5} className="py-2 pr-2 text-xs text-dark-300">
                      <div className="space-y-2">
                        {f.description && (
                          <div>
                            <div className="text-dark-500 uppercase text-[10px]">Description</div>
                            <div>{f.description}</div>
                          </div>
                        )}
                        {f.remediation && (
                          <div>
                            <div className="text-dark-500 uppercase text-[10px]">Remediation</div>
                            <div>{f.remediation}</div>
                          </div>
                        )}
                        {f.verification && (
                          <div>
                            <div className="text-dark-500 uppercase text-[10px]">Verification</div>
                            <pre className="text-[11px] bg-dark-900 p-2 rounded whitespace-pre-wrap break-all">
                              {JSON.stringify(f.verification, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
