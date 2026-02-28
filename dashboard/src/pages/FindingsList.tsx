import { useEffect, useState } from 'react'
import { BarChart, Bar, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { api } from '../api/client'
import { severityColor, severityLabel, severityFill, statusColor } from '../utils/severity'

interface FindingProps {
  severity_id?: number
  title?: string
  provider?: string
  status?: string
  message?: string
  remediation?: { description?: string }
  cloud?: { provider?: string; account_uid?: string; region?: string }
  vulnerabilities?: Array<{ cve?: { uid?: string }; cvss?: Array<{ base_score?: number }> }>
  resources?: Array<{ name?: string; type?: string; region?: string }>
}

function getProps(f: Record<string, unknown>): FindingProps {
  return (f.properties as FindingProps) || {}
}

const SEVERITY_IDS = [1, 2, 3, 4, 5] as const

export default function FindingsList() {
  const [findings, setFindings] = useState<Record<string, unknown>[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<number | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)

  useEffect(() => {
    api.getFindings(500)
      .then((data) => setFindings(data.findings as Record<string, unknown>[]))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-8 text-gray-500 dark:text-gray-400">Loading...</div>

  // Severity counts for mini bar
  const sevCounts: Record<number, number> = {}
  for (const f of findings) {
    const sev = getProps(f).severity_id ?? 0
    sevCounts[sev] = (sevCounts[sev] || 0) + 1
  }
  const barData = SEVERITY_IDS.map((id) => ({
    name: severityLabel(id),
    value: sevCounts[id] || 0,
    id,
  }))

  const filtered = filter !== null
    ? findings.filter((f) => getProps(f).severity_id === filter)
    : findings

  return (
    <div>
      <h2 className="text-2xl font-bold mb-4">Findings</h2>

      {/* Severity distribution mini bar */}
      {findings.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4 mb-4">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Severity Distribution</p>
          <ResponsiveContainer width="100%" height={40}>
            <BarChart data={barData} layout="horizontal" margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
              <Tooltip formatter={(v: number, name: string) => [v, name]} />
              <Bar dataKey="value" radius={[4, 4, 4, 4]}>
                {barData.map((d) => (
                  <Cell key={d.id} fill={severityFill(d.id)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Filter buttons */}
      <div className="flex gap-2 mb-4 flex-wrap">
        <button
          onClick={() => { setFilter(null); setExpanded(null) }}
          className={`px-3 py-1 rounded text-sm font-medium ${filter === null ? 'bg-gray-800 text-white' : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
        >
          All ({findings.length})
        </button>
        {[5, 4, 3, 2, 1].map((id) => (
          <button
            key={id}
            onClick={() => { setFilter(id); setExpanded(null) }}
            className={`px-3 py-1 rounded text-sm font-medium ${filter === id ? severityColor(id) + ' ring-2 ring-offset-1 ring-gray-400' : severityColor(id) + ' opacity-70 hover:opacity-100'}`}
          >
            {severityLabel(id)} ({sevCounts[id] || 0})
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Severity</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Title</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Provider</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {filtered.map((f, i) => {
              const props = getProps(f)
              const isExpanded = expanded === i
              return (
                <tr key={i} className="cursor-pointer" onClick={() => setExpanded(isExpanded ? null : i)}>
                  <td className="px-4 py-3" colSpan={isExpanded ? undefined : undefined}>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${severityColor(props.severity_id ?? 0)}`}>
                      {severityLabel(props.severity_id ?? 0)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{props.title || 'Untitled'}</td>
                  <td className="px-4 py-3 text-sm">{props.provider || '-'}</td>
                  <td className="px-4 py-3 text-sm">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${statusColor(props.status || '')}`}>
                      {props.status || '-'}
                    </span>
                  </td>
                </tr>
              )
            })}
            {/* Expanded detail row */}
            {expanded !== null && filtered[expanded] && (() => {
              const props = getProps(filtered[expanded])
              return (
                <tr className="bg-gray-50 dark:bg-gray-900">
                  <td colSpan={4} className="px-4 py-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      {/* Message */}
                      {props.message && (
                        <div className="md:col-span-2">
                          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">Message</p>
                          <p className="text-gray-700 dark:text-gray-300">{props.message}</p>
                        </div>
                      )}

                      {/* Resources */}
                      {props.resources && props.resources.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">Resources</p>
                          <ul className="space-y-1">
                            {props.resources.map((r, ri) => (
                              <li key={ri} className="text-gray-700 dark:text-gray-300">
                                <span className="font-medium">{r.name || 'unnamed'}</span>
                                {r.type && <span className="text-gray-400 dark:text-gray-500 ml-1">({r.type})</span>}
                                {r.region && <span className="text-gray-400 dark:text-gray-500 ml-1">— {r.region}</span>}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Vulnerabilities */}
                      {props.vulnerabilities && props.vulnerabilities.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">Vulnerabilities</p>
                          <ul className="space-y-1">
                            {props.vulnerabilities.map((v, vi) => (
                              <li key={vi} className="text-gray-700 dark:text-gray-300">
                                {v.cve?.uid && <span className="font-mono font-medium">{v.cve.uid}</span>}
                                {v.cvss?.[0]?.base_score != null && (
                                  <span className="ml-2 text-gray-500 dark:text-gray-400">CVSS: {v.cvss[0].base_score}</span>
                                )}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Remediation */}
                      {props.remediation?.description && (
                        <div>
                          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">Remediation</p>
                          <p className="text-gray-700 dark:text-gray-300">{props.remediation.description}</p>
                        </div>
                      )}

                      {/* Cloud context */}
                      {props.cloud && (
                        <div>
                          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">Cloud Context</p>
                          <p className="text-gray-700 dark:text-gray-300">
                            {props.cloud.provider && <span>Provider: {props.cloud.provider}</span>}
                            {props.cloud.account_uid && <span className="ml-3">Account: {props.cloud.account_uid}</span>}
                            {props.cloud.region && <span className="ml-3">Region: {props.cloud.region}</span>}
                          </p>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })()}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <p className="text-center text-gray-400 dark:text-gray-500 py-8">No findings found</p>
        )}
      </div>
      <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">
        Showing {filtered.length} of {findings.length} findings
        {filter !== null && ` (filtered: ${severityLabel(filter)})`}
      </p>
    </div>
  )
}
