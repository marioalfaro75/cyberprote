import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { api } from '../api/client'
import type { ThreatIntelOverview, VulnFinding, TacticCoverage, CVEEntry, ExposedResource } from '../api/threatintel-types'

export default function ThreatIntelligence() {
  const [overview, setOverview] = useState<ThreatIntelOverview | null>(null)
  const [kevFindings, setKevFindings] = useState<VulnFinding[]>([])
  const [tactics, setTactics] = useState<TacticCoverage[]>([])
  const [cves, setCves] = useState<CVEEntry[]>([])
  const [exposed, setExposed] = useState<ExposedResource[]>([])
  const [loading, setLoading] = useState(true)
  const [sortField, setSortField] = useState<'cvss_score' | 'epss_score' | 'cve_id'>('cvss_score')
  const [sortAsc, setSortAsc] = useState(false)

  useEffect(() => {
    Promise.all([
      api.getThreatIntelOverview(),
      api.getKEVFindings(),
      api.getAttackMatrix(),
      api.getCVEInventory(),
      api.getExposure(),
    ])
      .then(([ov, kev, atk, cveInv, exp]) => {
        setOverview(ov)
        setKevFindings(kev.findings || [])
        setTactics(atk.tactics || [])
        setCves(cveInv.cves || [])
        setExposed(exp.resources || [])
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-8 text-gray-500 dark:text-gray-400">Loading...</div>

  // EPSS distribution histogram buckets
  const epssBuckets = [
    { range: '0-10%', min: 0, max: 0.1, count: 0, color: '#22c55e' },
    { range: '10-30%', min: 0.1, max: 0.3, count: 0, color: '#84cc16' },
    { range: '30-50%', min: 0.3, max: 0.5, count: 0, color: '#eab308' },
    { range: '50-70%', min: 0.5, max: 0.7, count: 0, color: '#f97316' },
    { range: '70-100%', min: 0.7, max: 1.01, count: 0, color: '#ef4444' },
  ]
  for (const cve of cves) {
    for (const bucket of epssBuckets) {
      if (cve.epss_score >= bucket.min && cve.epss_score < bucket.max) {
        bucket.count++
        break
      }
    }
  }

  // Sort CVEs
  const sortedCves = [...cves].sort((a, b) => {
    const mul = sortAsc ? 1 : -1
    if (sortField === 'cve_id') return mul * a.cve_id.localeCompare(b.cve_id)
    return mul * ((a[sortField] ?? 0) - (b[sortField] ?? 0))
  })

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc)
    } else {
      setSortField(field)
      setSortAsc(false)
    }
  }

  const sortIndicator = (field: typeof sortField) =>
    sortField === field ? (sortAsc ? ' \u25b2' : ' \u25bc') : ''

  // ATT&CK heatmap color
  const heatColor = (count: number) => {
    if (count === 0) return 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'
    if (count <= 2) return 'bg-red-200 text-red-800'
    if (count <= 5) return 'bg-red-400 text-white'
    return 'bg-red-600 text-white'
  }

  const severityBadge = (severity: string) => {
    const s = severity?.toLowerCase() || ''
    if (s === 'critical') return 'bg-red-600 text-white'
    if (s === 'high') return 'bg-orange-500 text-white'
    if (s === 'medium') return 'bg-yellow-500 text-white'
    if (s === 'low') return 'bg-blue-400 text-white'
    return 'bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300'
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Threat Intelligence</h2>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Total CVEs</p>
          <p className="text-3xl font-bold">{overview?.total_cves ?? 0}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Known Exploited (KEV)</p>
          <p className="text-3xl font-bold text-red-600">{overview?.kev_count ?? 0}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Avg EPSS Score</p>
          <p className="text-3xl font-bold">{((overview?.avg_epss ?? 0) * 100).toFixed(1)}%</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Exposed Resources</p>
          <p className="text-3xl font-bold text-orange-500">{overview?.exposure_count ?? 0}</p>
        </div>
      </div>

      {/* EPSS Distribution + KEV Panel */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {/* EPSS histogram */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">EPSS Score Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={epssBuckets}>
              <XAxis dataKey="range" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" name="CVEs">
                {epssBuckets.map((b, i) => (
                  <Cell key={i} fill={b.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* KEV urgency panel */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">Known Exploited Vulnerabilities (KEV)</h3>
          {kevFindings.length === 0 ? (
            <p className="text-gray-400 dark:text-gray-500 text-sm mt-4">No KEV findings detected</p>
          ) : (
            <div className="space-y-2 max-h-[250px] overflow-y-auto">
              {kevFindings.map((kf) => (
                <div key={kf.finding_uid} className="flex items-center gap-3 p-2 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityBadge(kf.vuln_severity)}`}>
                    {kf.vuln_severity || 'Unknown'}
                  </span>
                  <span className="text-sm font-medium flex-1 truncate">{kf.vuln_uid}</span>
                  <span className="text-xs text-gray-500 dark:text-gray-400">CVSS {kf.cvss_score.toFixed(1)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ATT&CK Heatmap */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4 mb-8">
        <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-4">MITRE ATT&CK Coverage</h3>
        {tactics.length === 0 ? (
          <p className="text-gray-400 dark:text-gray-500 text-sm">No ATT&CK data available</p>
        ) : (
          <div className="overflow-x-auto">
            <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(100px, 1fr))` }}>
              {/* Header row: tactic names */}
              {tactics.map((tac) => (
                <div key={tac.uid} className="text-xs font-semibold text-center p-1 bg-gray-800 text-white rounded-t">
                  {tac.name}
                  {tac.finding_count > 0 && <span className="ml-1 text-yellow-300">({tac.finding_count})</span>}
                </div>
              ))}
              {/* Technique cells — transpose: iterate by row index */}
              {Array.from({ length: Math.max(...tactics.map((t) => t.techniques?.length ?? 0)) }).map((_, rowIdx) => (
                tactics.map((tac) => {
                  const tech = tac.techniques?.[rowIdx]
                  if (!tech) return <div key={`${tac.uid}-${rowIdx}`} className="bg-gray-50 dark:bg-gray-900 min-h-[28px]" />
                  return (
                    <div
                      key={tech.uid}
                      className={`text-xs p-1 rounded text-center truncate ${heatColor(tech.finding_count)}`}
                      title={`${tech.uid} ${tech.name} (${tech.finding_count} findings)`}
                    >
                      {tech.uid}
                    </div>
                  )
                })
              ))}
            </div>
          </div>
        )}
      </div>

      {/* CVE Inventory Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4 mb-8">
        <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">CVE Inventory</h3>
        {sortedCves.length === 0 ? (
          <p className="text-gray-400 dark:text-gray-500 text-sm">No CVEs found</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b dark:border-gray-700 text-left text-gray-500 dark:text-gray-400">
                  <th className="p-2 cursor-pointer select-none" onClick={() => handleSort('cve_id')}>
                    CVE ID{sortIndicator('cve_id')}
                  </th>
                  <th className="p-2 cursor-pointer select-none" onClick={() => handleSort('cvss_score')}>
                    CVSS{sortIndicator('cvss_score')}
                  </th>
                  <th className="p-2 cursor-pointer select-none" onClick={() => handleSort('epss_score')}>
                    EPSS{sortIndicator('epss_score')}
                  </th>
                  <th className="p-2">KEV</th>
                  <th className="p-2">Severity</th>
                  <th className="p-2">Title</th>
                  <th className="p-2">Affected</th>
                </tr>
              </thead>
              <tbody>
                {sortedCves.map((cve) => (
                  <tr key={cve.cve_id} className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="p-2 font-mono">{cve.cve_id}</td>
                    <td className="p-2">{cve.cvss_score.toFixed(1)}</td>
                    <td className="p-2">{(cve.epss_score * 100).toFixed(1)}%</td>
                    <td className="p-2">
                      {cve.is_exploited && (
                        <span className="px-2 py-0.5 bg-red-600 text-white text-xs rounded font-medium">KEV</span>
                      )}
                    </td>
                    <td className="p-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityBadge(cve.severity)}`}>
                        {cve.severity || 'Unknown'}
                      </span>
                    </td>
                    <td className="p-2 truncate max-w-xs">{cve.title}</td>
                    <td className="p-2 text-center">{cve.affected_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Exposed Resources */}
      {exposed.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">Exposed Resources</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b dark:border-gray-700 text-left text-gray-500 dark:text-gray-400">
                  <th className="p-2">Resource</th>
                  <th className="p-2">Type</th>
                  <th className="p-2">Provider</th>
                  <th className="p-2">Endpoint</th>
                  <th className="p-2">Port</th>
                  <th className="p-2">Protocol</th>
                </tr>
              </thead>
              <tbody>
                {exposed.map((r) => (
                  <tr key={r.resource_uid} className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="p-2 font-mono text-xs truncate max-w-xs">{r.resource_name || r.resource_uid}</td>
                    <td className="p-2">{r.resource_type}</td>
                    <td className="p-2">{r.provider}</td>
                    <td className="p-2 font-mono">{r.endpoint}</td>
                    <td className="p-2">{r.port}</td>
                    <td className="p-2">{r.protocol}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
