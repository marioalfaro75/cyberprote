import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { api } from '../api/client'
import type { FrameworkInfo, FrameworkPosture, ControlPosture } from '../api/compliance-types'
import { severityColor } from '../utils/severity'

export default function CompliancePosturePage() {
  const [frameworks, setFrameworks] = useState<FrameworkInfo[]>([])
  const [selectedFw, setSelectedFw] = useState<string>('')
  const [posture, setPosture] = useState<FrameworkPosture | null>(null)
  const [expandedControl, setExpandedControl] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.getComplianceFrameworks()
      .then((res) => {
        setFrameworks(res.frameworks || [])
        if (res.frameworks?.length > 0) {
          setSelectedFw(res.frameworks[0].id)
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!selectedFw) return
    setLoading(true)
    setExpandedControl(null)
    api.getFrameworkPosture(selectedFw)
      .then(setPosture)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [selectedFw])

  if (loading && !posture) {
    return <div className="text-gray-500 dark:text-gray-400">Loading compliance data...</div>
  }

  if (error) {
    return <div className="text-red-600">Error: {error}</div>
  }

  const score = posture?.score ?? -1
  const scoreColor = score < 0 ? 'text-gray-400' : score >= 80 ? 'text-green-600' : score >= 50 ? 'text-yellow-600' : 'text-red-600'

  // Build category-level chart data
  const categoryData = posture?.functions.flatMap((fn) =>
    fn.categories.map((cat) => ({
      name: cat.id,
      pass: cat.status.pass,
      fail: cat.status.fail,
      unknown: cat.status.unknown,
    }))
  ) || []

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Compliance Posture</h1>

      {/* Framework selector tabs */}
      <div className="flex space-x-2 mb-6">
        {frameworks.map((fw) => (
          <button
            key={fw.id}
            onClick={() => setSelectedFw(fw.id)}
            className={`px-4 py-2 rounded-t font-medium text-sm ${
              selectedFw === fw.id
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
            }`}
          >
            {fw.name} {fw.version}
          </button>
        ))}
      </div>

      {posture && (
        <>
          {/* Score gauge */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-6 mb-6 flex items-center space-x-8">
            <div className="text-center">
              <div className={`text-5xl font-bold ${scoreColor}`}>
                {score < 0 ? 'N/A' : `${Math.round(score)}%`}
              </div>
              <div className="text-gray-500 dark:text-gray-400 text-sm mt-1">Compliance Score</div>
            </div>
            <div className="flex space-x-6">
              <StatBadge label="Pass" value={posture.status.pass} color="bg-green-100 text-green-800" />
              <StatBadge label="Fail" value={posture.status.fail} color="bg-red-100 text-red-800" />
              <StatBadge label="Unknown" value={posture.status.unknown} color="bg-gray-100 text-gray-800" />
            </div>
          </div>

          {/* Category bar chart */}
          {categoryData.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-6 mb-6">
              <h2 className="text-lg font-semibold mb-4">Category Compliance</h2>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={categoryData} layout="vertical" margin={{ left: 60 }}>
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={80} tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Bar dataKey="pass" stackId="a" fill="#22c55e" name="Pass" />
                  <Bar dataKey="fail" stackId="a" fill="#ef4444" name="Fail" />
                  <Bar dataKey="unknown" stackId="a" fill="#d1d5db" name="Unknown" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Function / category / control drilldown */}
          <div className="space-y-4">
            {posture.functions.map((fn) => (
              <div key={fn.id} className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50">
                <div className="p-4 border-b dark:border-gray-700">
                  <h2 className="text-lg font-semibold">
                    {fn.id} — {fn.name}
                  </h2>
                  <div className="flex space-x-4 text-sm mt-1">
                    <span className="text-green-700">{fn.status.pass} pass</span>
                    <span className="text-red-700">{fn.status.fail} fail</span>
                    <span className="text-gray-500 dark:text-gray-400">{fn.status.unknown} unknown</span>
                  </div>
                </div>
                {fn.categories.map((cat) => (
                  <div key={cat.id} className="border-b last:border-b-0 dark:border-gray-700">
                    <div className="px-4 py-3 bg-gray-50 dark:bg-gray-700">
                      <span className="font-medium text-sm">{cat.id} — {cat.name}</span>
                      <span className="text-xs text-gray-500 dark:text-gray-400 ml-4">
                        {cat.status.pass}P / {cat.status.fail}F / {cat.status.unknown}U
                      </span>
                    </div>
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-gray-500 dark:text-gray-400 text-xs">
                          <th className="px-4 py-2 w-32">Control</th>
                          <th className="px-4 py-2">Name</th>
                          <th className="px-4 py-2 w-20 text-center">Pass</th>
                          <th className="px-4 py-2 w-20 text-center">Fail</th>
                          <th className="px-4 py-2 w-20 text-center">Unknown</th>
                        </tr>
                      </thead>
                      <tbody>
                        {cat.controls.map((ctrl) => (
                          <ControlRow
                            key={ctrl.id}
                            ctrl={ctrl}
                            expanded={expandedControl === `${fn.id}/${cat.id}/${ctrl.id}`}
                            onToggle={() =>
                              setExpandedControl(
                                expandedControl === `${fn.id}/${cat.id}/${ctrl.id}`
                                  ? null
                                  : `${fn.id}/${cat.id}/${ctrl.id}`
                              )
                            }
                          />
                        ))}
                      </tbody>
                    </table>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function StatBadge({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className={`px-4 py-2 rounded ${color}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs">{label}</div>
    </div>
  )
}

function ControlRow({
  ctrl,
  expanded,
  onToggle,
}: {
  ctrl: ControlPosture
  expanded: boolean
  onToggle: () => void
}) {
  const hasFindings = (ctrl.findings?.length ?? 0) > 0

  return (
    <>
      <tr
        className={`border-t dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 ${hasFindings ? 'cursor-pointer' : ''}`}
        onClick={hasFindings ? onToggle : undefined}
      >
        <td className="px-4 py-2 font-mono text-xs">{ctrl.id}</td>
        <td className="px-4 py-2">
          {ctrl.name}
          {hasFindings && (
            <span className="ml-2 text-gray-400 dark:text-gray-500 text-xs">{expanded ? '▼' : '▶'}</span>
          )}
        </td>
        <td className="px-4 py-2 text-center">
          {ctrl.status.pass > 0 && (
            <span className="bg-green-100 text-green-800 px-2 py-0.5 rounded text-xs">{ctrl.status.pass}</span>
          )}
        </td>
        <td className="px-4 py-2 text-center">
          {ctrl.status.fail > 0 && (
            <span className="bg-red-100 text-red-800 px-2 py-0.5 rounded text-xs">{ctrl.status.fail}</span>
          )}
        </td>
        <td className="px-4 py-2 text-center">
          {ctrl.status.unknown > 0 && (
            <span className="bg-gray-100 text-gray-600 px-2 py-0.5 rounded text-xs">{ctrl.status.unknown}</span>
          )}
        </td>
      </tr>
      {expanded && ctrl.findings && (
        <tr>
          <td colSpan={5} className="bg-gray-50 dark:bg-gray-900 px-6 py-3">
            <div className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Findings ({ctrl.findings.length})</div>
            <div className="space-y-1">
              {ctrl.findings.map((f) => (
                <div key={f.uid} className="flex items-center space-x-3 text-xs">
                  <span className={`px-2 py-0.5 rounded ${severityColor(f.severity_id)}`}>
                    S{f.severity_id}
                  </span>
                  <ComplianceBadge status={f.compliance_status} />
                  <span className="text-gray-600 dark:text-gray-400 truncate flex-1" title={f.title}>{f.title}</span>
                  <span className="text-gray-400 dark:text-gray-500">{f.provider}</span>
                </div>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function ComplianceBadge({ status }: { status: string }) {
  const s = status?.toLowerCase()
  const color =
    s === 'pass' || s === 'passed' || s === 'compliant'
      ? 'bg-green-100 text-green-800'
      : s === 'fail' || s === 'failed' || s === 'non_compliant'
        ? 'bg-red-100 text-red-800'
        : 'bg-gray-100 text-gray-600'
  return <span className={`px-2 py-0.5 rounded ${color}`}>{status || 'unknown'}</span>
}
