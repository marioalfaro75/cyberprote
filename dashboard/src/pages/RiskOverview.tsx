import { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { api } from '../api/client'
import { severityLabel, severityFill, statusColor, providerColor } from '../utils/severity'

interface FindingProps {
  severity_id?: number
  provider?: string
  status?: string
}

function getProps(f: Record<string, unknown>): FindingProps {
  return (f.properties as FindingProps) || {}
}

export default function RiskOverview() {
  const [stats, setStats] = useState<Record<string, number>>({})
  const [findings, setFindings] = useState<Record<string, unknown>[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.getGraphStats(),
      api.getFindings(500).then((d) => d.findings as Record<string, unknown>[]),
    ])
      .then(([s, f]) => { setStats(s); setFindings(f) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-8 text-gray-500 dark:text-gray-400">Loading...</div>

  // Node type distribution for donut chart
  const nodeData = Object.entries(stats)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))
  const NODE_COLORS = ['#3b82f6', '#ef4444', '#f97316', '#10b981', '#8b5cf6', '#eab308']

  // Severity breakdown
  const sevCounts: Record<number, number> = {}
  const provCounts: Record<string, number> = {}
  const statusCounts: Record<string, number> = {}
  for (const f of findings) {
    const p = getProps(f)
    const sev = p.severity_id ?? 0
    sevCounts[sev] = (sevCounts[sev] || 0) + 1
    const prov = p.provider ?? 'Unknown'
    provCounts[prov] = (provCounts[prov] || 0) + 1
    const st = p.status ?? 'Unknown'
    statusCounts[st] = (statusCounts[st] || 0) + 1
  }

  const sevData = Object.entries(sevCounts)
    .map(([id, count]) => ({ name: severityLabel(Number(id)), value: count, id: Number(id) }))
    .sort((a, b) => b.id - a.id)

  const provData = Object.entries(provCounts)
    .map(([name, value]) => ({ name, value }))

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Risk Overview</h2>

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {Object.entries(stats).map(([label, count]) => (
          <div key={label} className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
            <p className="text-3xl font-bold">{count >= 0 ? count : 'N/A'}</p>
          </div>
        ))}
      </div>

      {/* Status summary */}
      {Object.keys(statusCounts).length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {Object.entries(statusCounts).map(([status, count]) => (
            <div key={status} className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4 flex items-center gap-3">
              <span className={`px-2 py-1 rounded text-xs font-medium ${statusColor(status)}`}>{status}</span>
              <span className="text-2xl font-bold">{count}</span>
            </div>
          ))}
        </div>
      )}

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Node type donut */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">Node Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={nodeData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                {nodeData.map((_, i) => (
                  <Cell key={i} fill={NODE_COLORS[i % NODE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Severity bar chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">Findings by Severity</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={sevData} layout="vertical" margin={{ left: 80 }}>
              <XAxis type="number" allowDecimals={false} />
              <YAxis type="category" dataKey="name" width={75} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="value" name="Findings">
                {sevData.map((d) => (
                  <Cell key={d.id} fill={severityFill(d.id)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Provider pie */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/50 p-4">
          <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">Findings by Provider</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={provData} dataKey="value" nameKey="name" outerRadius={90} paddingAngle={2}>
                {provData.map((d) => (
                  <Cell key={d.name} fill={providerColor(d.name)} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
