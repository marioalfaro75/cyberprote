import { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { api } from '../api/client'
import { formatSnakeCase } from '../utils/severity'

const DECISION_STYLES: Record<string, { bg: string; text: string; icon: string }> = {
  escalate: { bg: 'bg-red-100', text: 'text-red-800', icon: '!' },
  immediate_action: { bg: 'bg-red-200', text: 'text-red-900', icon: '!!' },
  suppress: { bg: 'bg-gray-100', text: 'text-gray-600', icon: '—' },
  auto_remediate: { bg: 'bg-blue-100', text: 'text-blue-800', icon: '~' },
  normal: { bg: 'bg-green-100', text: 'text-green-800', icon: '*' },
}

const DECISION_COLORS: Record<string, string> = {
  escalate: '#ef4444',
  immediate_action: '#991b1b',
  suppress: '#9ca3af',
  auto_remediate: '#3b82f6',
  normal: '#10b981',
}

function decisionStyle(decision: string) {
  return DECISION_STYLES[decision] || DECISION_STYLES.normal
}

function inferDecisionType(policyName: string): string {
  const name = policyName.toLowerCase()
  if (name.includes('critical') || name.includes('immediate')) return 'immediate_action'
  if (name.includes('escalat') || name.includes('high')) return 'escalate'
  if (name.includes('suppress') || name.includes('ignore')) return 'suppress'
  if (name.includes('auto') || name.includes('remediat')) return 'auto_remediate'
  return 'normal'
}

export default function Policies() {
  const [policies, setPolicies] = useState<string[]>([])
  const [testInput, setTestInput] = useState('{\n  "class_uid": 2001,\n  "severity_id": 5\n}')
  const [evalResult, setEvalResult] = useState<{ decision: string; reasons: string[] } | null>(null)
  const [bulkResults, setBulkResults] = useState<Record<string, number>>({})
  const [loadingBulk, setLoadingBulk] = useState(false)

  useEffect(() => {
    api.getPolicies().then((data) => setPolicies(data.policies))
  }, [])

  // Bulk evaluation: evaluate sample findings against policies on page load
  useEffect(() => {
    setLoadingBulk(true)
    api.getFindings(100)
      .then(async (data) => {
        const findings = data.findings as Record<string, unknown>[]
        const counts: Record<string, number> = {}
        // Evaluate a sample of findings (up to 20)
        const sample = findings.slice(0, 20)
        await Promise.all(
          sample.map(async (f) => {
            try {
              const props = (f as Record<string, unknown>).properties || f
              const result = await api.evaluatePolicy(props)
              counts[result.decision] = (counts[result.decision] || 0) + 1
            } catch {
              // skip failed evaluations
            }
          })
        )
        setBulkResults(counts)
      })
      .catch(console.error)
      .finally(() => setLoadingBulk(false))
  }, [])

  const handleEvaluate = async () => {
    try {
      const finding = JSON.parse(testInput)
      const result = await api.evaluatePolicy(finding)
      setEvalResult(result)
    } catch {
      setEvalResult({ decision: 'error', reasons: ['Invalid JSON input'] })
    }
  }

  // Group policies by inferred decision type
  const grouped: Record<string, string[]> = {}
  for (const p of policies) {
    const dt = inferDecisionType(p)
    if (!grouped[dt]) grouped[dt] = []
    grouped[dt].push(p)
  }

  // Bulk results pie chart data
  const pieData = Object.entries(bulkResults).map(([name, value]) => ({ name, value }))

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Policy Engine</h2>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policy cards — left 2 columns */}
        <div className="lg:col-span-2">
          <h3 className="font-semibold mb-3">Loaded Policies</h3>
          {Object.entries(grouped).length > 0 ? (
            <div className="space-y-4">
              {Object.entries(grouped).map(([decision, pols]) => {
                const style = decisionStyle(decision)
                return (
                  <div key={decision}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`w-6 h-6 rounded flex items-center justify-center text-xs font-bold ${style.bg} ${style.text}`}>
                        {style.icon}
                      </span>
                      <span className="text-sm font-medium text-gray-600 uppercase">{formatSnakeCase(decision)}</span>
                      <span className="text-xs text-gray-400">({pols.length})</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {pols.map((p) => (
                        <div key={p} className={`px-3 py-2 rounded-lg border ${style.bg} border-opacity-50`}>
                          <p className={`text-sm font-medium ${style.text}`}>{formatSnakeCase(p)}</p>
                          <p className="text-xs text-gray-400 font-mono">{p}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="text-gray-400 text-sm">No policies loaded</p>
          )}
        </div>

        {/* Right column: bulk eval + test panel */}
        <div className="space-y-6">
          {/* Bulk evaluation summary */}
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="font-semibold mb-2 text-sm">Bulk Evaluation Summary</h3>
            <p className="text-xs text-gray-500 mb-3">Sample of findings evaluated against policies</p>
            {loadingBulk ? (
              <p className="text-gray-400 text-sm">Evaluating...</p>
            ) : pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={70} paddingAngle={2}>
                    {pieData.map((d) => (
                      <Cell key={d.name} fill={DECISION_COLORS[d.name] || '#6b7280'} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-gray-400 text-sm">No evaluation data</p>
            )}
          </div>

          {/* Test panel */}
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="font-semibold mb-2 text-sm">Test Policy</h3>
            <textarea
              value={testInput}
              onChange={(e) => setTestInput(e.target.value)}
              className="w-full h-32 border rounded p-2 font-mono text-sm"
            />
            <button onClick={handleEvaluate} className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm">
              Evaluate
            </button>
            {evalResult && (
              <div className="mt-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Decision:</span>
                  <span className={`px-2 py-1 rounded text-xs font-bold ${decisionStyle(evalResult.decision).bg} ${decisionStyle(evalResult.decision).text}`}>
                    {evalResult.decision}
                  </span>
                </div>
                {evalResult.reasons?.length > 0 && (
                  <ul className="mt-2 text-xs text-gray-600 space-y-1">
                    {evalResult.reasons.map((r, i) => <li key={i}>- {r}</li>)}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
