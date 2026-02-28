import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { formatSnakeCase, severityColor, severityLabel } from '../utils/severity'

const DESCRIPTIONS: Record<string, string> = {
  public_admin_access: 'Resources with public exposure combined with administrative access',
  public_vuln_critical: 'Publicly accessible resources with critical vulnerabilities',
  overprivileged_identity: 'Identities with excessive permissions beyond their needs',
  unencrypted_public: 'Publicly accessible resources lacking encryption',
  stale_admin_keys: 'Administrative API keys that have not been rotated',
  cross_account_trust: 'Cross-account trust relationships that may be exploitable',
  exposed_secrets: 'Secrets or credentials exposed in code or configurations',
  lateral_movement_path: 'Paths that enable lateral movement across resources',
  privilege_escalation_chain: 'Chains of permissions enabling privilege escalation',
  data_exfil_risk: 'Resources at risk of data exfiltration',
  shadow_admin: 'Identities with effective admin access through indirect permissions',
  orphaned_resources: 'Resources without proper ownership or management',
  compliance_gap: 'Resources failing multiple compliance requirements',
  network_exposure: 'Resources with excessive network exposure',
  iam_misconfiguration: 'Identity and access management misconfigurations',
}

interface ResultItem {
  title?: string
  name?: string
  severity_id?: number
  resource_name?: string
  type?: string
  [key: string]: unknown
}

export default function ToxicCombinations() {
  const [combinations, setCombinations] = useState<string[]>([])
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [results, setResults] = useState<ResultItem[]>([])
  const [loadingCounts, setLoadingCounts] = useState(true)

  useEffect(() => {
    api.getToxicCombinations().then(async (data) => {
      setCombinations(data.toxic_combinations)
      const countMap: Record<string, number> = {}
      await Promise.all(
        data.toxic_combinations.map(async (name) => {
          try {
            const r = await api.getToxicCombination(name)
            countMap[name] = r.count
          } catch {
            countMap[name] = -1
          }
        })
      )
      setCounts(countMap)
      setLoadingCounts(false)
    })
  }, [])

  const handleSelect = async (name: string) => {
    setSelected(name)
    const data = await api.getToxicCombination(name)
    setResults(data.results as ResultItem[])
  }

  const dangerCount = Object.values(counts).filter((c) => c > 0).length
  const safeCount = Object.values(counts).filter((c) => c === 0).length

  return (
    <div>
      <h2 className="text-2xl font-bold mb-2">Toxic Combinations</h2>
      {!loadingCounts && (
        <p className="text-sm text-gray-500 mb-6">
          <span className="text-red-600 font-medium">{dangerCount} detected</span>
          {' · '}
          <span className="text-green-600 font-medium">{safeCount} clear</span>
        </p>
      )}

      {/* Card grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {combinations.map((name) => {
          const count = counts[name]
          const hasResults = count !== undefined && count > 0
          const isSelected = selected === name
          return (
            <button
              key={name}
              onClick={() => handleSelect(name)}
              className={`text-left rounded-lg shadow p-4 border-2 transition-colors ${
                isSelected
                  ? 'border-blue-500 bg-blue-50'
                  : hasResults
                    ? 'border-red-200 bg-white hover:border-red-400'
                    : 'border-green-200 bg-white hover:border-green-400'
              }`}
            >
              <div className="flex items-start justify-between mb-1">
                <h3 className="font-semibold text-sm">{formatSnakeCase(name)}</h3>
                {count !== undefined && (
                  <span className={`ml-2 px-2 py-0.5 rounded-full text-xs font-bold ${
                    count > 0 ? 'bg-red-100 text-red-800' : count === 0 ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-500'
                  }`}>
                    {count >= 0 ? count : '?'}
                  </span>
                )}
                {count === undefined && loadingCounts && (
                  <span className="ml-2 px-2 py-0.5 rounded-full text-xs bg-gray-100 text-gray-400">…</span>
                )}
              </div>
              <p className="text-xs text-gray-500">{DESCRIPTIONS[name] || 'Security pattern analysis'}</p>
            </button>
          )
        })}
      </div>

      {/* Result detail */}
      {selected && (
        <div className="bg-white rounded-lg shadow p-4">
          <h3 className="font-semibold mb-3">{formatSnakeCase(selected)}</h3>
          {results.length === 0 ? (
            <p className="text-green-600 text-sm">No toxic combinations detected for this pattern.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Title / Name</th>
                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Resource</th>
                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {results.map((r, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-3 py-2">{r.title || r.name || `Result ${i + 1}`}</td>
                      <td className="px-3 py-2">
                        {r.severity_id != null ? (
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityColor(r.severity_id)}`}>
                            {severityLabel(r.severity_id)}
                          </span>
                        ) : '-'}
                      </td>
                      <td className="px-3 py-2 text-gray-600">{r.resource_name || '-'}</td>
                      <td className="px-3 py-2 text-gray-600">{r.type || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
