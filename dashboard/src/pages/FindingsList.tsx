import { useEffect, useState } from 'react'
import { api } from '../api/client'

const severityColors: Record<number, string> = {
  1: 'bg-blue-100 text-blue-800',
  2: 'bg-yellow-100 text-yellow-800',
  3: 'bg-orange-100 text-orange-800',
  4: 'bg-red-100 text-red-800',
  5: 'bg-red-200 text-red-900',
}

export default function FindingsList() {
  const [findings, setFindings] = useState<Record<string, unknown>[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getFindings(100)
      .then((data) => setFindings(data.findings as Record<string, unknown>[]))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div>Loading...</div>

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Findings</h2>
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Provider</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {findings?.map((f, i) => {
              const props = (f as Record<string, unknown>)?.properties as Record<string, unknown> | undefined
              return (
                <tr key={i} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${severityColors[props?.severity_id as number] || 'bg-gray-100'}`}>
                      {String(props?.severity_id ?? 'N/A')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{(props?.title as string) || 'Untitled'}</td>
                  <td className="px-4 py-3 text-sm">{(props?.provider as string) || '-'}</td>
                  <td className="px-4 py-3 text-sm">{(props?.status as string) || '-'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {(!findings || findings.length === 0) && (
          <p className="text-center text-gray-400 py-8">No findings found</p>
        )}
      </div>
    </div>
  )
}
