import { useEffect, useState } from 'react'
import { api } from '../api/client'

const PIPELINE_ENDPOINTS = [
  { name: 'OTLP gRPC', address: 'localhost:4317', description: 'OpenTelemetry gRPC receiver' },
  { name: 'OTLP HTTP', address: 'localhost:4318', description: 'OpenTelemetry HTTP receiver' },
  { name: 'zPages', address: 'localhost:55679', description: 'Debug pages for pipeline diagnostics' },
  { name: 'Metrics', address: 'localhost:8888', description: 'Collector internal metrics' },
]

const RECEIVERS = [
  { name: 'AWS Security Hub', key: 'awssechubreceiver', status: 'configured' },
  { name: 'GitHub GHAS', key: 'githubghasreceiver', status: 'configured' },
  { name: 'GCP SCC', key: 'gcpsccreceiver', status: 'stub' },
  { name: 'Azure Defender', key: 'azuredefenderreceiver', status: 'stub' },
]

export default function ConnectorHealth() {
  const [status, setStatus] = useState<{ collector: string } | null>(null)
  const [lastChecked, setLastChecked] = useState<Date | null>(null)

  useEffect(() => {
    api.getConnectorStatus()
      .then((s) => { setStatus(s); setLastChecked(new Date()) })
      .catch(() => { setStatus({ collector: 'unreachable' }); setLastChecked(new Date()) })
  }, [])

  const isHealthy = status?.collector === 'healthy'

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Connector Health</h2>

      {/* Collector status */}
      <div className={`rounded-lg shadow p-6 mb-6 ${isHealthy ? 'bg-white' : 'bg-red-50'}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`w-4 h-4 rounded-full ${isHealthy ? 'bg-green-500' : 'bg-red-500'} ${isHealthy ? 'animate-pulse' : ''}`} />
            <div>
              <span className="font-semibold text-lg">OTel Collector</span>
              <span className={`ml-3 px-2 py-1 rounded text-xs font-medium ${isHealthy ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                {status?.collector || 'checking...'}
              </span>
            </div>
          </div>
          {lastChecked && (
            <span className="text-xs text-gray-400">
              Last checked: {lastChecked.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Pipeline endpoints */}
      <h3 className="text-lg font-semibold mb-3">Pipeline Endpoints</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        {PIPELINE_ENDPOINTS.map((ep) => (
          <div key={ep.name} className="bg-white rounded-lg shadow p-4">
            <div className="flex items-center justify-between mb-1">
              <span className="font-medium text-sm">{ep.name}</span>
              <code className="text-xs bg-gray-100 px-2 py-1 rounded">{ep.address}</code>
            </div>
            <p className="text-xs text-gray-500">{ep.description}</p>
          </div>
        ))}
      </div>

      {/* Receiver status */}
      <h3 className="text-lg font-semibold mb-3">Receivers</h3>
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Receiver</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Component</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {RECEIVERS.map((r) => (
              <tr key={r.key}>
                <td className="px-4 py-3 text-sm font-medium">{r.name}</td>
                <td className="px-4 py-3 text-sm font-mono text-gray-500">{r.key}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    r.status === 'configured' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                  }`}>
                    {r.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
