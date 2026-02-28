import { useEffect, useState } from 'react'
import { api } from '../api/client'

export default function ConnectorHealth() {
  const [status, setStatus] = useState<{ collector: string } | null>(null)

  useEffect(() => {
    api.getConnectorStatus()
      .then(setStatus)
      .catch(() => setStatus({ collector: 'unreachable' }))
  }, [])

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Connector Health</h2>
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${status?.collector === 'healthy' ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="font-medium">OTel Collector</span>
          <span className="text-sm text-gray-500">{status?.collector || 'checking...'}</span>
        </div>
      </div>
    </div>
  )
}
