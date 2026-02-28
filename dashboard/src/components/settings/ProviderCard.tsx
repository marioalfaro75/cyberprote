import { ReactNode, useState } from 'react'
import type { TestConnectionResult } from '../../api/settings-types'
import { api } from '../../api/client'

interface ProviderCardProps {
  name: string
  provider: string
  color: string
  enabled: boolean
  onToggle: (enabled: boolean) => void
  children: ReactNode
}

export default function ProviderCard({ name, provider, color, enabled, onToggle, children }: ProviderCardProps) {
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null)

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const result = await api.testConnectorConnection(provider)
      setTestResult(result)
    } catch (err) {
      setTestResult({ success: false, error: String(err) })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className={`border rounded-lg overflow-hidden ${enabled ? 'border-gray-300' : 'border-gray-200'}`}>
      <div className="flex items-center justify-between px-4 py-3" style={{ borderLeft: `4px solid ${color}` }}>
        <h3 className="font-medium text-gray-900">{name}</h3>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => onToggle(e.target.checked)}
            className="sr-only peer"
          />
          <div className="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600" />
        </label>
      </div>
      {enabled && (
        <div className="px-4 pb-4 space-y-4 border-t border-gray-100 pt-4">
          {children}
          <div className="flex items-center gap-3 pt-2 border-t border-gray-100">
            <button
              type="button"
              onClick={handleTest}
              disabled={testing}
              className="px-3 py-1.5 text-sm border border-gray-300 rounded hover:bg-gray-50 disabled:opacity-50"
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            {testResult && (
              <span className={`text-sm ${testResult.success ? 'text-green-600' : 'text-red-600'}`}>
                {testResult.success ? testResult.message : testResult.error}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
