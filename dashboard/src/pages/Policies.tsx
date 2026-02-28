import { useEffect, useState } from 'react'
import { api } from '../api/client'

export default function Policies() {
  const [policies, setPolicies] = useState<string[]>([])
  const [testInput, setTestInput] = useState('{\n  "class_uid": 2001,\n  "severity_id": 5\n}')
  const [evalResult, setEvalResult] = useState<{ decision: string; reasons: string[] } | null>(null)

  useEffect(() => {
    api.getPolicies().then((data) => setPolicies(data.policies))
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

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Policy Engine</h2>
      <div className="grid grid-cols-2 gap-6">
        <div>
          <h3 className="font-semibold mb-3">Loaded Policies</h3>
          <ul className="space-y-1">
            {policies.map((p) => (
              <li key={p} className="bg-white px-3 py-2 rounded shadow-sm text-sm">{p}</li>
            ))}
          </ul>
        </div>
        <div>
          <h3 className="font-semibold mb-3">Test Policy</h3>
          <textarea
            value={testInput}
            onChange={(e) => setTestInput(e.target.value)}
            className="w-full h-40 border rounded p-2 font-mono text-sm"
          />
          <button onClick={handleEvaluate} className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
            Evaluate
          </button>
          {evalResult && (
            <div className="mt-4 bg-white rounded shadow p-4">
              <p className="font-medium">Decision: <span className="text-blue-600">{evalResult.decision}</span></p>
              {evalResult.reasons?.length > 0 && (
                <ul className="mt-2 text-sm text-gray-600">
                  {evalResult.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
