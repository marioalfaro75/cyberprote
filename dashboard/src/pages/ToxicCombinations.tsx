import { useEffect, useState } from 'react'
import { api } from '../api/client'

export default function ToxicCombinations() {
  const [combinations, setCombinations] = useState<string[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [results, setResults] = useState<unknown[]>([])

  useEffect(() => {
    api.getToxicCombinations().then((data) => setCombinations(data.toxic_combinations))
  }, [])

  const handleSelect = async (name: string) => {
    setSelected(name)
    const data = await api.getToxicCombination(name)
    setResults(data.results)
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Toxic Combinations</h2>
      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-1 space-y-2">
          {combinations.map((name) => (
            <button
              key={name}
              onClick={() => handleSelect(name)}
              className={`w-full text-left px-3 py-2 rounded text-sm ${
                selected === name ? 'bg-red-100 text-red-800' : 'bg-white hover:bg-gray-100'
              }`}
            >
              {name.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
        <div className="col-span-2 bg-white rounded-lg shadow p-4">
          {selected ? (
            <>
              <h3 className="font-semibold mb-2">{selected.replace(/_/g, ' ')}</h3>
              <pre className="text-xs bg-gray-50 p-3 rounded overflow-auto max-h-96">
                {JSON.stringify(results, null, 2)}
              </pre>
            </>
          ) : (
            <p className="text-gray-400">Select a toxic combination to view results</p>
          )}
        </div>
      </div>
    </div>
  )
}
