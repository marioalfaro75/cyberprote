const BASE_URL = '/api/v1'

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`)
  }
  return response.json()
}

export const api = {
  getHealth: () => fetchJSON<{ status: string }>('/health'),
  getFindings: (limit = 50) => fetchJSON<{ findings: unknown[]; count: number }>(`/findings?limit=${limit}`),
  getToxicCombinations: () => fetchJSON<{ toxic_combinations: string[]; count: number }>('/risk/toxic-combinations'),
  getToxicCombination: (name: string) => fetchJSON<{ name: string; results: unknown[]; count: number }>(`/risk/toxic-combinations/${name}`),
  getConnectorStatus: () => fetchJSON<{ collector: string }>('/connectors/status'),
  getPolicies: () => fetchJSON<{ policies: string[]; count: number }>('/policies'),
  evaluatePolicy: (finding: unknown) => fetchJSON<{ decision: string; reasons: string[] }>('/policies/evaluate', {
    method: 'POST',
    body: JSON.stringify(finding),
  }),
  getGraphStats: () => fetchJSON<Record<string, number>>('/graph/stats'),
}
