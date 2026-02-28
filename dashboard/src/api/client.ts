import type { ProviderSettings, SaveResult, TestConnectionResult, ApplyResult } from './settings-types'

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

  // Settings / connector configuration
  getConnectorSettings: () => fetchJSON<ProviderSettings>('/settings/connectors'),
  updateConnectorSettings: (settings: ProviderSettings) =>
    fetchJSON<SaveResult>('/settings/connectors', {
      method: 'PUT',
      body: JSON.stringify(settings),
    }),
  updateConnectorSecrets: (provider: string, key: string, value: string) =>
    fetchJSON<{ saved: boolean; restart_required: boolean }>(
      `/settings/connectors/${provider}/secrets`,
      { method: 'PUT', body: JSON.stringify({ key, value }) },
    ),
  testConnectorConnection: (provider: string) =>
    fetchJSON<TestConnectionResult>(`/settings/connectors/${provider}/test`, {
      method: 'POST',
    }),
  applySettings: () =>
    fetchJSON<ApplyResult>('/settings/apply', { method: 'POST' }),
}
