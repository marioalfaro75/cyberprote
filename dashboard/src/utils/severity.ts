export function severityColor(id: number): string {
  switch (id) {
    case 1: return 'bg-blue-100 text-blue-800'
    case 2: return 'bg-yellow-100 text-yellow-800'
    case 3: return 'bg-orange-100 text-orange-800'
    case 4: return 'bg-red-100 text-red-800'
    case 5: return 'bg-red-200 text-red-900'
    default: return 'bg-gray-100 text-gray-800'
  }
}

export function severityFill(id: number): string {
  switch (id) {
    case 1: return '#3b82f6'
    case 2: return '#eab308'
    case 3: return '#f97316'
    case 4: return '#ef4444'
    case 5: return '#991b1b'
    default: return '#9ca3af'
  }
}

export function severityLabel(id: number): string {
  switch (id) {
    case 1: return 'Informational'
    case 2: return 'Low'
    case 3: return 'Medium'
    case 4: return 'High'
    case 5: return 'Critical'
    default: return 'Unknown'
  }
}

export function statusColor(status: string): string {
  switch (status?.toLowerCase()) {
    case 'new': return 'bg-blue-100 text-blue-800'
    case 'in_progress': case 'in progress': return 'bg-yellow-100 text-yellow-800'
    case 'resolved': return 'bg-green-100 text-green-800'
    case 'suppressed': return 'bg-gray-100 text-gray-600'
    default: return 'bg-gray-100 text-gray-800'
  }
}

export function formatSnakeCase(s: string): string {
  return s
    .replace(/[-_]/g, ' ')
    .replace(/\.rego$/i, '')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

const PROVIDER_COLORS: Record<string, string> = {
  AWS: '#ff9900',
  GitHub: '#333333',
  GCP: '#4285f4',
  Azure: '#0078d4',
}

export function providerColor(provider: string): string {
  return PROVIDER_COLORS[provider] || '#6b7280'
}
