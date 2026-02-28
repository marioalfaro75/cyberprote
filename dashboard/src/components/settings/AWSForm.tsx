import type { AWSConfig } from '../../api/settings-types'

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1',
  'sa-east-1', 'ca-central-1', 'me-south-1', 'af-south-1',
]

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

interface AWSFormProps {
  config: AWSConfig
  onChange: (config: AWSConfig) => void
}

export default function AWSForm({ config, onChange }: AWSFormProps) {
  const update = (patch: Partial<AWSConfig>) => onChange({ ...config, ...patch })

  const toggleSeverity = (label: string) => {
    const current = config.severity_labels || []
    const next = current.includes(label)
      ? current.filter((l) => l !== label)
      : [...current, label]
    update({ severity_labels: next })
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-500">
        AWS uses the SDK credential chain — configure via environment variables or instance role.
      </p>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Region</label>
        <select
          value={config.region}
          onChange={(e) => update({ region: e.target.value })}
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        >
          {AWS_REGIONS.map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Poll Interval</label>
          <input
            type="text"
            value={config.poll_interval}
            onChange={(e) => update({ poll_interval: e.target.value })}
            placeholder="5m"
            className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Batch Size</label>
          <input
            type="number"
            value={config.batch_size}
            onChange={(e) => update({ batch_size: parseInt(e.target.value) || 100 })}
            min={1}
            max={100}
            className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Assume Role ARN</label>
        <input
          type="text"
          value={config.assume_role}
          onChange={(e) => update({ assume_role: e.target.value })}
          placeholder="arn:aws:iam::123456789012:role/SecurityHubReader"
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        />
      </div>

      {config.assume_role && (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">External ID</label>
          <input
            type="text"
            value={config.external_id}
            onChange={(e) => update({ external_id: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
          />
        </div>
      )}

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Severity Labels</label>
        <div className="flex flex-wrap gap-2">
          {SEVERITY_OPTIONS.map((s) => (
            <label key={s} className="inline-flex items-center gap-1 text-sm">
              <input
                type="checkbox"
                checked={(config.severity_labels || []).includes(s)}
                onChange={() => toggleSeverity(s)}
                className="rounded border-gray-300"
              />
              {s}
            </label>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Record State</label>
        <select
          value={config.record_state}
          onChange={(e) => update({ record_state: e.target.value })}
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        >
          <option value="">All</option>
          <option value="ACTIVE">ACTIVE</option>
          <option value="ARCHIVED">ARCHIVED</option>
        </select>
      </div>
    </div>
  )
}
