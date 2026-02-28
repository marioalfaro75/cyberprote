import type { GCPConfig } from '../../api/settings-types'
import SecretField from './SecretField'
import { api } from '../../api/client'

interface GCPFormProps {
  config: GCPConfig
  onChange: (config: GCPConfig) => void
}

export default function GCPForm({ config, onChange }: GCPFormProps) {
  const update = (patch: Partial<GCPConfig>) => onChange({ ...config, ...patch })

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Scope</label>
        <div className="flex gap-4">
          <label className="inline-flex items-center gap-1 text-sm">
            <input
              type="radio"
              name="gcp-scope"
              value="organization"
              checked={config.scope_type === 'organization'}
              onChange={() => update({ scope_type: 'organization' })}
            />
            Organization
          </label>
          <label className="inline-flex items-center gap-1 text-sm">
            <input
              type="radio"
              name="gcp-scope"
              value="project"
              checked={config.scope_type === 'project'}
              onChange={() => update({ scope_type: 'project' })}
            />
            Project
          </label>
        </div>
      </div>

      {config.scope_type === 'organization' ? (
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Organization ID</label>
          <input
            type="text"
            value={config.organization_id}
            onChange={(e) => update({ organization_id: e.target.value })}
            placeholder="123456789"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded text-sm bg-white dark:bg-gray-900 dark:text-gray-100"
          />
        </div>
      ) : (
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Project ID</label>
          <input
            type="text"
            value={config.project_id}
            onChange={(e) => update({ project_id: e.target.value })}
            placeholder="my-gcp-project"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded text-sm bg-white dark:bg-gray-900 dark:text-gray-100"
          />
        </div>
      )}

      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Poll Interval</label>
        <input
          type="text"
          value={config.poll_interval}
          onChange={(e) => update({ poll_interval: e.target.value })}
          placeholder="5m"
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded text-sm bg-white dark:bg-gray-900 dark:text-gray-100"
        />
      </div>

      <SecretField
        label="Credentials (Service Account JSON)"
        hasValue={config.has_credentials}
        onSave={async (value) => {
          await api.updateConnectorSecrets('gcp', 'credentials', value)
          update({ has_credentials: true })
        }}
        placeholder='{"type": "service_account", ...}'
        multiline
      />

      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Sources <span className="text-gray-400 dark:text-gray-500 font-normal">(comma-separated, empty = all)</span>
        </label>
        <input
          type="text"
          value={(config.sources || []).join(', ')}
          onChange={(e) =>
            update({ sources: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })
          }
          placeholder="source1, source2"
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded text-sm bg-white dark:bg-gray-900 dark:text-gray-100"
        />
      </div>
    </div>
  )
}
