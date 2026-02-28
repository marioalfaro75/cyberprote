import type { AzureConfig } from '../../api/settings-types'
import SecretField from './SecretField'
import { api } from '../../api/client'

interface AzureFormProps {
  config: AzureConfig
  onChange: (config: AzureConfig) => void
}

export default function AzureForm({ config, onChange }: AzureFormProps) {
  const update = (patch: Partial<AzureConfig>) => onChange({ ...config, ...patch })

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Subscription ID</label>
        <input
          type="text"
          value={config.subscription_id}
          onChange={(e) => update({ subscription_id: e.target.value })}
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Tenant ID</label>
        <input
          type="text"
          value={config.tenant_id}
          onChange={(e) => update({ tenant_id: e.target.value })}
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Client ID</label>
        <input
          type="text"
          value={config.client_id}
          onChange={(e) => update({ client_id: e.target.value })}
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        />
      </div>

      <SecretField
        label="Client Secret"
        hasValue={config.has_client_secret}
        onSave={async (value) => {
          await api.updateConnectorSecrets('azure', 'client_secret', value)
          update({ has_client_secret: true })
        }}
        placeholder="Client secret value"
      />

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
    </div>
  )
}
