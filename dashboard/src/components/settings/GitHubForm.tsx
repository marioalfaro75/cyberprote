import type { GitHubConfig } from '../../api/settings-types'
import SecretField from './SecretField'
import { api } from '../../api/client'

interface GitHubFormProps {
  config: GitHubConfig
  onChange: (config: GitHubConfig) => void
}

export default function GitHubForm({ config, onChange }: GitHubFormProps) {
  const update = (patch: Partial<GitHubConfig>) => onChange({ ...config, ...patch })

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Owner (org or user)</label>
        <input
          type="text"
          value={config.owner}
          onChange={(e) => update({ owner: e.target.value })}
          placeholder="my-org"
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Repositories <span className="text-gray-400 font-normal">(comma-separated, empty = all)</span>
        </label>
        <input
          type="text"
          value={(config.repos || []).join(', ')}
          onChange={(e) =>
            update({ repos: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })
          }
          placeholder="repo1, repo2"
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Authentication Method</label>
        <div className="flex gap-4">
          <label className="inline-flex items-center gap-1 text-sm">
            <input
              type="radio"
              name="github-auth"
              value="pat"
              checked={config.auth_method === 'pat'}
              onChange={() => update({ auth_method: 'pat' })}
            />
            Personal Access Token
          </label>
          <label className="inline-flex items-center gap-1 text-sm">
            <input
              type="radio"
              name="github-auth"
              value="app"
              checked={config.auth_method === 'app'}
              onChange={() => update({ auth_method: 'app' })}
            />
            GitHub App
          </label>
        </div>
      </div>

      {config.auth_method === 'pat' && (
        <SecretField
          label="Token"
          hasValue={config.has_token}
          onSave={async (value) => {
            await api.updateConnectorSecrets('github', 'token', value)
            update({ has_token: true })
          }}
          placeholder="ghp_..."
        />
      )}

      {config.auth_method === 'app' && (
        <>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">App ID</label>
              <input
                type="number"
                value={config.app_id || ''}
                onChange={(e) => update({ app_id: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Installation ID</label>
              <input
                type="number"
                value={config.app_installation_id || ''}
                onChange={(e) => update({ app_installation_id: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
              />
            </div>
          </div>
          <SecretField
            label="App Private Key"
            hasValue={config.has_app_private_key}
            onSave={async (value) => {
              await api.updateConnectorSecrets('github', 'app_private_key', value)
              update({ has_app_private_key: true })
            }}
            placeholder="-----BEGIN RSA PRIVATE KEY-----"
            multiline
          />
        </>
      )}

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
        <label className="block text-sm font-medium text-gray-700 mb-2">Scanning Features</label>
        <div className="flex flex-wrap gap-4">
          <label className="inline-flex items-center gap-1 text-sm">
            <input
              type="checkbox"
              checked={config.enable_code_scanning}
              onChange={(e) => update({ enable_code_scanning: e.target.checked })}
              className="rounded border-gray-300"
            />
            Code Scanning
          </label>
          <label className="inline-flex items-center gap-1 text-sm">
            <input
              type="checkbox"
              checked={config.enable_dependabot}
              onChange={(e) => update({ enable_dependabot: e.target.checked })}
              className="rounded border-gray-300"
            />
            Dependabot
          </label>
          <label className="inline-flex items-center gap-1 text-sm">
            <input
              type="checkbox"
              checked={config.enable_secret_scanning}
              onChange={(e) => update({ enable_secret_scanning: e.target.checked })}
              className="rounded border-gray-300"
            />
            Secret Scanning
          </label>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          API URL <span className="text-gray-400 font-normal">(GitHub Enterprise only)</span>
        </label>
        <input
          type="text"
          value={config.api_url}
          onChange={(e) => update({ api_url: e.target.value })}
          placeholder="https://github.example.com/api/v3"
          className="w-full px-3 py-2 border border-gray-300 rounded text-sm"
        />
      </div>
    </div>
  )
}
