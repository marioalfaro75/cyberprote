import { useEffect, useState, useCallback } from 'react'
import type { ProviderSettings } from '../api/settings-types'
import { DEFAULT_SETTINGS } from '../api/settings-types'
import { api } from '../api/client'
import ProviderCard from '../components/settings/ProviderCard'
import AWSForm from '../components/settings/AWSForm'
import GitHubForm from '../components/settings/GitHubForm'
import GCPForm from '../components/settings/GCPForm'
import AzureForm from '../components/settings/AzureForm'

export default function Settings() {
  const [settings, setSettings] = useState<ProviderSettings>(DEFAULT_SETTINGS)
  const [savedSnapshot, setSavedSnapshot] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [applying, setApplying] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [banner, setBanner] = useState<string | null>(null)

  const isDirty = JSON.stringify(settings) !== savedSnapshot

  const loadSettings = useCallback(async () => {
    try {
      const data = await api.getConnectorSettings()
      setSettings(data)
      setSavedSnapshot(JSON.stringify(data))
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadSettings()
  }, [loadSettings])

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      const result = await api.updateConnectorSettings(settings)
      setSettings(result.settings)
      setSavedSnapshot(JSON.stringify(result.settings))
      if (result.restart_required) {
        setBanner('Configuration saved. Restart the collector to apply changes.')
      }
    } catch (err) {
      setError(String(err))
    } finally {
      setSaving(false)
    }
  }

  const handleApply = async () => {
    setApplying(true)
    setError(null)
    try {
      const result = await api.applySettings()
      if (result.restart_required) {
        setBanner(`Collector config written to ${result.config_path}. Restart the collector to apply changes.`)
      }
    } catch (err) {
      setError(String(err))
    } finally {
      setApplying(false)
    }
  }

  if (loading) {
    return <div className="text-gray-500 dark:text-gray-400">Loading settings...</div>
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Settings</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Configure cloud provider connections</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleSave}
            disabled={saving || !isDirty}
            className={`px-4 py-2 text-sm font-medium rounded ${
              isDirty
                ? 'bg-blue-600 text-white hover:bg-blue-700'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 cursor-not-allowed'
            } disabled:opacity-50`}
          >
            {saving ? 'Saving...' : 'Save'}
          </button>
          <button
            onClick={handleApply}
            disabled={applying || isDirty}
            className="px-4 py-2 text-sm font-medium bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
          >
            {applying ? 'Applying...' : 'Apply Changes'}
          </button>
        </div>
      </div>

      {banner && (
        <div className="mb-6 px-4 py-3 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800 rounded-lg text-sm text-yellow-800 dark:text-yellow-200 flex items-center justify-between">
          <span>{banner}</span>
          <button onClick={() => setBanner(null)} className="text-yellow-600 hover:text-yellow-800 ml-4">
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="mb-6 px-4 py-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ProviderCard
          name="AWS Security Hub"
          provider="aws"
          color="#ff9900"
          enabled={settings.aws.enabled}
          onToggle={(enabled) => setSettings({ ...settings, aws: { ...settings.aws, enabled } })}
        >
          <AWSForm
            config={settings.aws}
            onChange={(aws) => setSettings({ ...settings, aws })}
          />
        </ProviderCard>

        <ProviderCard
          name="GitHub Advanced Security"
          provider="github"
          color="#333333"
          enabled={settings.github.enabled}
          onToggle={(enabled) => setSettings({ ...settings, github: { ...settings.github, enabled } })}
        >
          <GitHubForm
            config={settings.github}
            onChange={(github) => setSettings({ ...settings, github })}
          />
        </ProviderCard>

        <ProviderCard
          name="GCP Security Command Center"
          provider="gcp"
          color="#4285f4"
          enabled={settings.gcp.enabled}
          onToggle={(enabled) => setSettings({ ...settings, gcp: { ...settings.gcp, enabled } })}
        >
          <GCPForm
            config={settings.gcp}
            onChange={(gcp) => setSettings({ ...settings, gcp })}
          />
        </ProviderCard>

        <ProviderCard
          name="Azure Defender for Cloud"
          provider="azure"
          color="#0078d4"
          enabled={settings.azure.enabled}
          onToggle={(enabled) => setSettings({ ...settings, azure: { ...settings.azure, enabled } })}
        >
          <AzureForm
            config={settings.azure}
            onChange={(azure) => setSettings({ ...settings, azure })}
          />
        </ProviderCard>
      </div>
    </div>
  )
}
