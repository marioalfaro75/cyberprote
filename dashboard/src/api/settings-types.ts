export interface AWSConfig {
  enabled: boolean
  region: string
  poll_interval: string
  batch_size: number
  assume_role: string
  external_id: string
  severity_labels: string[]
  record_state: string
}

export interface GitHubConfig {
  enabled: boolean
  owner: string
  repos: string[]
  auth_method: 'pat' | 'app'
  app_id: number
  app_installation_id: number
  poll_interval: string
  enable_code_scanning: boolean
  enable_dependabot: boolean
  enable_secret_scanning: boolean
  api_url: string
  has_token: boolean
  has_app_private_key: boolean
}

export interface GCPConfig {
  enabled: boolean
  scope_type: 'organization' | 'project'
  organization_id: string
  project_id: string
  poll_interval: string
  sources: string[]
  has_credentials: boolean
}

export interface AzureConfig {
  enabled: boolean
  subscription_id: string
  tenant_id: string
  client_id: string
  poll_interval: string
  has_client_secret: boolean
}

export interface ProviderSettings {
  aws: AWSConfig
  github: GitHubConfig
  gcp: GCPConfig
  azure: AzureConfig
}

export interface TestConnectionResult {
  success: boolean
  message?: string
  error?: string
}

export interface SaveResult {
  settings: ProviderSettings
  restart_required: boolean
}

export interface ApplyResult {
  applied: boolean
  config_path: string
  restart_required: boolean
}

export const DEFAULT_SETTINGS: ProviderSettings = {
  aws: {
    enabled: false,
    region: 'us-east-1',
    poll_interval: '5m',
    batch_size: 100,
    assume_role: '',
    external_id: '',
    severity_labels: [],
    record_state: 'ACTIVE',
  },
  github: {
    enabled: false,
    owner: '',
    repos: [],
    auth_method: 'pat',
    app_id: 0,
    app_installation_id: 0,
    poll_interval: '5m',
    enable_code_scanning: true,
    enable_dependabot: true,
    enable_secret_scanning: true,
    api_url: '',
    has_token: false,
    has_app_private_key: false,
  },
  gcp: {
    enabled: false,
    scope_type: 'organization',
    organization_id: '',
    project_id: '',
    poll_interval: '5m',
    sources: [],
    has_credentials: false,
  },
  azure: {
    enabled: false,
    subscription_id: '',
    tenant_id: '',
    client_id: '',
    poll_interval: '5m',
    has_client_secret: false,
  },
}
