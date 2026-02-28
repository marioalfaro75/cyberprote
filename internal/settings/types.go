// Package settings manages cloud provider connector configurations
// for the CSF dashboard, storing non-secret config in JSON and
// secrets in a .env file with restricted permissions.
package settings

// ProviderSettings holds configuration for all cloud provider connectors.
type ProviderSettings struct {
	AWS    AWSConfig    `json:"aws"`
	GitHub GitHubConfig `json:"github"`
	GCP    GCPConfig    `json:"gcp"`
	Azure  AzureConfig  `json:"azure"`
}

// AWSConfig holds AWS Security Hub receiver configuration.
// AWS uses the SDK credential chain — no secret input fields are needed.
type AWSConfig struct {
	Enabled        bool     `json:"enabled"`
	Region         string   `json:"region"`
	PollInterval   string   `json:"poll_interval"`
	BatchSize      int32    `json:"batch_size"`
	AssumeRole     string   `json:"assume_role,omitempty"`
	ExternalID     string   `json:"external_id,omitempty"`
	SeverityLabels []string `json:"severity_labels,omitempty"`
	RecordState    string   `json:"record_state,omitempty"`
}

// GitHubConfig holds GitHub GHAS receiver configuration.
type GitHubConfig struct {
	Enabled              bool   `json:"enabled"`
	Owner                string `json:"owner"`
	Repos                []string `json:"repos,omitempty"`
	AuthMethod           string `json:"auth_method"` // "pat" or "app"
	AppID                int64  `json:"app_id,omitempty"`
	AppInstallationID    int64  `json:"app_installation_id,omitempty"`
	PollInterval         string `json:"poll_interval"`
	EnableCodeScanning   bool   `json:"enable_code_scanning"`
	EnableDependabot     bool   `json:"enable_dependabot"`
	EnableSecretScanning bool   `json:"enable_secret_scanning"`
	APIURL               string `json:"api_url,omitempty"`

	// Read-only flags indicating whether secrets are configured.
	HasToken         bool `json:"has_token"`
	HasAppPrivateKey bool `json:"has_app_private_key"`
}

// GCPConfig holds GCP Security Command Center receiver configuration.
type GCPConfig struct {
	Enabled        bool     `json:"enabled"`
	ScopeType      string   `json:"scope_type"` // "organization" or "project"
	OrganizationID string   `json:"organization_id,omitempty"`
	ProjectID      string   `json:"project_id,omitempty"`
	PollInterval   string   `json:"poll_interval"`
	Sources        []string `json:"sources,omitempty"`

	// Read-only flag indicating whether credentials are configured.
	HasCredentials bool `json:"has_credentials"`
}

// AzureConfig holds Azure Defender receiver configuration.
type AzureConfig struct {
	Enabled        bool   `json:"enabled"`
	SubscriptionID string `json:"subscription_id"`
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id,omitempty"`
	PollInterval   string `json:"poll_interval"`

	// Read-only flag indicating whether the client secret is configured.
	HasClientSecret bool `json:"has_client_secret"`
}

// DefaultSettings returns a ProviderSettings with sensible defaults.
func DefaultSettings() *ProviderSettings {
	return &ProviderSettings{
		AWS: AWSConfig{
			Region:       "us-east-1",
			PollInterval: "5m",
			BatchSize:    100,
			RecordState:  "ACTIVE",
		},
		GitHub: GitHubConfig{
			AuthMethod:           "pat",
			PollInterval:         "5m",
			EnableCodeScanning:   true,
			EnableDependabot:     true,
			EnableSecretScanning: true,
		},
		GCP: GCPConfig{
			ScopeType:    "organization",
			PollInterval: "5m",
		},
		Azure: AzureConfig{
			PollInterval: "5m",
		},
	}
}

// Secret environment variable names used in .csf-secrets.env and
// referenced as ${VAR} in the generated collector-config.yaml.
const (
	SecretGitHubToken         = "CSF_GITHUB_TOKEN"
	SecretGitHubAppPrivateKey = "CSF_GITHUB_APP_PRIVATE_KEY"
	SecretGCPCredentials      = "CSF_GCP_CREDENTIALS"
	SecretAzureClientSecret   = "CSF_AZURE_CLIENT_SECRET"
)
