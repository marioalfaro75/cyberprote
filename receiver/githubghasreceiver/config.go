// Package githubghasreceiver implements an OTel Collector receiver that polls
// GitHub Advanced Security (GHAS) alerts and emits them as OCSF-formatted logs.
package githubghasreceiver

import (
	"errors"
	"time"
)

// Config defines configuration for the GitHub GHAS receiver.
type Config struct {
	// Owner is the GitHub organization or user that owns the repositories.
	Owner string `mapstructure:"owner"`

	// Repos is a list of repository names to poll. Empty means all repos in the org.
	Repos []string `mapstructure:"repos"`

	// Token is a GitHub personal access token (PAT) or GitHub App token.
	Token string `mapstructure:"token"`

	// AppID is the GitHub App ID (used with AppPrivateKey for App-based auth).
	AppID int64 `mapstructure:"app_id"`

	// AppInstallationID is the GitHub App installation ID.
	AppInstallationID int64 `mapstructure:"app_installation_id"`

	// AppPrivateKey is the path to the GitHub App private key PEM file.
	AppPrivateKey string `mapstructure:"app_private_key"`

	// PollInterval is how often to poll for new alerts.
	PollInterval time.Duration `mapstructure:"poll_interval"`

	// EnableCodeScanning enables polling CodeQL / code scanning alerts.
	EnableCodeScanning bool `mapstructure:"enable_code_scanning"`

	// EnableDependabot enables polling Dependabot alerts.
	EnableDependabot bool `mapstructure:"enable_dependabot"`

	// EnableSecretScanning enables polling secret scanning alerts.
	EnableSecretScanning bool `mapstructure:"enable_secret_scanning"`

	// APIURL overrides the GitHub API URL (for GitHub Enterprise Server).
	APIURL string `mapstructure:"api_url"`
}

// Validate checks the receiver configuration.
func (cfg *Config) Validate() error {
	if cfg.Owner == "" {
		return errors.New("owner is required")
	}
	if cfg.Token == "" && cfg.AppID == 0 {
		return errors.New("either token or app_id + app_private_key is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	if !cfg.EnableCodeScanning && !cfg.EnableDependabot && !cfg.EnableSecretScanning {
		cfg.EnableCodeScanning = true
		cfg.EnableDependabot = true
		cfg.EnableSecretScanning = true
	}
	return nil
}
