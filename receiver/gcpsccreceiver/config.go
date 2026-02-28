// Package gcpsccreceiver implements an OTel Collector receiver that polls
// Google Cloud Security Command Center (SCC) findings.
package gcpsccreceiver

import (
	"errors"
	"time"
)

// Config defines configuration for the GCP SCC receiver.
type Config struct {
	// OrganizationID is the GCP organization ID.
	OrganizationID string `mapstructure:"organization_id"`

	// ProjectID is the GCP project ID (alternative to organization scope).
	ProjectID string `mapstructure:"project_id"`

	// PollInterval is how often to poll for new findings.
	PollInterval time.Duration `mapstructure:"poll_interval"`

	// CredentialsFile is the path to the GCP service account JSON key.
	CredentialsFile string `mapstructure:"credentials_file"`

	// Sources limits which SCC sources to poll. Empty means all.
	Sources []string `mapstructure:"sources"`
}

// Validate checks the receiver configuration.
func (cfg *Config) Validate() error {
	if cfg.OrganizationID == "" && cfg.ProjectID == "" {
		return errors.New("either organization_id or project_id is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	return nil
}
