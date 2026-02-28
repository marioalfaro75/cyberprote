// Package azuredefenderreceiver implements an OTel Collector receiver that polls
// Microsoft Defender for Cloud (Azure Defender) alerts.
package azuredefenderreceiver

import (
	"errors"
	"time"
)

// Config defines configuration for the Azure Defender receiver.
type Config struct {
	// SubscriptionID is the Azure subscription ID.
	SubscriptionID string `mapstructure:"subscription_id"`

	// TenantID is the Azure AD tenant ID.
	TenantID string `mapstructure:"tenant_id"`

	// ClientID is the Azure AD application (client) ID.
	ClientID string `mapstructure:"client_id"`

	// ClientSecret is the Azure AD application secret.
	ClientSecret string `mapstructure:"client_secret"`

	// PollInterval is how often to poll for new alerts.
	PollInterval time.Duration `mapstructure:"poll_interval"`
}

// Validate checks the receiver configuration.
func (cfg *Config) Validate() error {
	if cfg.SubscriptionID == "" {
		return errors.New("subscription_id is required")
	}
	if cfg.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	return nil
}
