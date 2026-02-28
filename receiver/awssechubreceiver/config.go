// Package awssechubreceiver implements an OTel Collector receiver that polls
// AWS Security Hub for security findings and emits them as OCSF-formatted logs.
package awssechubreceiver

import (
	"errors"
	"time"
)

// Config defines configuration for the AWS Security Hub receiver.
type Config struct {
	// Region is the AWS region to poll Security Hub from.
	Region string `mapstructure:"region"`

	// PollInterval is how often to poll for new findings.
	PollInterval time.Duration `mapstructure:"poll_interval"`

	// BatchSize is the maximum number of findings per GetFindings call.
	BatchSize int32 `mapstructure:"batch_size"`

	// AssumeRole is an optional IAM role ARN to assume for cross-account access.
	AssumeRole string `mapstructure:"assume_role"`

	// ExternalID is an optional external ID for the AssumeRole call.
	ExternalID string `mapstructure:"external_id"`

	// Filters allows limiting which findings are retrieved.
	Filters *FindingFilters `mapstructure:"filters"`
}

// FindingFilters defines optional filters for Security Hub findings.
type FindingFilters struct {
	// ProductArns limits findings to specific product ARNs.
	ProductArns []string `mapstructure:"product_arns"`

	// SeverityLabels limits findings to specific severity labels (CRITICAL, HIGH, etc.).
	SeverityLabels []string `mapstructure:"severity_labels"`

	// RecordState limits to ACTIVE or ARCHIVED.
	RecordState string `mapstructure:"record_state"`
}

// Validate checks the receiver configuration.
func (cfg *Config) Validate() error {
	if cfg.Region == "" {
		return errors.New("region is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	if cfg.BatchSize <= 0 || cfg.BatchSize > 100 {
		cfg.BatchSize = 100
	}
	return nil
}
