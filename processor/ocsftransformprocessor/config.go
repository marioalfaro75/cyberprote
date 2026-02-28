// Package ocsftransformprocessor implements an OTel Collector processor that
// transforms security findings from various cloud providers into OCSF format.
package ocsftransformprocessor

import "errors"

// Config defines configuration for the OCSF transform processor.
type Config struct {
	// EnrichEPSS enables CVE enrichment using the FIRST EPSS API.
	EnrichEPSS bool `mapstructure:"enrich_epss"`

	// EnrichKEV enables checking CVEs against the CISA Known Exploited Vulnerabilities catalog.
	EnrichKEV bool `mapstructure:"enrich_kev"`

	// CSFExtensions enables CSF-specific extension fields in the output.
	CSFExtensions bool `mapstructure:"csf_extensions"`

	// EPSSAPIEndpoint overrides the default EPSS API endpoint (for testing).
	EPSSAPIEndpoint string `mapstructure:"epss_api_endpoint"`

	// KEVFeedURL overrides the default CISA KEV feed URL (for testing).
	KEVFeedURL string `mapstructure:"kev_feed_url"`
}

// Validate checks the processor configuration.
func (cfg *Config) Validate() error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	return nil
}
