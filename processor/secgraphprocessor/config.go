// Package secgraphprocessor implements an OTel processor that extracts
// security graph relationships from OCSF findings.
package secgraphprocessor

// Config defines configuration for the security graph builder processor.
type Config struct {
	// DetectPublicFacing enables detection of public-facing resources.
	DetectPublicFacing bool `mapstructure:"detect_public_facing"`

	// DetectAdminEquivalent enables detection of admin-equivalent identities.
	DetectAdminEquivalent bool `mapstructure:"detect_admin_equivalent"`

	// DetectToxicCombinations enables pattern-matching for toxic combinations.
	DetectToxicCombinations bool `mapstructure:"detect_toxic_combinations"`
}

// Validate checks the processor configuration.
func (cfg *Config) Validate() error {
	return nil
}
