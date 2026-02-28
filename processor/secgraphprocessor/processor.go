package secgraphprocessor

import (
	"context"
	"encoding/json"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// secGraphProcessor enriches log records with graph relationship metadata.
type secGraphProcessor struct {
	cfg          *Config
	logger       *zap.Logger
	nextConsumer consumer.Logs
}

func newSecGraphProcessor(cfg *Config, logger *zap.Logger, next consumer.Logs) (*secGraphProcessor, error) {
	return &secGraphProcessor{cfg: cfg, logger: logger, nextConsumer: next}, nil
}

func (p *secGraphProcessor) Start(_ context.Context, _ component.Host) error { return nil }
func (p *secGraphProcessor) Shutdown(_ context.Context) error                 { return nil }
func (p *secGraphProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

// ConsumeLogs analyzes OCSF findings and adds graph edge metadata as log attributes.
func (p *secGraphProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				p.enrichRecord(lr)
			}
		}
	}
	return p.nextConsumer.ConsumeLogs(ctx, ld)
}

// enrichRecord adds graph metadata attributes to a log record.
func (p *secGraphProcessor) enrichRecord(lr plog.LogRecord) {
	bodyStr := lr.Body().AsString()
	if bodyStr == "" {
		return
	}

	var finding map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &finding); err != nil {
		return
	}

	// Extract resource → identity relationships
	if resources, ok := finding["resources"].([]interface{}); ok {
		for _, r := range resources {
			res, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			resUID, _ := res["uid"].(string)
			resType, _ := res["type"].(string)

			if resUID != "" {
				lr.Attributes().PutStr("csf.graph.resource.uid", resUID)
				lr.Attributes().PutStr("csf.graph.resource.type", resType)
			}

			// Detect public-facing resources
			if p.cfg.DetectPublicFacing && isPublicFacing(res) {
				lr.Attributes().PutBool("csf.graph.is_public_facing", true)
			}

			// Check for identity/owner
			if owner, ok := res["owner"].(map[string]interface{}); ok {
				if ownerUID, ok := owner["uid"].(string); ok {
					lr.Attributes().PutStr("csf.graph.identity.uid", ownerUID)
					if p.cfg.DetectAdminEquivalent && isAdminEquivalent(owner) {
						lr.Attributes().PutBool("csf.graph.is_admin_equivalent", true)
					}
				}
			}
		}
	}

	// Detect toxic combination patterns
	if p.cfg.DetectToxicCombinations {
		patterns := detectToxicPatterns(finding, lr)
		if len(patterns) > 0 {
			lr.Attributes().PutStr("csf.graph.toxic_patterns", strings.Join(patterns, ","))
		}
	}
}

// isPublicFacing heuristically determines if a resource is internet-exposed.
func isPublicFacing(res map[string]interface{}) bool {
	resType, _ := res["type"].(string)
	typeLower := strings.ToLower(resType)

	publicTypes := []string{"loadbalancer", "cloudfront", "apigateway", "publicip"}
	for _, pt := range publicTypes {
		if strings.Contains(typeLower, pt) {
			return true
		}
	}

	if labels, ok := res["labels"].([]interface{}); ok {
		for _, l := range labels {
			if s, ok := l.(string); ok && strings.Contains(strings.ToLower(s), "public") {
				return true
			}
		}
	}
	return false
}

// isAdminEquivalent checks if an identity has admin-equivalent privileges.
func isAdminEquivalent(identity map[string]interface{}) bool {
	identityType, _ := identity["type"].(string)
	name, _ := identity["name"].(string)
	combined := strings.ToLower(identityType + " " + name)

	adminIndicators := []string{"admin", "root", "superuser", "owner", "poweruser"}
	for _, ind := range adminIndicators {
		if strings.Contains(combined, ind) {
			return true
		}
	}
	return false
}

// detectToxicPatterns checks for known toxic combination patterns.
func detectToxicPatterns(finding map[string]interface{}, lr plog.LogRecord) []string {
	var patterns []string

	classUID, _ := finding["class_uid"].(float64)
	sevID, _ := finding["severity_id"].(float64)

	// Pattern: high-severity vulnerability on public-facing resource
	if classUID == 2002 && sevID >= 4 {
		isPublic, _ := lr.Attributes().Get("csf.graph.is_public_facing")
		if isPublic.Bool() {
			patterns = append(patterns, "public_facing_critical_vuln")
		}
	}

	// Pattern: credential exposure with admin identity
	if classUID == 2001 {
		msg, _ := finding["message"].(string)
		if strings.Contains(strings.ToLower(msg), "credential") || strings.Contains(strings.ToLower(msg), "secret") || strings.Contains(strings.ToLower(msg), "key") {
			isAdmin, _ := lr.Attributes().Get("csf.graph.is_admin_equivalent")
			if isAdmin.Bool() {
				patterns = append(patterns, "admin_credential_exposure")
			}
		}
	}

	return patterns
}
