package ocsftransformprocessor

import (
	"context"
	"encoding/json"
	"sync/atomic"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// ocsfProcessor transforms raw security findings into OCSF format.
type ocsfProcessor struct {
	cfg          *Config
	logger       *zap.Logger
	nextConsumer consumer.Logs
	epss         *EPSSClient
	kev          *KEVClient

	transformedTotal atomic.Int64
	validationErrors atomic.Int64
}

func newOCSFProcessor(cfg *Config, logger *zap.Logger, nextConsumer consumer.Logs) (*ocsfProcessor, error) {
	p := &ocsfProcessor{
		cfg:          cfg,
		logger:       logger,
		nextConsumer: nextConsumer,
	}

	if cfg.EnrichEPSS {
		endpoint := "https://api.first.org/data/v1/epss"
		if cfg.EPSSAPIEndpoint != "" {
			endpoint = cfg.EPSSAPIEndpoint
		}
		p.epss = NewEPSSClient(endpoint)
	}

	if cfg.EnrichKEV {
		feedURL := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
		if cfg.KEVFeedURL != "" {
			feedURL = cfg.KEVFeedURL
		}
		p.kev = NewKEVClient(feedURL)
	}

	return p, nil
}

// Start is called on processor start.
func (p *ocsfProcessor) Start(_ context.Context, _ component.Host) error {
	return nil
}

// Shutdown is called on processor shutdown.
func (p *ocsfProcessor) Shutdown(_ context.Context) error {
	return nil
}

// Capabilities returns the processor capabilities.
func (p *ocsfProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

// ConsumeLogs transforms incoming log records and passes them to the next consumer.
func (p *ocsfProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		platform := detectPlatform(rl)

		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				if err := p.transformRecord(ctx, lr, platform); err != nil {
					p.validationErrors.Add(1)
					p.logger.Debug("failed to transform log record",
						zap.Error(err),
						zap.String("platform", platform),
					)
				} else {
					p.transformedTotal.Add(1)
				}
			}
		}
	}
	return p.nextConsumer.ConsumeLogs(ctx, ld)
}

// detectPlatform reads the source platform from OTel resource attributes.
func detectPlatform(rl plog.ResourceLogs) string {
	attrs := rl.Resource().Attributes()
	if v, ok := attrs.Get("csf.source.platform"); ok {
		return v.AsString()
	}
	if v, ok := attrs.Get("cloud.provider"); ok {
		return v.AsString()
	}
	return "unknown"
}

// transformRecord transforms a single log record. If the body is already OCSF,
// it validates and enriches. Otherwise it detects the source format and maps.
func (p *ocsfProcessor) transformRecord(ctx context.Context, lr plog.LogRecord, platform string) error {
	bodyStr := lr.Body().AsString()
	if bodyStr == "" {
		return nil
	}

	// Check if already OCSF
	var envelope struct {
		ClassUID int32 `json:"class_uid"`
	}
	if err := json.Unmarshal([]byte(bodyStr), &envelope); err != nil {
		return err
	}

	if envelope.ClassUID > 0 {
		// Already OCSF — validate and enrich
		return p.validateAndEnrich(ctx, lr, bodyStr)
	}

	// Not yet OCSF — body should be transformed by the receiver-specific mapper
	return nil
}

// validateAndEnrich validates an OCSF finding and optionally enriches it with EPSS/KEV data.
func (p *ocsfProcessor) validateAndEnrich(ctx context.Context, lr plog.LogRecord, bodyStr string) error {
	finding, err := ocsf.ParseFinding([]byte(bodyStr))
	if err != nil {
		return err
	}

	if err := ocsf.Validate(finding); err != nil {
		p.validationErrors.Add(1)
		return err
	}

	modified := false

	// Enrich vulnerability findings with EPSS/KEV data
	if vf, ok := finding.(*ocsf.VulnerabilityFinding); ok {
		for i := range vf.Vulnerabilities {
			vuln := &vf.Vulnerabilities[i]
			if vuln.CVE == nil || vuln.CVE.UID == "" {
				continue
			}

			if p.epss != nil {
				score, err := p.epss.GetScore(ctx, vuln.CVE.UID)
				if err == nil && score > 0 {
					vuln.CVE.EPSSScore = &score
					modified = true
				}
			}

			if p.kev != nil {
				exploited, err := p.kev.IsKnownExploited(ctx, vuln.CVE.UID)
				if err == nil {
					vuln.CVE.IsExploited = &exploited
					modified = true
				}
			}
		}
	}

	if modified {
		enriched, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		lr.Body().SetStr(string(enriched))
	}

	return nil
}
