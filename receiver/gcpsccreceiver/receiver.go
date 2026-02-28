package gcpsccreceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.uber.org/zap"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// sccReceiver polls GCP Security Command Center.
type sccReceiver struct {
	cfg          *Config
	logger       *zap.Logger
	nextConsumer consumer.Logs
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	findingsTotal atomic.Int64
}

func newSCCReceiver(cfg *Config, logger *zap.Logger, next consumer.Logs) (*sccReceiver, error) {
	return &sccReceiver{cfg: cfg, logger: logger, nextConsumer: next}, nil
}

func (r *sccReceiver) Start(ctx context.Context, host component.Host) error {
	pollCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go r.poll(pollCtx)
	r.logger.Info("GCP SCC receiver started")
	return nil
}

func (r *sccReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	return nil
}

func (r *sccReceiver) poll(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// GCP SCC API polling would go here
			r.logger.Debug("GCP SCC poll cycle (stub)")
		}
	}
}

// MapSCCFindingToOCSF maps a GCP SCC finding to OCSF format.
// SCC categories → OCSF class mapping:
//   VULNERABILITY → 2002, MISCONFIGURATION → 2003, THREAT → 2004
func MapSCCFindingToOCSF(finding map[string]interface{}) ([]byte, error) {
	category, _ := finding["category"].(string)
	classUID := ocsf.ClassSecurityFinding

	switch category {
	case "VULNERABILITY":
		classUID = ocsf.ClassVulnerabilityFind
	case "MISCONFIGURATION":
		classUID = ocsf.ClassComplianceFinding
	case "THREAT":
		classUID = ocsf.ClassDetectionFinding
	}

	severity, _ := finding["severity"].(string)
	sevID := mapGCPSeverity(severity)

	name, _ := finding["name"].(string)
	desc, _ := finding["description"].(string)
	resourceName, _ := finding["resourceName"].(string)

	f := ocsf.SecurityFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    classUID,
		SeverityID:  sevID,
		Severity:    severity,
		StatusID:    ocsf.StatusNew,
		Status:      "New",
		Message:     desc,
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       "Security Command Center",
				VendorName: "Google Cloud",
			},
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:   name,
			Title: fmt.Sprintf("%s: %s", category, desc),
		},
		Resources: []ocsf.Resource{
			{UID: resourceName, Type: "GcpResource", Cloud: &ocsf.Cloud{Provider: "gcp"}},
		},
		Cloud: &ocsf.Cloud{Provider: "gcp"},
	}

	return json.Marshal(&f)
}

func mapGCPSeverity(severity string) int32 {
	switch severity {
	case "CRITICAL":
		return ocsf.SeverityCritical
	case "HIGH":
		return ocsf.SeverityHigh
	case "MEDIUM":
		return ocsf.SeverityMedium
	case "LOW":
		return ocsf.SeverityLow
	default:
		return ocsf.SeverityUnknown
	}
}
