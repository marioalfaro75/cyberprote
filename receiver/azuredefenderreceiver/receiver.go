package azuredefenderreceiver

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.uber.org/zap"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// azureReceiver polls Azure Defender for Cloud alerts.
type azureReceiver struct {
	cfg          *Config
	logger       *zap.Logger
	nextConsumer consumer.Logs
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	findingsTotal atomic.Int64
}

func newAzureReceiver(cfg *Config, logger *zap.Logger, next consumer.Logs) (*azureReceiver, error) {
	return &azureReceiver{cfg: cfg, logger: logger, nextConsumer: next}, nil
}

func (r *azureReceiver) Start(ctx context.Context, host component.Host) error {
	pollCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go r.poll(pollCtx)
	r.logger.Info("Azure Defender receiver started")
	return nil
}

func (r *azureReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	return nil
}

func (r *azureReceiver) poll(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.logger.Debug("Azure Defender poll cycle (stub)")
		}
	}
}

// MapAzureAlertToOCSF maps an Azure Defender alert to OCSF format.
func MapAzureAlertToOCSF(alert map[string]interface{}) ([]byte, error) {
	alertType, _ := alert["alertType"].(string)
	severity, _ := alert["severity"].(string)
	displayName, _ := alert["alertDisplayName"].(string)
	description, _ := alert["description"].(string)
	resourceID, _ := alert["compromisedEntity"].(string)

	classUID := ocsf.ClassSecurityFinding
	sevID := mapAzureSeverity(severity)

	f := ocsf.SecurityFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    classUID,
		SeverityID:  sevID,
		Severity:    severity,
		StatusID:    ocsf.StatusNew,
		Status:      "New",
		Message:     description,
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       "Microsoft Defender for Cloud",
				VendorName: "Microsoft",
			},
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:   alertType,
			Title: displayName,
		},
		Resources: []ocsf.Resource{
			{UID: resourceID, Type: "AzureResource", Cloud: &ocsf.Cloud{Provider: "azure"}},
		},
		Cloud: &ocsf.Cloud{Provider: "azure"},
	}

	return json.Marshal(&f)
}

func mapAzureSeverity(severity string) int32 {
	switch severity {
	case "High":
		return ocsf.SeverityHigh
	case "Medium":
		return ocsf.SeverityMedium
	case "Low":
		return ocsf.SeverityLow
	case "Informational":
		return ocsf.SeverityInformational
	default:
		return ocsf.SeverityUnknown
	}
}
