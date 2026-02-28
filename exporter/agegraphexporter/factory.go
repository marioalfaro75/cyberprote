package agegraphexporter

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
)

const (
	typeStr = "agegraph"
)

// NewFactory creates a factory for the AGE graph exporter.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		exporter.WithLogs(createLogsExporter, component.StabilityLevelAlpha),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		DSN:           "postgres://csf:csf-dev-password@localhost:5432/csf?sslmode=disable",
		GraphName:     "security_fabric",
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
	}
}

func createLogsExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Logs, error) {
	eCfg := cfg.(*Config)
	if err := eCfg.Validate(); err != nil {
		return nil, err
	}
	return newAGEExporter(eCfg, set.Logger)
}
