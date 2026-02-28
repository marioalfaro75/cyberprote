package githubghasreceiver

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

const typeStr = "githubghas"

// NewFactory creates a factory for the GitHub GHAS receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, component.StabilityLevelAlpha),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		PollInterval:         5 * time.Minute,
		EnableCodeScanning:   true,
		EnableDependabot:     true,
		EnableSecretScanning: true,
	}
}

func createLogsReceiver(
	ctx context.Context,
	set receiver.Settings,
	cfg component.Config,
	nextConsumer consumer.Logs,
) (receiver.Logs, error) {
	rCfg := cfg.(*Config)
	if err := rCfg.Validate(); err != nil {
		return nil, err
	}
	return newGHASReceiver(rCfg, set.Logger, nextConsumer)
}
