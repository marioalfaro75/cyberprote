package agegraphexporter

import (
	"context"
	"fmt"
	"sync/atomic"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/cloud-security-fabric/csf/internal/graph"
)

// ageExporter implements exporter.Logs for writing OCSF findings to Apache AGE.
type ageExporter struct {
	cfg    *Config
	logger *zap.Logger
	gs     *graph.GraphService

	// Prometheus-style counters (read via metrics endpoint)
	nodesUpserted atomic.Int64
	edgesCreated  atomic.Int64
	errorsTotal   atomic.Int64
}

func newAGEExporter(cfg *Config, logger *zap.Logger) (*ageExporter, error) {
	return &ageExporter{
		cfg:    cfg,
		logger: logger,
	}, nil
}

// Start initializes the connection to PostgreSQL/AGE.
func (e *ageExporter) Start(ctx context.Context, host component.Host) error {
	gs, err := graph.NewGraphService(e.cfg.DSN, e.cfg.GraphName)
	if err != nil {
		return fmt.Errorf("failed to connect to AGE: %w", err)
	}
	e.gs = gs
	e.logger.Info("AGE graph exporter started",
		zap.String("graph", e.cfg.GraphName),
		zap.Int("batch_size", e.cfg.BatchSize),
	)
	return nil
}

// Shutdown closes the database connection.
func (e *ageExporter) Shutdown(ctx context.Context) error {
	if e.gs != nil {
		return e.gs.Close()
	}
	return nil
}

// ConsumeLogs processes incoming log records containing OCSF finding JSON bodies.
func (e *ageExporter) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				if err := e.processLogRecord(ctx, lr); err != nil {
					e.errorsTotal.Add(1)
					e.logger.Warn("failed to process log record",
						zap.Error(err),
					)
				}
			}
		}
	}
	return nil
}

// processLogRecord extracts the OCSF JSON from a log record and writes it to the graph.
func (e *ageExporter) processLogRecord(ctx context.Context, lr plog.LogRecord) error {
	bodyStr := lr.Body().AsString()
	if bodyStr == "" {
		return nil
	}

	body, err := extractBodyJSON(bodyStr)
	if err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}

	if err := processOCSFFinding(ctx, e.gs, body); err != nil {
		return fmt.Errorf("process OCSF finding: %w", err)
	}

	e.nodesUpserted.Add(1)
	return nil
}

// Capabilities returns the exporter capabilities.
func (e *ageExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

