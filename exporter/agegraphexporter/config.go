// Package agegraphexporter implements an OpenTelemetry Collector exporter
// that writes OCSF security findings to an Apache AGE graph database.
package agegraphexporter

import (
	"errors"
	"time"
)

// Config defines configuration for the AGE graph exporter.
type Config struct {
	// DSN is the PostgreSQL connection string (with AGE extension).
	DSN string `mapstructure:"dsn"`

	// GraphName is the Apache AGE graph name (default: "security_fabric").
	GraphName string `mapstructure:"graph_name"`

	// BatchSize controls how many findings to batch before flushing to the graph.
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the maximum time to wait before flushing a partial batch.
	FlushInterval time.Duration `mapstructure:"flush_interval"`
}

// Validate checks the exporter configuration.
func (cfg *Config) Validate() error {
	if cfg.DSN == "" {
		return errors.New("dsn is required")
	}
	if cfg.GraphName == "" {
		cfg.GraphName = "security_fabric"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	return nil
}
