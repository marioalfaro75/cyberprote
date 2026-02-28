package agegraphexporter

import (
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "empty DSN",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: Config{
				DSN:       "postgres://user:pass@localhost:5432/db",
				GraphName: "test_graph",
				BatchSize: 50,
			},
			wantErr: false,
		},
		{
			name: "defaults applied",
			cfg: Config{
				DSN: "postgres://user:pass@localhost:5432/db",
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{DSN: "postgres://localhost/test"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.GraphName != "security_fabric" {
		t.Errorf("default graph_name = %s, want security_fabric", cfg.GraphName)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("default batch_size = %d, want 100", cfg.BatchSize)
	}
	if cfg.FlushInterval != 10*time.Second {
		t.Errorf("default flush_interval = %v, want 10s", cfg.FlushInterval)
	}
}

func TestExtractBodyJSON(t *testing.T) {
	valid := `{"class_uid": 2001, "activity_id": 1}`
	data, err := extractBodyJSON(valid)
	if err != nil {
		t.Fatalf("extractBodyJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}

	invalid := "not json"
	_, err = extractBodyJSON(invalid)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestNewAGEExporter(t *testing.T) {
	cfg := &Config{
		DSN:       "postgres://localhost/test",
		GraphName: "test",
		BatchSize: 10,
	}
	exp, err := newAGEExporter(cfg, nil)
	if err != nil {
		t.Fatalf("newAGEExporter: %v", err)
	}
	if exp == nil {
		t.Fatal("expected non-nil exporter")
	}
}
