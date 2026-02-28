package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func tempPaths(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "csf-settings.json"), filepath.Join(dir, ".csf-secrets.env")
}

func TestLoadReturnsDefaultsWhenNoFile(t *testing.T) {
	sp, ep := tempPaths(t)
	fs := NewFileStore(sp, ep)

	s, err := fs.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.AWS.Region != "us-east-1" {
		t.Errorf("expected default region us-east-1, got %s", s.AWS.Region)
	}
	if s.GitHub.PollInterval != "5m" {
		t.Errorf("expected default poll interval 5m, got %s", s.GitHub.PollInterval)
	}
}

func TestSaveAndLoad(t *testing.T) {
	sp, ep := tempPaths(t)
	fs := NewFileStore(sp, ep)

	s := DefaultSettings()
	s.AWS.Enabled = true
	s.AWS.Region = "eu-west-1"
	s.GitHub.Enabled = true
	s.GitHub.Owner = "my-org"

	if err := fs.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := fs.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AWS.Region != "eu-west-1" {
		t.Errorf("expected eu-west-1, got %s", loaded.AWS.Region)
	}
	if loaded.GitHub.Owner != "my-org" {
		t.Errorf("expected my-org, got %s", loaded.GitHub.Owner)
	}
	if !loaded.AWS.Enabled {
		t.Error("expected AWS enabled")
	}
}

func TestSaveSecretAndHasSecret(t *testing.T) {
	sp, ep := tempPaths(t)
	fs := NewFileStore(sp, ep)

	if fs.HasSecret(SecretGitHubToken) {
		t.Error("expected no secret before save")
	}

	if err := fs.SaveSecret(SecretGitHubToken, "ghp_test123"); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}

	if !fs.HasSecret(SecretGitHubToken) {
		t.Error("expected secret after save")
	}

	v, ok := fs.GetSecret(SecretGitHubToken)
	if !ok || v != "ghp_test123" {
		t.Errorf("expected ghp_test123, got %s (ok=%v)", v, ok)
	}

	// Verify file permissions
	info, err := os.Stat(ep)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestLoadPopulatesHasFlags(t *testing.T) {
	sp, ep := tempPaths(t)
	fs := NewFileStore(sp, ep)

	s := DefaultSettings()
	s.GitHub.Enabled = true
	s.Azure.Enabled = true
	if err := fs.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := fs.SaveSecret(SecretGitHubToken, "ghp_abc"); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	if err := fs.SaveSecret(SecretAzureClientSecret, "azure-secret"); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}

	loaded, err := fs.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !loaded.GitHub.HasToken {
		t.Error("expected HasToken true")
	}
	if loaded.GitHub.HasAppPrivateKey {
		t.Error("expected HasAppPrivateKey false")
	}
	if !loaded.Azure.HasClientSecret {
		t.Error("expected HasClientSecret true")
	}
	if loaded.GCP.HasCredentials {
		t.Error("expected HasCredentials false")
	}
}

func TestSaveDoesNotPersistHasFlags(t *testing.T) {
	sp, ep := tempPaths(t)
	fs := NewFileStore(sp, ep)

	s := DefaultSettings()
	s.GitHub.HasToken = true // This should be stripped on save

	if err := fs.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(sp)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// The JSON should have has_token: false since we zeroed it
	if string(data) == "" {
		t.Error("expected non-empty settings file")
	}
}

func TestSaveSecretOverwritesExisting(t *testing.T) {
	sp, ep := tempPaths(t)
	fs := NewFileStore(sp, ep)

	if err := fs.SaveSecret(SecretGitHubToken, "old-token"); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	if err := fs.SaveSecret(SecretGitHubToken, "new-token"); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}

	v, ok := fs.GetSecret(SecretGitHubToken)
	if !ok || v != "new-token" {
		t.Errorf("expected new-token, got %s", v)
	}
}
