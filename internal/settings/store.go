package settings

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// FileStore persists provider settings as JSON and secrets in a .env file.
type FileStore struct {
	mu          sync.RWMutex
	settingsPath string
	secretsPath  string
}

// NewFileStore creates a FileStore that reads/writes the given paths.
func NewFileStore(settingsPath, secretsPath string) *FileStore {
	return &FileStore{
		settingsPath: settingsPath,
		secretsPath:  secretsPath,
	}
}

// Load reads provider settings from the JSON file and populates the
// Has* flags by checking which secrets exist in the .env file.
func (fs *FileStore) Load() (*ProviderSettings, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	settings := DefaultSettings()

	data, err := os.ReadFile(fs.settingsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No settings file yet — return defaults.
			return settings, nil
		}
		return nil, fmt.Errorf("read settings: %w", err)
	}

	if err := json.Unmarshal(data, settings); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}

	// Populate Has* flags from secrets file.
	settings.GitHub.HasToken = fs.hasSecretLocked(SecretGitHubToken)
	settings.GitHub.HasAppPrivateKey = fs.hasSecretLocked(SecretGitHubAppPrivateKey)
	settings.GCP.HasCredentials = fs.hasSecretLocked(SecretGCPCredentials)
	settings.Azure.HasClientSecret = fs.hasSecretLocked(SecretAzureClientSecret)

	return settings, nil
}

// Save writes provider settings to the JSON file. Secret values are
// never stored here; use SaveSecret for those.
func (fs *FileStore) Save(s *ProviderSettings) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Zero out read-only Has* flags before saving — they are derived.
	s.GitHub.HasToken = false
	s.GitHub.HasAppPrivateKey = false
	s.GCP.HasCredentials = false
	s.Azure.HasClientSecret = false

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return os.WriteFile(fs.settingsPath, data, 0644)
}

// SaveSecret writes or updates a single key=value pair in the secrets
// .env file and sets file permissions to 0600.
func (fs *FileStore) SaveSecret(key, value string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	envMap, err := fs.readEnvLocked()
	if err != nil {
		return err
	}
	envMap[key] = value
	return fs.writeEnvLocked(envMap)
}

// HasSecret returns true if the key exists in the secrets file.
func (fs *FileStore) HasSecret(key string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.hasSecretLocked(key)
}

// GetSecret returns the secret value for the given key.
// Returns ("", false) if the key does not exist.
func (fs *FileStore) GetSecret(key string) (string, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	envMap, err := fs.readEnvLocked()
	if err != nil {
		return "", false
	}
	v, ok := envMap[key]
	return v, ok
}

// hasSecretLocked checks without acquiring the lock (caller must hold it).
func (fs *FileStore) hasSecretLocked(key string) bool {
	envMap, err := fs.readEnvLocked()
	if err != nil {
		return false
	}
	v, ok := envMap[key]
	return ok && v != ""
}

// readEnvLocked parses KEY=VALUE lines from the secrets file.
func (fs *FileStore) readEnvLocked() (map[string]string, error) {
	f, err := os.Open(fs.secretsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return make(map[string]string), nil
		}
		return nil, fmt.Errorf("read secrets: %w", err)
	}
	defer f.Close()

	envMap := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		envMap[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return envMap, scanner.Err()
}

// writeEnvLocked writes all key=value pairs to the secrets file with 0600 permissions.
func (fs *FileStore) writeEnvLocked(envMap map[string]string) error {
	var sb strings.Builder
	sb.WriteString("# CSF secrets — managed by CSF API. Do not edit manually.\n")
	for k, v := range envMap {
		if v != "" {
			fmt.Fprintf(&sb, "%s=%s\n", k, v)
		}
	}
	return os.WriteFile(fs.secretsPath, []byte(sb.String()), 0600)
}
