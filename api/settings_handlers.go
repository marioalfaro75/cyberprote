package api

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/cloud-security-fabric/csf/internal/settings"
)

func (s *Server) handleGetConnectors(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.settingsStore.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleUpdateConnectors(w http.ResponseWriter, r *http.Request) {
	var cfg settings.ProviderSettings
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if err := s.settingsStore.Save(&cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Re-read to populate Has* flags.
	saved, err := s.settingsStore.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"settings":         saved,
		"restart_required": true,
	})
}

func (s *Server) handleUpdateSecrets(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")

	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Map provider + key to the correct env var name.
	envKey, ok := resolveSecretKey(provider, body.Key)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown secret key"})
		return
	}

	if err := s.settingsStore.SaveSecret(envKey, body.Value); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"saved":            true,
		"restart_required": true,
	})
}

func (s *Server) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")

	cfg, err := s.settingsStore.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var msg string

	switch provider {
	case "aws":
		msg, err = settings.TestAWSConnection(r.Context(), cfg.AWS)
	case "github":
		token, _ := s.settingsStore.GetSecret(settings.SecretGitHubToken)
		msg, err = settings.TestGitHubConnection(r.Context(), cfg.GitHub, token)
	case "gcp":
		msg, err = settings.TestGCPConnection(r.Context(), cfg.GCP)
	case "azure":
		secret, _ := s.settingsStore.GetSecret(settings.SecretAzureClientSecret)
		msg, err = settings.TestAzureConnection(r.Context(), cfg.Azure, secret)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider"})
		return
	}

	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": msg,
	})
}

func (s *Server) handleApplySettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.settingsStore.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	dsn := os.Getenv("CSF_DSN")
	if dsn == "" {
		dsn = "postgres://csf:csf-dev-password@localhost:5432/csf?sslmode=disable"
	}

	yaml := settings.RenderCollectorConfig(cfg, dsn)

	configPath := os.Getenv("CSF_COLLECTOR_CONFIG")
	if configPath == "" {
		configPath = "./collector-config.yaml"
	}

	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"applied":          true,
		"config_path":      configPath,
		"restart_required": true,
	})
}

// resolveSecretKey maps a provider + friendly key name to the env var used
// in the secrets file.
func resolveSecretKey(provider, key string) (string, bool) {
	m := map[string]map[string]string{
		"github": {
			"token":           settings.SecretGitHubToken,
			"app_private_key": settings.SecretGitHubAppPrivateKey,
		},
		"gcp": {
			"credentials": settings.SecretGCPCredentials,
		},
		"azure": {
			"client_secret": settings.SecretAzureClientSecret,
		},
	}
	providerMap, ok := m[provider]
	if !ok {
		return "", false
	}
	envKey, ok := providerMap[key]
	return envKey, ok
}
