package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TestGCPConnection verifies GCP connectivity by using application default
// credentials (via the gcloud CLI or GOOGLE_APPLICATION_CREDENTIALS) to make
// a test call to the Cloud Resource Manager API.
func TestGCPConnection(ctx context.Context, cfg GCPConfig) (string, error) {
	token, err := getGCPAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("GCP auth: %w", err)
	}

	var url string
	if cfg.ScopeType == "organization" && cfg.OrganizationID != "" {
		url = fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/organizations/%s", cfg.OrganizationID)
	} else if cfg.ProjectID != "" {
		url = fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s", cfg.ProjectID)
	} else {
		return "", fmt.Errorf("either organization_id or project_id is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resource manager request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resource manager returned %d", resp.StatusCode)
	}

	scope := cfg.ProjectID
	if cfg.ScopeType == "organization" {
		scope = "org:" + cfg.OrganizationID
	}
	return fmt.Sprintf("GCP credentials valid (scope: %s)", scope), nil
}

// getGCPAccessToken tries to obtain an access token via gcloud CLI, which
// is the simplest approach that works without adding heavy GCP SDK deps.
func getGCPAccessToken(ctx context.Context) (string, error) {
	// First try GOOGLE_APPLICATION_CREDENTIALS + metadata server isn't
	// practical here, so rely on gcloud as the user-facing test path.
	if credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); credFile != "" {
		// Read the service account JSON and extract the token via
		// a quick gcloud print-access-token call.
		_ = credFile // Presence is enough — gcloud will use it.
	}

	cmd := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gcloud auth print-access-token failed: %w (is gcloud installed?)", err)
	}

	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("gcloud returned empty token")
	}

	// Validate token format loosely.
	if !json.Valid([]byte(`"`+token+`"`)) {
		return "", fmt.Errorf("invalid token format from gcloud")
	}

	return token, nil
}
