package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TestAzureConnection verifies Azure connectivity by obtaining an OAuth2 token
// using client credentials and making a test call to the Management API.
func TestAzureConnection(ctx context.Context, cfg AzureConfig, clientSecret string) (string, error) {
	if cfg.TenantID == "" {
		return "", fmt.Errorf("tenant_id is required")
	}
	if cfg.ClientID == "" {
		return "", fmt.Errorf("client_id is required")
	}
	if clientSecret == "" {
		return "", fmt.Errorf("no client secret configured")
	}

	// Obtain an access token via client credentials flow.
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cfg.TenantID)
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.ClientID},
		"client_secret": {clientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(tokenURL, form)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	// Test management API access.
	subURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s?api-version=2022-12-01",
		strings.TrimSpace(cfg.SubscriptionID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp2, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("management API request: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return "", fmt.Errorf("management API returned %d", resp2.StatusCode)
	}

	return fmt.Sprintf("Authenticated to Azure (subscription: %s)", cfg.SubscriptionID), nil
}
