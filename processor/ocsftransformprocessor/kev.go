package ocsftransformprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// KEVClient checks CVEs against the CISA Known Exploited Vulnerabilities catalog.
type KEVClient struct {
	feedURL    string
	client     *http.Client
	knownCVEs  map[string]bool
	lastUpdate time.Time
	mu         sync.RWMutex
}

// kevCatalog represents the CISA KEV JSON catalog structure.
type kevCatalog struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// NewKEVClient creates a new KEV catalog client.
func NewKEVClient(feedURL string) *KEVClient {
	return &KEVClient{
		feedURL:   feedURL,
		client:    &http.Client{Timeout: 30 * time.Second},
		knownCVEs: make(map[string]bool),
	}
}

// IsKnownExploited checks if a CVE is in the CISA KEV catalog.
// The catalog is refreshed daily.
func (c *KEVClient) IsKnownExploited(ctx context.Context, cveID string) (bool, error) {
	if err := c.refreshIfNeeded(ctx); err != nil {
		return false, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.knownCVEs[cveID], nil
}

// refreshIfNeeded downloads the KEV catalog if it's older than 24 hours.
func (c *KEVClient) refreshIfNeeded(ctx context.Context) error {
	c.mu.RLock()
	if !c.lastUpdate.IsZero() && time.Since(c.lastUpdate) < 24*time.Hour {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if !c.lastUpdate.IsZero() && time.Since(c.lastUpdate) < 24*time.Hour {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.feedURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV feed returned status %d", resp.StatusCode)
	}

	var catalog kevCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return err
	}

	newCVEs := make(map[string]bool, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		newCVEs[v.CVEID] = true
	}

	c.knownCVEs = newCVEs
	c.lastUpdate = time.Now()
	return nil
}
