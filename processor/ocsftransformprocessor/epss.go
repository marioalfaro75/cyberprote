package ocsftransformprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// EPSSClient queries the FIRST EPSS API for exploit prediction scores.
type EPSSClient struct {
	endpoint string
	client   *http.Client
	cache    map[string]epssEntry
	mu       sync.RWMutex
}

type epssEntry struct {
	score     float64
	fetchedAt time.Time
}

// NewEPSSClient creates a new EPSS API client.
func NewEPSSClient(endpoint string) *EPSSClient {
	return &EPSSClient{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
		cache:    make(map[string]epssEntry),
	}
}

// epssResponse represents the FIRST EPSS API response.
type epssResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Data       []struct {
		CVE   string `json:"cve"`
		EPSS  string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// GetScore returns the EPSS probability score for a CVE ID.
// Results are cached for 24 hours.
func (c *EPSSClient) GetScore(ctx context.Context, cveID string) (float64, error) {
	// Check cache
	c.mu.RLock()
	if entry, ok := c.cache[cveID]; ok && time.Since(entry.fetchedAt) < 24*time.Hour {
		c.mu.RUnlock()
		return entry.score, nil
	}
	c.mu.RUnlock()

	// Fetch from API
	url := fmt.Sprintf("%s?cve=%s", c.endpoint, cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var result epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	if len(result.Data) == 0 {
		return 0, fmt.Errorf("no EPSS data for %s", cveID)
	}

	score, err := strconv.ParseFloat(result.Data[0].EPSS, 64)
	if err != nil {
		return 0, err
	}

	// Cache the result
	c.mu.Lock()
	c.cache[cveID] = epssEntry{score: score, fetchedAt: time.Now()}
	c.mu.Unlock()

	return score, nil
}
