package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ShodanResult represents the response from the Shodan InternetDB API.
type ShodanResult struct {
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

type shodanCacheEntry struct {
	result    *ShodanResult
	fetchedAt time.Time
}

// ShodanClient queries the free Shodan InternetDB API with caching.
type ShodanClient struct {
	httpClient *http.Client
	baseURL    string
	cache      map[string]shodanCacheEntry
	cacheTTL   time.Duration
	mu         sync.RWMutex
}

// NewShodanClient creates a new Shodan InternetDB client.
func NewShodanClient() *ShodanClient {
	return &ShodanClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    "https://internetdb.shodan.io",
		cache:      make(map[string]shodanCacheEntry),
		cacheTTL:   24 * time.Hour,
	}
}

// Lookup queries the Shodan InternetDB for information about an IP address.
// Returns nil, nil if the IP is not found in Shodan's database.
func (c *ShodanClient) Lookup(ctx context.Context, ip string) (*ShodanResult, error) {
	c.mu.RLock()
	if entry, ok := c.cache[ip]; ok && time.Since(entry.fetchedAt) < c.cacheTTL {
		c.mu.RUnlock()
		return entry.result, nil
	}
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s", c.baseURL, ip), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		c.mu.Lock()
		c.cache[ip] = shodanCacheEntry{result: nil, fetchedAt: time.Now()}
		c.mu.Unlock()
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API returned status %d", resp.StatusCode)
	}

	var result ShodanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode shodan response: %w", err)
	}

	c.mu.Lock()
	c.cache[ip] = shodanCacheEntry{result: &result, fetchedAt: time.Now()}
	c.mu.Unlock()

	return &result, nil
}
