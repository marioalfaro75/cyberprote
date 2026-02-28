package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// NVDCVEDetail holds parsed CVE details from the NVD API.
type NVDCVEDetail struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSS3Score  float64  `json:"cvss3_score"`
	CWEs        []string `json:"cwes"`
	References  []string `json:"references"`
}

type nvdCacheEntry struct {
	detail    *NVDCVEDetail
	fetchedAt time.Time
}

// NVDClient queries the NVD 2.0 API for CVE details with caching.
type NVDClient struct {
	httpClient *http.Client
	baseURL    string
	cache      map[string]nvdCacheEntry
	cacheTTL   time.Duration
	mu         sync.RWMutex
}

// NewNVDClient creates a new NVD CVE detail client.
func NewNVDClient() *NVDClient {
	return &NVDClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		baseURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		cache:      make(map[string]nvdCacheEntry),
		cacheTTL:   7 * 24 * time.Hour,
	}
}

// nvdResponse is the top-level NVD 2.0 API response.
type nvdResponse struct {
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string         `json:"id"`
	Descriptions []nvdLangStr   `json:"descriptions"`
	Metrics      *nvdMetrics    `json:"metrics,omitempty"`
	Weaknesses   []nvdWeakness  `json:"weaknesses,omitempty"`
	References   []nvdReference `json:"references,omitempty"`
}

type nvdLangStr struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSS31 []nvdCVSSEntry `json:"cvssMetricV31,omitempty"`
	CVSS30 []nvdCVSSEntry `json:"cvssMetricV30,omitempty"`
}

type nvdCVSSEntry struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore float64 `json:"baseScore"`
}

type nvdWeakness struct {
	Description []nvdLangStr `json:"description"`
}

type nvdReference struct {
	URL string `json:"url"`
}

// GetCVE fetches CVE details from the NVD API, using cache when available.
func (c *NVDClient) GetCVE(ctx context.Context, cveID string) (*NVDCVEDetail, error) {
	c.mu.RLock()
	if entry, ok := c.cache[cveID]; ok && time.Since(entry.fetchedAt) < c.cacheTTL {
		c.mu.RUnlock()
		return entry.detail, nil
	}
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?cveId=%s", c.baseURL, cveID), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found in NVD", cveID)
	}

	cve := nvdResp.Vulnerabilities[0].CVE
	detail := &NVDCVEDetail{
		ID: cve.ID,
	}

	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			detail.Description = d.Value
			break
		}
	}

	if cve.Metrics != nil {
		if len(cve.Metrics.CVSS31) > 0 {
			detail.CVSS3Score = cve.Metrics.CVSS31[0].CVSSData.BaseScore
		} else if len(cve.Metrics.CVSS30) > 0 {
			detail.CVSS3Score = cve.Metrics.CVSS30[0].CVSSData.BaseScore
		}
	}

	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && d.Value != "NVD-CWE-Other" && d.Value != "NVD-CWE-noinfo" {
				detail.CWEs = append(detail.CWEs, d.Value)
			}
		}
	}

	for _, ref := range cve.References {
		detail.References = append(detail.References, ref.URL)
	}

	c.mu.Lock()
	c.cache[cveID] = nvdCacheEntry{detail: detail, fetchedAt: time.Now()}
	c.mu.Unlock()

	return detail, nil
}
