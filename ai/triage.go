// Package ai provides AI-powered triage and explanation for security findings
// using local LLM inference via Ollama.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"text/template"
	"time"
)

// TriageClient connects to an Ollama instance for finding triage.
type TriageClient struct {
	endpoint string
	model    string
	client   *http.Client
	cache    map[string]string
	mu       sync.RWMutex
}

// NewTriageClient creates a new AI triage client.
func NewTriageClient(endpoint, model string) *TriageClient {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}
	return &TriageClient{
		endpoint: endpoint,
		model:    model,
		client:   &http.Client{Timeout: 60 * time.Second},
		cache:    make(map[string]string),
	}
}

// ExplainFinding generates an AI explanation and remediation guidance for a finding.
func (c *TriageClient) ExplainFinding(ctx context.Context, finding map[string]interface{}, graphContext string) (string, error) {
	// Check cache
	cacheKey := fmt.Sprintf("%v", finding["finding_info"])
	c.mu.RLock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	prompt, err := buildPrompt(finding, graphContext)
	if err != nil {
		return fallbackExplanation(finding), nil
	}

	resp, err := c.generate(ctx, prompt)
	if err != nil {
		return fallbackExplanation(finding), nil
	}

	// Cache the response
	c.mu.Lock()
	c.cache[cacheKey] = resp
	c.mu.Unlock()

	return resp, nil
}

// ollamaRequest represents an Ollama generate API request.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// ollamaResponse represents an Ollama generate API response.
type ollamaResponse struct {
	Response string `json:"response"`
}

func (c *TriageClient) generate(ctx context.Context, prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Response, nil
}

var triageTemplate = template.Must(template.New("triage").Parse(`You are a cloud security analyst. Analyze this security finding and provide:
1. A clear explanation of the risk
2. Impact assessment
3. Recommended remediation steps

Finding:
- Title: {{.Title}}
- Severity: {{.Severity}}
- Type: {{.Type}}
- Description: {{.Description}}
- Resources: {{.Resources}}

{{if .GraphContext}}Graph Context:
{{.GraphContext}}
{{end}}

Provide a concise, actionable response.`))

func buildPrompt(finding map[string]interface{}, graphContext string) (string, error) {
	title := ""
	if fi, ok := finding["finding_info"].(map[string]interface{}); ok {
		title, _ = fi["title"].(string)
	}
	severity, _ := finding["severity"].(string)
	msg, _ := finding["message"].(string)
	classUID, _ := finding["class_uid"].(float64)

	typeName := "Security Finding"
	switch int32(classUID) {
	case 2002:
		typeName = "Vulnerability"
	case 2003:
		typeName = "Compliance"
	case 2004:
		typeName = "Detection"
	case 2006:
		typeName = "Data Security"
	}

	var buf bytes.Buffer
	err := triageTemplate.Execute(&buf, map[string]interface{}{
		"Title":        title,
		"Severity":     severity,
		"Type":         typeName,
		"Description":  msg,
		"Resources":    fmt.Sprintf("%v", finding["resources"]),
		"GraphContext": graphContext,
	})
	return buf.String(), err
}

func fallbackExplanation(finding map[string]interface{}) string {
	title := "Unknown finding"
	if fi, ok := finding["finding_info"].(map[string]interface{}); ok {
		if t, ok := fi["title"].(string); ok {
			title = t
		}
	}
	severity, _ := finding["severity"].(string)

	return fmt.Sprintf("Finding: %s\nSeverity: %s\n\nAI triage is unavailable. Please review the finding details and consult your security runbooks for remediation guidance.", title, severity)
}
