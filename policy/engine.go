// Package policy provides an OPA-based policy evaluation engine for the
// Cloud Security Fabric. It evaluates OCSF findings against Rego policies.
package policy

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed policies/*.rego
var defaultPolicies embed.FS

// Decision represents the outcome of a policy evaluation.
type Decision string

const (
	DecisionNormal        Decision = "normal"
	DecisionSuppressed    Decision = "suppress"
	DecisionEscalated     Decision = "escalate"
	DecisionImmediate     Decision = "immediate_action"
	DecisionAutoRemediate Decision = "auto_remediate"
)

// EvalResult holds the result of evaluating a finding against policies.
type EvalResult struct {
	Decision    Decision          `json:"decision"`
	Reasons     []string          `json:"reasons"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Engine manages OPA policy evaluation.
type Engine struct {
	modules map[string]string
	mu      sync.RWMutex
}

// NewEngine creates a new policy engine with default policies loaded.
func NewEngine() (*Engine, error) {
	e := &Engine{
		modules: make(map[string]string),
	}
	if err := e.loadDefaultPolicies(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) loadDefaultPolicies() error {
	entries, err := defaultPolicies.ReadDir("policies")
	if err != nil {
		return fmt.Errorf("read policies dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}
		data, err := defaultPolicies.ReadFile("policies/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read policy %s: %w", entry.Name(), err)
		}
		e.modules[entry.Name()] = string(data)
	}
	return nil
}

// Evaluate runs all loaded policies against an OCSF finding (as map).
func (e *Engine) Evaluate(ctx context.Context, finding map[string]interface{}) (*EvalResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := &EvalResult{
		Decision: DecisionNormal,
	}

	for name, module := range e.modules {
		r := rego.New(
			rego.Query("data.csf."+policyName(name)),
			rego.Module(name, module),
			rego.Input(finding),
		)

		rs, err := r.Eval(ctx)
		if err != nil {
			continue // skip broken policies
		}

		for _, expr := range rs {
			for _, val := range expr.Expressions {
				if m, ok := val.Value.(map[string]interface{}); ok {
					if dec, ok := m["decision"].(string); ok {
						newDec := Decision(dec)
						if priority(newDec) > priority(result.Decision) {
							result.Decision = newDec
						}
					}
					if reason, ok := m["reason"].(string); ok {
						result.Reasons = append(result.Reasons, reason)
					}
				}
			}
		}
	}

	return result, nil
}

// AddPolicy adds a custom policy module.
func (e *Engine) AddPolicy(name, module string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules[name] = module
}

// ListPolicies returns the names of all loaded policies.
func (e *Engine) ListPolicies() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.modules))
	for name := range e.modules {
		names = append(names, name)
	}
	return names
}

func policyName(filename string) string {
	name := strings.TrimSuffix(filename, ".rego")
	return strings.ReplaceAll(name, "-", "_")
}

func priority(d Decision) int {
	switch d {
	case DecisionNormal:
		return 0
	case DecisionSuppressed:
		return 1
	case DecisionEscalated:
		return 2
	case DecisionImmediate:
		return 3
	case DecisionAutoRemediate:
		return 4
	default:
		return 0
	}
}
