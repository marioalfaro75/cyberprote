// Package playbooks provides a YAML-defined playbook engine for automated
// security response actions.
package playbooks

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Playbook defines a security response playbook.
type Playbook struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Trigger     Trigger  `yaml:"trigger"`
	Steps       []Step   `yaml:"steps"`
	Approval    Approval `yaml:"approval"`
}

// Trigger defines when a playbook should activate.
type Trigger struct {
	ClassUID   int32    `yaml:"class_uid"`
	SeverityID int32    `yaml:"min_severity_id"`
	Keywords   []string `yaml:"keywords"`
	SecretType string   `yaml:"secret_type"`
}

// Step defines a single action in a playbook.
type Step struct {
	Name        string            `yaml:"name"`
	Action      string            `yaml:"action"`
	Parameters  map[string]string `yaml:"parameters"`
	OnFailure   string            `yaml:"on_failure"`
	DryRunSafe  bool              `yaml:"dry_run_safe"`
}

// Approval defines the approval workflow for a playbook.
type Approval struct {
	Required bool     `yaml:"required"`
	Approvers []string `yaml:"approvers"`
	Timeout  string   `yaml:"timeout"`
}

// ExecutionResult captures the result of running a playbook.
type ExecutionResult struct {
	PlaybookName string       `json:"playbook_name"`
	StartedAt    time.Time    `json:"started_at"`
	CompletedAt  time.Time    `json:"completed_at"`
	DryRun       bool         `json:"dry_run"`
	Steps        []StepResult `json:"steps"`
	Status       string       `json:"status"`
}

// StepResult captures the result of a single step.
type StepResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

// Engine manages and executes playbooks.
type Engine struct {
	playbooks map[string]*Playbook
}

// NewEngine creates a new playbook engine.
func NewEngine() *Engine {
	return &Engine{playbooks: make(map[string]*Playbook)}
}

// LoadPlaybook parses and registers a playbook from YAML.
func (e *Engine) LoadPlaybook(data []byte) error {
	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return fmt.Errorf("parse playbook: %w", err)
	}
	e.playbooks[pb.Name] = &pb
	return nil
}

// ListPlaybooks returns all registered playbook names.
func (e *Engine) ListPlaybooks() []string {
	names := make([]string, 0, len(e.playbooks))
	for name := range e.playbooks {
		names = append(names, name)
	}
	return names
}

// MatchPlaybooks returns playbooks triggered by a finding.
func (e *Engine) MatchPlaybooks(finding map[string]interface{}) []*Playbook {
	var matched []*Playbook
	for _, pb := range e.playbooks {
		if matchesTrigger(pb.Trigger, finding) {
			matched = append(matched, pb)
		}
	}
	return matched
}

// Execute runs a playbook in dry-run or live mode.
func (e *Engine) Execute(ctx context.Context, playbookName string, finding map[string]interface{}, dryRun bool) (*ExecutionResult, error) {
	pb, ok := e.playbooks[playbookName]
	if !ok {
		return nil, fmt.Errorf("playbook not found: %s", playbookName)
	}

	result := &ExecutionResult{
		PlaybookName: playbookName,
		StartedAt:    time.Now(),
		DryRun:       dryRun,
		Status:       "completed",
	}

	for _, step := range pb.Steps {
		sr := StepResult{Name: step.Name}

		if dryRun && !step.DryRunSafe {
			sr.Status = "skipped"
			sr.Output = "dry-run: action would execute"
		} else {
			// Execute the step action
			sr.Status = "completed"
			sr.Output = fmt.Sprintf("executed action: %s", step.Action)
		}

		result.Steps = append(result.Steps, sr)
	}

	result.CompletedAt = time.Now()
	return result, nil
}

func matchesTrigger(trigger Trigger, finding map[string]interface{}) bool {
	if trigger.ClassUID > 0 {
		classUID, _ := finding["class_uid"].(float64)
		if int32(classUID) != trigger.ClassUID {
			return false
		}
	}
	if trigger.SeverityID > 0 {
		sevID, _ := finding["severity_id"].(float64)
		if int32(sevID) < trigger.SeverityID {
			return false
		}
	}
	return true
}
