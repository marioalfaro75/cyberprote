// Package ocsf provides Go type definitions for the Open Cybersecurity Schema Framework (OCSF)
// event classes used by the Cloud Security Fabric.
package ocsf

import (
	"encoding/json"
	"time"
)

// OCSF class UIDs
const (
	ClassSecurityFinding    int32 = 2001
	ClassVulnerabilityFind  int32 = 2002
	ClassComplianceFinding  int32 = 2003
	ClassDetectionFinding   int32 = 2004
	ClassDataSecurityFind   int32 = 2006
)

// OCSF severity IDs
const (
	SeverityUnknown       int32 = 0
	SeverityInformational int32 = 1
	SeverityLow           int32 = 2
	SeverityMedium        int32 = 3
	SeverityHigh          int32 = 4
	SeverityCritical      int32 = 5
	SeverityFatal         int32 = 6
	SeverityOther         int32 = 99
)

// OCSF status IDs
const (
	StatusNew        int32 = 1
	StatusInProgress int32 = 2
	StatusSuppressed int32 = 3
	StatusResolved   int32 = 4
	StatusOther      int32 = 99
)

// OCSF activity IDs
const (
	ActivityCreate int32 = 1
	ActivityUpdate int32 = 2
	ActivityClose  int32 = 3
	ActivityOther  int32 = 99
)

// Metadata holds OCSF metadata about the event source.
type Metadata struct {
	Product    *Product `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	LogName    string   `json:"log_name,omitempty"`
	LogVersion string   `json:"log_version,omitempty"`
	Profiles   []string `json:"profiles,omitempty"`
}

// Product identifies the source product that generated the finding.
type Product struct {
	Name      string `json:"name,omitempty"`
	VendorName string `json:"vendor_name,omitempty"`
	Version   string `json:"version,omitempty"`
	UID       string `json:"uid,omitempty"`
	Feature   *Feature `json:"feature,omitempty"`
}

// Feature describes the product feature that generated the finding.
type Feature struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// Cloud describes the cloud environment where the resource resides.
type Cloud struct {
	Provider  string `json:"provider,omitempty"`
	Region    string `json:"region,omitempty"`
	Zone      string `json:"zone,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
}

// Resource represents a cloud resource referenced in a finding.
type Resource struct {
	UID     string            `json:"uid,omitempty"`
	Name    string            `json:"name,omitempty"`
	Type    string            `json:"type,omitempty"`
	Cloud   *Cloud            `json:"cloud,omitempty"`
	Labels  []string          `json:"labels,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
	Region  string            `json:"region,omitempty"`
	Owner   *Identity         `json:"owner,omitempty"`
}

// Identity represents a user, role, or service principal.
type Identity struct {
	UID       string `json:"uid,omitempty"`
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	Provider  string `json:"provider,omitempty"`
	AccountID string `json:"account_id,omitempty"`
}

// FindingInfo contains supplemental finding details.
type FindingInfo struct {
	UID         string   `json:"uid,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"desc,omitempty"`
	CreatedTime *Time    `json:"created_time,omitempty"`
	ModifiedTime *Time   `json:"modified_time,omitempty"`
	FirstSeenTime *Time  `json:"first_seen_time,omitempty"`
	LastSeenTime  *Time  `json:"last_seen_time,omitempty"`
	SrcURL      string   `json:"src_url,omitempty"`
	Types       []string `json:"types,omitempty"`
	RelatedEvents []string `json:"related_events,omitempty"`
	DataSources   []string `json:"data_sources,omitempty"`
}

// CVSS represents Common Vulnerability Scoring System scores.
type CVSS struct {
	Version     string  `json:"version,omitempty"`
	BaseScore   float64 `json:"base_score,omitempty"`
	Severity    string  `json:"severity,omitempty"`
	VectorString string `json:"vector_string,omitempty"`
	Metrics     json.RawMessage `json:"metrics,omitempty"`
}

// CVE represents a Common Vulnerabilities and Exposures entry.
type CVE struct {
	UID           string    `json:"uid,omitempty"`
	CVSS          []CVSS    `json:"cvss,omitempty"`
	CWE           *CWE      `json:"cwe,omitempty"`
	EPSSScore     *float64  `json:"epss_score,omitempty"`
	IsExploited   *bool     `json:"is_exploited,omitempty"`
	References    []string  `json:"references,omitempty"`
	CreatedTime   *Time     `json:"created_time,omitempty"`
	ModifiedTime  *Time     `json:"modified_time,omitempty"`
}

// CWE represents a Common Weakness Enumeration entry.
type CWE struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
	SrcURL string `json:"src_url,omitempty"`
}

// Vulnerability represents a vulnerability referenced in a finding.
type Vulnerability struct {
	UID           string   `json:"uid,omitempty"`
	Title         string   `json:"title,omitempty"`
	Description   string   `json:"desc,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	CVE           *CVE     `json:"cve,omitempty"`
	Packages      []Package `json:"packages,omitempty"`
	AffectedCode  []AffectedCode `json:"affected_code,omitempty"`
	FixAvailable  *bool    `json:"fix_available,omitempty"`
	References    []string `json:"references,omitempty"`
	VendorName    string   `json:"vendor_name,omitempty"`
	KBArticles    []string `json:"kb_articles,omitempty"`
}

// Package represents a software package affected by a vulnerability.
type Package struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	FixedIn string `json:"fixed_in,omitempty"`
	Type    string `json:"type,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// AffectedCode represents a code location affected by a vulnerability.
type AffectedCode struct {
	FilePath  string `json:"file_path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

// Remediation describes the recommended fix for a finding.
type Remediation struct {
	Description string   `json:"desc,omitempty"`
	References  []string `json:"references,omitempty"`
	KBArticles  []string `json:"kb_articles,omitempty"`
}

// Compliance describes the compliance standard that was evaluated.
type Compliance struct {
	Requirements []string `json:"requirements,omitempty"`
	Status       string   `json:"status,omitempty"`
	StatusDetail string   `json:"status_detail,omitempty"`
	Standards    []string `json:"standards,omitempty"`
	Control      string   `json:"control,omitempty"`
}

// Time is a wrapper around time.Time for OCSF timestamp serialization (epoch millis).
type Time struct {
	time.Time
}

// MarshalJSON serializes Time as epoch milliseconds.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UnixMilli())
}

// UnmarshalJSON deserializes epoch milliseconds to Time.
func (t *Time) UnmarshalJSON(data []byte) error {
	var ms int64
	if err := json.Unmarshal(data, &ms); err != nil {
		// Try RFC3339 fallback
		var s string
		if err2 := json.Unmarshal(data, &s); err2 != nil {
			return err
		}
		parsed, err2 := time.Parse(time.RFC3339, s)
		if err2 != nil {
			return err2
		}
		t.Time = parsed
		return nil
	}
	t.Time = time.UnixMilli(ms)
	return nil
}

// NewTime creates an OCSF Time from a standard time.Time.
func NewTime(t time.Time) *Time {
	return &Time{Time: t}
}

// SecurityFinding represents OCSF class_uid 2001 — Security Finding.
type SecurityFinding struct {
	ActivityID  int32        `json:"activity_id"`
	CategoryUID int32        `json:"category_uid"`
	ClassUID    int32        `json:"class_uid"`
	Confidence  *int32       `json:"confidence,omitempty"`
	Count       *int32       `json:"count,omitempty"`
	Message     string       `json:"message,omitempty"`
	Metadata    Metadata     `json:"metadata"`
	Severity    string       `json:"severity,omitempty"`
	SeverityID  int32        `json:"severity_id"`
	Status      string       `json:"status,omitempty"`
	StatusID    int32        `json:"status_id,omitempty"`
	Time        *Time        `json:"time,omitempty"`
	TypeUID     int32        `json:"type_uid,omitempty"`
	TypeName    string       `json:"type_name,omitempty"`

	FindingInfo  *FindingInfo  `json:"finding_info,omitempty"`
	Resources    []Resource    `json:"resources,omitempty"`
	Cloud        *Cloud        `json:"cloud,omitempty"`
	Remediation  *Remediation  `json:"remediation,omitempty"`

	// CSF extension fields
	Unmapped map[string]interface{} `json:"unmapped,omitempty"`
}

// VulnerabilityFinding represents OCSF class_uid 2002 — Vulnerability Finding.
type VulnerabilityFinding struct {
	ActivityID  int32        `json:"activity_id"`
	CategoryUID int32        `json:"category_uid"`
	ClassUID    int32        `json:"class_uid"`
	Confidence  *int32       `json:"confidence,omitempty"`
	Count       *int32       `json:"count,omitempty"`
	Message     string       `json:"message,omitempty"`
	Metadata    Metadata     `json:"metadata"`
	Severity    string       `json:"severity,omitempty"`
	SeverityID  int32        `json:"severity_id"`
	Status      string       `json:"status,omitempty"`
	StatusID    int32        `json:"status_id,omitempty"`
	Time        *Time        `json:"time,omitempty"`
	TypeUID     int32        `json:"type_uid,omitempty"`
	TypeName    string       `json:"type_name,omitempty"`

	FindingInfo     *FindingInfo     `json:"finding_info,omitempty"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities,omitempty"`
	Resources       []Resource       `json:"resources,omitempty"`
	Cloud           *Cloud           `json:"cloud,omitempty"`
	Remediation     *Remediation     `json:"remediation,omitempty"`

	Unmapped map[string]interface{} `json:"unmapped,omitempty"`
}

// ComplianceFinding represents OCSF class_uid 2003 — Compliance Finding.
type ComplianceFinding struct {
	ActivityID  int32        `json:"activity_id"`
	CategoryUID int32        `json:"category_uid"`
	ClassUID    int32        `json:"class_uid"`
	Confidence  *int32       `json:"confidence,omitempty"`
	Count       *int32       `json:"count,omitempty"`
	Message     string       `json:"message,omitempty"`
	Metadata    Metadata     `json:"metadata"`
	Severity    string       `json:"severity,omitempty"`
	SeverityID  int32        `json:"severity_id"`
	Status      string       `json:"status,omitempty"`
	StatusID    int32        `json:"status_id,omitempty"`
	Time        *Time        `json:"time,omitempty"`
	TypeUID     int32        `json:"type_uid,omitempty"`
	TypeName    string       `json:"type_name,omitempty"`

	FindingInfo *FindingInfo `json:"finding_info,omitempty"`
	Compliance  *Compliance  `json:"compliance,omitempty"`
	Resources   []Resource   `json:"resources,omitempty"`
	Cloud       *Cloud       `json:"cloud,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`

	Unmapped map[string]interface{} `json:"unmapped,omitempty"`
}

// DetectionFinding represents OCSF class_uid 2004 — Detection Finding.
type DetectionFinding struct {
	ActivityID  int32        `json:"activity_id"`
	CategoryUID int32        `json:"category_uid"`
	ClassUID    int32        `json:"class_uid"`
	Confidence  *int32       `json:"confidence,omitempty"`
	Count       *int32       `json:"count,omitempty"`
	Message     string       `json:"message,omitempty"`
	Metadata    Metadata     `json:"metadata"`
	Severity    string       `json:"severity,omitempty"`
	SeverityID  int32        `json:"severity_id"`
	Status      string       `json:"status,omitempty"`
	StatusID    int32        `json:"status_id,omitempty"`
	Time        *Time        `json:"time,omitempty"`
	TypeUID     int32        `json:"type_uid,omitempty"`
	TypeName    string       `json:"type_name,omitempty"`

	FindingInfo *FindingInfo `json:"finding_info,omitempty"`
	Attacks     []Attack     `json:"attacks,omitempty"`
	Evidences   []Evidence   `json:"evidences,omitempty"`
	Resources   []Resource   `json:"resources,omitempty"`
	Cloud       *Cloud       `json:"cloud,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`

	Unmapped map[string]interface{} `json:"unmapped,omitempty"`
}

// Attack represents a MITRE ATT&CK technique reference.
type Attack struct {
	Tactic    *AttackTactic    `json:"tactic,omitempty"`
	Technique *AttackTechnique `json:"technique,omitempty"`
	Version   string           `json:"version,omitempty"`
}

// AttackTactic is a MITRE ATT&CK tactic.
type AttackTactic struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

// AttackTechnique is a MITRE ATT&CK technique.
type AttackTechnique struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

// Evidence represents supporting evidence for a detection finding.
type Evidence struct {
	Data json.RawMessage `json:"data,omitempty"`
}

// DataSecurityFinding represents OCSF class_uid 2006 — Data Security Finding.
type DataSecurityFinding struct {
	ActivityID  int32        `json:"activity_id"`
	CategoryUID int32        `json:"category_uid"`
	ClassUID    int32        `json:"class_uid"`
	Confidence  *int32       `json:"confidence,omitempty"`
	Count       *int32       `json:"count,omitempty"`
	Message     string       `json:"message,omitempty"`
	Metadata    Metadata     `json:"metadata"`
	Severity    string       `json:"severity,omitempty"`
	SeverityID  int32        `json:"severity_id"`
	Status      string       `json:"status,omitempty"`
	StatusID    int32        `json:"status_id,omitempty"`
	Time        *Time        `json:"time,omitempty"`
	TypeUID     int32        `json:"type_uid,omitempty"`
	TypeName    string       `json:"type_name,omitempty"`

	FindingInfo    *FindingInfo    `json:"finding_info,omitempty"`
	Resources      []Resource      `json:"resources,omitempty"`
	Cloud          *Cloud          `json:"cloud,omitempty"`
	DataSecurity   *DataSecurity   `json:"data_security,omitempty"`
	Remediation    *Remediation    `json:"remediation,omitempty"`

	Unmapped map[string]interface{} `json:"unmapped,omitempty"`
}

// DataSecurity describes data-security-specific attributes.
type DataSecurity struct {
	Classification string   `json:"classification,omitempty"`
	DataBucket     string   `json:"data_bucket,omitempty"`
	DataType       string   `json:"data_type,omitempty"`
	Status         string   `json:"status,omitempty"`
	Identifiers    []string `json:"identifiers,omitempty"`
}

// FindingEnvelope is a generic wrapper for deserializing any OCSF finding by class_uid.
type FindingEnvelope struct {
	ClassUID int32 `json:"class_uid"`
	Raw      json.RawMessage
}

// ParseFinding deserializes raw JSON into the appropriate OCSF finding struct.
func ParseFinding(data []byte) (interface{}, error) {
	var env FindingEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	switch env.ClassUID {
	case ClassSecurityFinding:
		var f SecurityFinding
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, err
		}
		return &f, nil
	case ClassVulnerabilityFind:
		var f VulnerabilityFinding
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, err
		}
		return &f, nil
	case ClassComplianceFinding:
		var f ComplianceFinding
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, err
		}
		return &f, nil
	case ClassDetectionFinding:
		var f DetectionFinding
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, err
		}
		return &f, nil
	case ClassDataSecurityFind:
		var f DataSecurityFinding
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, err
		}
		return &f, nil
	default:
		return nil, &ErrUnknownClassUID{ClassUID: env.ClassUID}
	}
}

// ErrUnknownClassUID is returned when an unsupported class_uid is encountered.
type ErrUnknownClassUID struct {
	ClassUID int32
}

func (e *ErrUnknownClassUID) Error() string {
	return "unknown OCSF class_uid: " + string(rune(e.ClassUID+'0'))
}
