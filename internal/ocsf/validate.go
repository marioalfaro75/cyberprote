package ocsf

import (
	"fmt"
	"strings"
)

// ValidationError collects multiple validation failures.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return "OCSF validation failed: " + strings.Join(e.Errors, "; ")
}

// HasErrors returns true if validation failures exist.
func (e *ValidationError) HasErrors() bool {
	return len(e.Errors) > 0
}

func (e *ValidationError) add(msg string) {
	e.Errors = append(e.Errors, msg)
}

func (e *ValidationError) addf(format string, args ...interface{}) {
	e.Errors = append(e.Errors, fmt.Sprintf(format, args...))
}

func validSeverityID(id int32) bool {
	switch id {
	case SeverityUnknown, SeverityInformational, SeverityLow, SeverityMedium,
		SeverityHigh, SeverityCritical, SeverityFatal, SeverityOther:
		return true
	}
	return false
}

// ValidateSecurityFinding validates a SecurityFinding against OCSF requirements.
func ValidateSecurityFinding(f *SecurityFinding) error {
	ve := &ValidationError{}
	if f.ClassUID != ClassSecurityFinding {
		ve.addf("class_uid must be %d, got %d", ClassSecurityFinding, f.ClassUID)
	}
	if f.ActivityID == 0 {
		ve.add("activity_id is required")
	}
	if !validSeverityID(f.SeverityID) {
		ve.addf("severity_id %d is not a valid OCSF severity", f.SeverityID)
	}
	if f.Metadata.Product == nil {
		ve.add("metadata.product is required")
	}
	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ValidateVulnerabilityFinding validates a VulnerabilityFinding.
func ValidateVulnerabilityFinding(f *VulnerabilityFinding) error {
	ve := &ValidationError{}
	if f.ClassUID != ClassVulnerabilityFind {
		ve.addf("class_uid must be %d, got %d", ClassVulnerabilityFind, f.ClassUID)
	}
	if f.ActivityID == 0 {
		ve.add("activity_id is required")
	}
	if !validSeverityID(f.SeverityID) {
		ve.addf("severity_id %d is not a valid OCSF severity", f.SeverityID)
	}
	if f.Metadata.Product == nil {
		ve.add("metadata.product is required")
	}
	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ValidateComplianceFinding validates a ComplianceFinding.
func ValidateComplianceFinding(f *ComplianceFinding) error {
	ve := &ValidationError{}
	if f.ClassUID != ClassComplianceFinding {
		ve.addf("class_uid must be %d, got %d", ClassComplianceFinding, f.ClassUID)
	}
	if f.ActivityID == 0 {
		ve.add("activity_id is required")
	}
	if !validSeverityID(f.SeverityID) {
		ve.addf("severity_id %d is not a valid OCSF severity", f.SeverityID)
	}
	if f.Metadata.Product == nil {
		ve.add("metadata.product is required")
	}
	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ValidateDetectionFinding validates a DetectionFinding.
func ValidateDetectionFinding(f *DetectionFinding) error {
	ve := &ValidationError{}
	if f.ClassUID != ClassDetectionFinding {
		ve.addf("class_uid must be %d, got %d", ClassDetectionFinding, f.ClassUID)
	}
	if f.ActivityID == 0 {
		ve.add("activity_id is required")
	}
	if !validSeverityID(f.SeverityID) {
		ve.addf("severity_id %d is not a valid OCSF severity", f.SeverityID)
	}
	if f.Metadata.Product == nil {
		ve.add("metadata.product is required")
	}
	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ValidateDataSecurityFinding validates a DataSecurityFinding.
func ValidateDataSecurityFinding(f *DataSecurityFinding) error {
	ve := &ValidationError{}
	if f.ClassUID != ClassDataSecurityFind {
		ve.addf("class_uid must be %d, got %d", ClassDataSecurityFind, f.ClassUID)
	}
	if f.ActivityID == 0 {
		ve.add("activity_id is required")
	}
	if !validSeverityID(f.SeverityID) {
		ve.addf("severity_id %d is not a valid OCSF severity", f.SeverityID)
	}
	if f.Metadata.Product == nil {
		ve.add("metadata.product is required")
	}
	if ve.HasErrors() {
		return ve
	}
	return nil
}

// Validate validates any OCSF finding (after ParseFinding).
func Validate(finding interface{}) error {
	switch f := finding.(type) {
	case *SecurityFinding:
		return ValidateSecurityFinding(f)
	case *VulnerabilityFinding:
		return ValidateVulnerabilityFinding(f)
	case *ComplianceFinding:
		return ValidateComplianceFinding(f)
	case *DetectionFinding:
		return ValidateDetectionFinding(f)
	case *DataSecurityFinding:
		return ValidateDataSecurityFinding(f)
	default:
		return fmt.Errorf("unsupported finding type: %T", finding)
	}
}
