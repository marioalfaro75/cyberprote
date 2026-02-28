package threatintel

// CWEToAttackTechniques maps common CWE IDs to ATT&CK technique UIDs.
// Based on MITRE CWE → ATT&CK Navigator mappings for the ~30 most common CWEs.
var CWEToAttackTechniques = map[string][]string{
	// Injection flaws
	"CWE-89":  {"T1190"},          // SQL Injection → Exploit Public-Facing Application
	"CWE-78":  {"T1059"},          // OS Command Injection → Command and Scripting Interpreter
	"CWE-77":  {"T1059"},          // Command Injection → Command and Scripting Interpreter
	"CWE-94":  {"T1059"},          // Code Injection → Command and Scripting Interpreter
	"CWE-79":  {"T1189"},          // XSS → Drive-by Compromise
	"CWE-611": {"T1190"},          // XXE → Exploit Public-Facing Application
	"CWE-917": {"T1190"},          // Expression Language Injection → Exploit Public-Facing Application
	"CWE-502": {"T1190", "T1059"}, // Deserialization → Exploit Public-Facing + Command Interpreter

	// Authentication & access control
	"CWE-287":  {"T1078"},          // Improper Authentication → Valid Accounts
	"CWE-306":  {"T1078"},          // Missing Authentication → Valid Accounts
	"CWE-862":  {"T1548"},          // Missing Authorization → Abuse Elevation Control
	"CWE-863":  {"T1548"},          // Incorrect Authorization → Abuse Elevation Control
	"CWE-269":  {"T1068"},          // Improper Privilege Management → Exploitation for Privilege Escalation
	"CWE-522":  {"T1110", "T1552"}, // Insufficiently Protected Credentials → Brute Force + Unsecured Credentials
	"CWE-798":  {"T1552"},          // Hard-coded Credentials → Unsecured Credentials
	"CWE-640":  {"T1078"},          // Weak Password Recovery → Valid Accounts
	"CWE-307":  {"T1110"},          // Improper Restriction of Auth Attempts → Brute Force
	"CWE-1391": {"T1552"},          // Use of Weak Credentials → Unsecured Credentials

	// Cryptographic issues
	"CWE-327": {"T1573"}, // Broken Crypto Algorithm → Encrypted Channel (defensive context)
	"CWE-330": {"T1110"}, // Insufficient Randomness → Brute Force
	"CWE-295": {"T1557"}, // Improper Certificate Validation → (Adversary-in-the-Middle approx)

	// Memory safety
	"CWE-120": {"T1203"}, // Buffer Overflow → Exploitation for Client Execution
	"CWE-787": {"T1203"}, // Out-of-bounds Write → Exploitation for Client Execution
	"CWE-416": {"T1203"}, // Use After Free → Exploitation for Client Execution
	"CWE-125": {"T1005"}, // Out-of-bounds Read → Data from Local System

	// Information exposure
	"CWE-200": {"T1005"},          // Information Exposure → Data from Local System
	"CWE-532": {"T1552"},          // Log File Info Exposure → Unsecured Credentials
	"CWE-312": {"T1552"},          // Cleartext Storage of Sensitive Data → Unsecured Credentials
	"CWE-319": {"T1040"},          // Cleartext Transmission → Network Sniffing (approx)
	"CWE-918": {"T1190", "T1530"}, // SSRF → Exploit Public-Facing Application + Data from Cloud Storage

	// Path/file issues
	"CWE-22":  {"T1005"}, // Path Traversal → Data from Local System
	"CWE-434": {"T1190"}, // Unrestricted Upload → Exploit Public-Facing Application
}
