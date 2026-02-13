package server

import "strings"

// Security event IDs (defined in conf/security_events.conf).
const (
	EventMalwareDetected     = 1300010
	EventSuspiciousBehavior  = 1300011
	EventUnauthorizedModule  = 1300012
	EventC2Communication     = 1300013
	EventComplianceFail      = 1300014
	EventAgentTamper         = 1300015
	EventLateralMovement     = 1300016
	EventPrivilegeEscalation = 1300017
)

type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type AlertEvent struct {
	RuleType        string
	RuleName        string
	Severity        Severity
	MITRETechniques []string
	Description     string
}

// Local placeholder for this workspace; production code wires this to the real package.
var security_event = struct {
	Trigger func(mac string, eventID int, description string) error
}{
	Trigger: func(string, int, string) error { return nil },
}

// BridgeAlertToSecurityEvent translates an agent alert into an eGuard
// security event for NAC enforcement.
func BridgeAlertToSecurityEvent(alert *AlertEvent, mac string) error {
	eventID := mapAlertToSecurityEvent(alert)
	if eventID == 0 {
		return nil // Not all alerts trigger NAC events.
	}

	return security_event.Trigger(mac, eventID, alert.Description)
}

func mapAlertToSecurityEvent(alert *AlertEvent) int {
	switch {
	case strings.EqualFold(alert.RuleType, "yara") && alert.Severity >= SeverityHigh:
		return EventMalwareDetected
	case strings.EqualFold(alert.RuleName, "unauthorized_kernel_module"):
		return EventUnauthorizedModule
	case strings.EqualFold(alert.RuleType, "ioc") && containsAny(alert.MITRETechniques, "T1071"):
		return EventC2Communication
	case strings.EqualFold(alert.RuleName, "compliance_failed"):
		return EventComplianceFail
	case strings.EqualFold(alert.RuleName, "agent_tamper"):
		return EventAgentTamper
	case strings.EqualFold(alert.RuleType, "sigma") && alert.Severity >= SeverityHigh:
		return EventSuspiciousBehavior
	case containsAny(alert.MITRETechniques, "T1021", "T1534"):
		return EventLateralMovement
	case containsAny(alert.MITRETechniques, "T1548", "T1068"):
		return EventPrivilegeEscalation
	default:
		return 0
	}
}

func containsAny(have []string, needles ...string) bool {
	for _, tech := range have {
		for _, needle := range needles {
			if strings.EqualFold(tech, needle) {
				return true
			}
		}
	}
	return false
}
