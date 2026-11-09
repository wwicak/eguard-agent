package core

import "time"

// Inventory is optional, operator-enabled device inventory, sent separately
// from posture and never used for access decisions. Software is read from the
// Windows uninstall registry (what "Apps & features" lists); User is the name
// of the account signed in at the console, not activity or history.
type Inventory struct {
	AgentType         string         `json:"agent_type"`
	ObservedAt        time.Time      `json:"observed_at"`
	UpdatesCollected  bool           `json:"updates_collected"`
	Updates           []UpdateItem   `json:"updates"`
	ServicesCollected bool           `json:"services_collected"`
	Services          []ServiceItem  `json:"services"`
	SoftwareCollected bool           `json:"software_collected"`
	Software          []SoftwareItem `json:"software"`
	SoftwareTruncated bool           `json:"software_truncated"`
	UserCollected     bool           `json:"user_collected"`
	User              string         `json:"user"`
	Errors            []string       `json:"errors"`
}

type UpdateItem struct {
	ID          string `json:"id"`
	InstalledOn string `json:"installed_on"`
	Description string `json:"description"`
}
type ServiceItem struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	StartMode   string `json:"start_mode"`
}
type SoftwareItem struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
}

// Inventory bounds shared by collector, boundary and transport.
const (
	MaxSoftwareItems = 800
	MaxInventoryText = 128
	// MaxInventoryBytes bounds the serialized inventory (collector output,
	// transport body and server ingress).
	MaxInventoryBytes = 512 * 1024
)
