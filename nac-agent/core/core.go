// Package core contains NAC-only evidence normalization and signed lifecycle decisions.
package core

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

type Tri string

const (
	Unknown Tri = "unknown"
	Yes     Tri = "yes"
	No      Tri = "no"
)

type Evidence struct {
	Value  Tri    `json:"value"`
	Source string `json:"source"`
	Error  string `json:"error,omitempty"`
}
type DomainEvidence struct {
	PartOfDomain Tri    `json:"part_of_domain"`
	Match        Tri    `json:"match"`
	Domain       string `json:"domain,omitempty"`
	Source       string `json:"source,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (d DomainEvidence) Result() Tri {
	if d.PartOfDomain == No || (d.PartOfDomain == Yes && d.Match == No) {
		return No
	}
	if d.PartOfDomain == Yes && d.Match == Yes {
		return Yes
	}
	return Unknown
}

type AVEvidence struct {
	Installed Tri                 `json:"installed"`
	Running   Tri                 `json:"running"`
	Updated   Tri                 `json:"updated"`
	Products  []AVProductEvidence `json:"products,omitempty"`
	// Vendors: per-product facts from the same reviewed vendor rules the
	// eGuard WinRM/DCOM collectors run (avvendor), read locally. Active is
	// enabled|disabled|absent; the signature date is only set when the
	// vendor rule could read it.
	Vendors []AVVendorEvidence `json:"vendors,omitempty"`
	Source  string             `json:"source,omitempty"`
	Error   string             `json:"error,omitempty"`
}
type AVVendorEvidence struct {
	ID                   string     `json:"id"`
	Active               string     `json:"active"`
	SignatureLastUpdated *time.Time `json:"signature_last_updated,omitempty"`
}

// MaxAVVendors bounds the per-vendor list (one entry per reviewed rule).
const MaxAVVendors = 64

type AVProductEvidence struct {
	Name   string `json:"name"`
	State  uint32 `json:"security_center_state"`
	Source string `json:"source"`
}

func (a AVEvidence) Result() Tri {
	if a.Installed == No || a.Running == No || a.Updated == No {
		return No
	}
	if a.Installed == Yes && a.Running == Yes && a.Updated == Yes {
		return Yes
	}
	return Unknown
}

type Adapter struct {
	Primary     bool     `json:"primary,omitempty"`
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	Addresses   []string `json:"addresses"`
	Kind        string   `json:"kind"`
	KindSource  string   `json:"kind_source,omitempty"`
	ActiveRoute bool     `json:"active_route"` // legacy hint; false is never proof of no route
	RouteStatus Tri      `json:"route_status"`
	RouteSource string   `json:"route_source,omitempty"`
}
type DeviceEvidence struct {
	SecureBoot    Evidence `json:"secure_boot"`
	BitlockerOS   Evidence `json:"bitlocker_os"`
	PendingReboot Evidence `json:"pending_reboot"`
	FreeDiskBytes *uint64  `json:"free_disk_bytes"`
}
type DefenderEvidence struct {
	Realtime          Evidence `json:"realtime"`
	SignatureAgeHours *uint32  `json:"signature_age_hours"`
}
type VPNEvidence struct {
	Connected Tri      `json:"connected"`
	Products  []string `json:"products,omitempty"`
	Source    string   `json:"source"`
	Error     string   `json:"error,omitempty"`
}

type Posture struct {
	VPN        *VPNEvidence        `json:"vpn,omitempty"`
	Hostname   string              `json:"hostname,omitempty"`
	Device     *DeviceEvidence     `json:"device,omitempty"`
	Defender   *DefenderEvidence   `json:"defender,omitempty"`
	AgentType  string              `json:"agent_type"`
	Domain     DomainEvidence      `json:"domain"`
	AV         AVEvidence          `json:"av"`
	Firewall   map[string]Evidence `json:"firewall"`
	Adapters   []Adapter           `json:"adapters"`
	OS         string              `json:"os"`
	ObservedAt time.Time           `json:"observed_at"`
	TTL        time.Duration       `json:"ttl"`
	Errors     []string            `json:"errors,omitempty"`
}

func (p Posture) Fresh(now time.Time) bool {
	return p.TTL > 0 && !now.Before(p.ObservedAt) && !now.After(p.ObservedAt.Add(p.TTL))
}

type Mode string

const (
	Temporary Mode = "temporary"
	Permanent Mode = "permanent"
)

type Session string

const (
	Pending        Session = "pending"
	Active         Session = "active"
	Expired        Session = "expired"
	CleanupPending Session = "cleanup_pending"
)

type Grant struct {
	DeviceID    string `json:"device_id"`
	Tenant      string `json:"tenant"`
	Site        string `json:"site"`
	Revision    uint64 `json:"revision"`
	Mode        Mode   `json:"mode"`
	ActivatedAt int64  `json:"activated_at"`
	ExpiresAt   int64  `json:"expires_at"`
	Action      string `json:"action"`
	Nonce       string `json:"nonce"`
}
type SignedGrant struct {
	Grant     Grant  `json:"grant"`
	Signature []byte `json:"signature"`
}
type State struct {
	DeviceID    string          `json:"device_id"`
	Tenant      string          `json:"tenant"`
	Site        string          `json:"site"`
	Revision    uint64          `json:"revision"`
	Mode        Mode            `json:"mode"`
	ActivatedAt int64           `json:"activated_at"`
	ExpiresAt   int64           `json:"expires_at"`
	Cleanup     bool            `json:"cleanup"`
	Nonces      map[string]bool `json:"nonces"`
}

func (s *State) Apply(key ed25519.PublicKey, signed SignedGrant, now int64) error {
	g := signed.Grant
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, b, signed.Signature) {
		return errors.New("invalid grant signature")
	}
	if g.DeviceID == "" || g.DeviceID != s.DeviceID || g.Tenant == "" || g.Site == "" || (s.Tenant != "" && s.Tenant != g.Tenant) || (s.Site != "" && s.Site != g.Site) {
		return errors.New("device or assignment mismatch")
	}
	if g.Revision <= s.Revision || g.Nonce == "" || s.Nonces[g.Nonce] {
		return errors.New("stale revision or replay")
	}
	switch g.Action {
	case "activate":
		if g.ActivatedAt <= 0 || g.ActivatedAt > now || (g.Mode != Temporary && g.Mode != Permanent) || (g.Mode == Temporary && g.ExpiresAt <= g.ActivatedAt) || (g.Mode == Permanent && g.ExpiresAt != 0) {
			return errors.New("invalid lifecycle grant")
		}
		if s.Cleanup {
			return errors.New("cleanup already authorized")
		}
		s.Mode = g.Mode
		s.ActivatedAt = g.ActivatedAt
		s.ExpiresAt = g.ExpiresAt
	case "uninstall":
		if s.Mode == "" || g.Mode != s.Mode || g.ExpiresAt <= now || g.ExpiresAt > now+600 || g.ActivatedAt > now {
			return errors.New("invalid uninstall authorization")
		}
		s.Cleanup = true
	default:
		return errors.New("unsupported action")
	}
	s.Tenant = g.Tenant
	s.Site = g.Site
	s.Revision = g.Revision
	if s.Nonces == nil {
		s.Nonces = make(map[string]bool)
	}
	s.Nonces[g.Nonce] = true
	return nil
}
func (s State) Session(now int64) Session {
	if s.Cleanup {
		return CleanupPending
	}
	if s.Mode == "" {
		return Pending
	}
	if s.Mode == Temporary && now >= s.ExpiresAt {
		return Expired
	}
	return Active
}
