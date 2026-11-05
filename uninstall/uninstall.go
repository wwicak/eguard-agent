// Package uninstall is the admin-initiated uninstall flow. Its behaviour depends on
// the SIGNED anti_tamper selection from the verified bootstrap (never a local flag):
//
//   - on:  a signed, device-bound authorize_uninstall grant (≤600s, single-use via
//     the lifecycle journal) is required before ANY side effect.
//   - off: an elevated local administrator may uninstall without server
//     authorization. A supplied authorization must still be valid.
//
// Temporary-expiry cleanup does not go through here: it is performed by the service
// itself from signed state and is never blocked by anti-tamper.
package uninstall

import (
	"crypto/ed25519"
	"errors"
	"time"

	"eguard-nac-agent/lifecycle"
)

type Config struct {
	AntiTamper  string // "on" | "off" from the verified signed bootstrap
	Keys        map[string]ed25519.PublicKey
	Binding     lifecycle.Binding
	MachineCert [32]byte
}

type Adapter interface {
	Config() (Config, error)
	StopService() error
	// Handoff gives a pre-verified authorization to the running protected
	// service, which records it in its journal (replay/sequence rules) and runs
	// official cleanup. Returns the service's verdict.
	Handoff(raw []byte) error
	Cleanup(machineCert [32]byte) error
}

var (
	ErrAuthorization = errors.New("valid signed uninstall authorization required")
	ErrMode          = errors.New("anti-tamper mode unknown")
)

func verify(c Config, raw []byte, now time.Time) error {
	g, e := lifecycle.VerifyEnvelope(raw, c.Keys, c.Binding)
	if e != nil || g.Action != "authorize_uninstall" || lifecycle.ValidateAcceptance(g, now.Unix()) != nil {
		return ErrAuthorization
	}
	return nil
}

func Run(a Adapter, authorization []byte, now time.Time) error {
	if a == nil {
		return ErrMode
	}
	c, e := a.Config()
	if e != nil {
		return e
	}
	switch c.AntiTamper {
	case "off":
		if authorization != nil {
			if e := verify(c, authorization, now); e != nil {
				return e
			}
		}
		if e := a.StopService(); e != nil {
			return e
		}
		return a.Cleanup(c.MachineCert)
	case "on":
		if authorization == nil {
			return ErrAuthorization
		}
		if e := verify(c, authorization, now); e != nil {
			return e
		}
		return a.Handoff(authorization)
	default:
		return ErrMode
	}
}
