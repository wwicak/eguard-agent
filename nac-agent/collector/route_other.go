//go:build !linux && !darwin

package collector

import "eguard-nac-agent/core"

func acquireDefaultRoute(p *core.Posture) {}
