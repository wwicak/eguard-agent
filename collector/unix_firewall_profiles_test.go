//go:build linux || darwin

package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"eguard-nac-agent/core"
)

// The service boundary and the server policy accept exactly the three
// firewall profiles. Unix host firewalls are profile-less, so one host
// observation must be reported for every profile (never as extra keys).
func TestUnixPostureFirewallUsesPolicyProfiles(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		posture func(UnixProvider) core.Posture
		cmd     string
		out     string
		want    core.Tri
	}{
		"linux-nft":   {func(u UnixProvider) core.Posture { return u.LinuxPosture(context.Background(), "") }, "/usr/sbin/nft list ruleset", "table inet filter { }", core.Yes},
		"linux-none":  {func(u UnixProvider) core.Posture { return u.LinuxPosture(context.Background(), "") }, "", "", core.Unknown},
		"mac-on":      {func(u UnixProvider) core.Posture { return u.MacPosture(context.Background(), "") }, "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "Firewall is enabled. (State = 1)", core.Yes},
		"mac-off":     {func(u UnixProvider) core.Posture { return u.MacPosture(context.Background(), "") }, "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "Firewall is disabled. (State = 0)", core.No},
		"mac-unknown": {func(u UnixProvider) core.Posture { return u.MacPosture(context.Background(), "") }, "", "", core.Unknown},
	} {
		t.Run(name, func(t *testing.T) {
			u := UnixProvider{Root: t.TempDir(), Now: func() time.Time { return now }, Run: func(_ context.Context, n string, a ...string) ([]byte, error) {
				key := n
				for _, x := range a {
					key += " " + x
				}
				if tc.cmd != "" && key == tc.cmd {
					return []byte(tc.out), nil
				}
				if key == "/usr/sbin/spctl --status" {
					return []byte("assessments enabled"), nil
				}
				return nil, errors.New("unavailable")
			}}
			p := tc.posture(u)
			if len(p.Firewall) != 3 {
				t.Fatalf("firewall keys %v", p.Firewall)
			}
			for _, profile := range []string{"domain", "private", "public"} {
				e, ok := p.Firewall[profile]
				if !ok || e.Value != tc.want || e.Source == "" {
					t.Fatalf("%s: %+v", profile, e)
				}
			}
		})
	}
}
