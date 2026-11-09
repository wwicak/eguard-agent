package uninstall

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"eguard-nac-agent/lifecycle"
)

var b = lifecycle.Binding{Issuer: "iss", DeviceID: "dev", TenantID: "ten", SiteID: "site", EnrollmentID: "enr"}

type fake struct {
	cfg       Config
	ops       []string
	acceptErr error
}

func (f *fake) Config() (Config, error)   { return f.cfg, nil }
func (f *fake) op(s string) error         { f.ops = append(f.ops, s); return nil }
func (f *fake) StopService() error        { return f.op("stop") }
func (f *fake) Cleanup(fp [32]byte) error { return f.op("cleanup") }
func (f *fake) Handoff(raw []byte) error {
	f.ops = append(f.ops, "handoff")
	return f.acceptErr
}

func keys(t *testing.T) (map[string]ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return map[string]ed25519.PublicKey{"k1": pub}, priv
}

func grant(priv ed25519.PrivateKey, action, device string, issued, until int64) []byte {
	p := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":"iss","device_id":%q,"tenant_id":"ten","site_id":"site","enrollment_id":"enr","grant_id":"g1","revision":2,"policy_revision":1,"action":%q,"mode":"permanent","issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":null}`, device, action, issued, issued, until, issued-100))
	sig := ed25519.Sign(priv, append([]byte("eguard-nac-lifecycle/v1\x00"), p...))
	return []byte(fmt.Sprintf(`{"version":1,"key_id":"k1","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
}

func TestOnRequiresValidAuthorizationBeforeAnySideEffect(t *testing.T) {
	k, priv := keys(t)
	_, other := keys(t)
	now := time.Unix(1_800_000_000, 0)
	n := now.Unix()
	for name, auth := range map[string][]byte{
		"missing":       nil,
		"wrong signer":  grant(other, "authorize_uninstall", "dev", n-1, n+300),
		"other device":  grant(priv, "authorize_uninstall", "other", n-1, n+300),
		"not uninstall": grant(priv, "renew", "dev", n-1, n+300),
		"expired":       grant(priv, "authorize_uninstall", "dev", n-400, n-100),
		"too long":      grant(priv, "authorize_uninstall", "dev", n-1, n+3600),
	} {
		t.Run(name, func(t *testing.T) {
			f := &fake{cfg: Config{AntiTamper: "on", Keys: k, Binding: b}}
			if e := Run(f, auth, now); e == nil {
				t.Fatal("accepted")
			}
			if len(f.ops) != 0 {
				t.Fatalf("side effects before authorization: %v", f.ops)
			}
		})
	}
}

func TestOnValidAuthorizationFlow(t *testing.T) {
	k, priv := keys(t)
	now := time.Unix(1_800_000_000, 0)
	f := &fake{cfg: Config{AntiTamper: "on", Keys: k, Binding: b}}
	if e := Run(f, grant(priv, "authorize_uninstall", "dev", now.Unix()-1, now.Unix()+300), now); e != nil {
		t.Fatal(e)
	}
	// ON: the protected service (SYSTEM) performs journal acceptance + cleanup;
	// the admin process never stops it or edits its DACL.
	want := []string{"handoff"}
	if !reflect.DeepEqual(f.ops, want) {
		t.Fatalf("%v", f.ops)
	}
}

// The service's verdict (e.g. replay rejected by the journal) is returned as-is
// and nothing else is done by the admin process.
func TestOnServiceRejectionReported(t *testing.T) {
	k, priv := keys(t)
	now := time.Unix(1_800_000_000, 0)
	replay := errors.New("replayed")
	f := &fake{cfg: Config{AntiTamper: "on", Keys: k, Binding: b}, acceptErr: replay}
	if e := Run(f, grant(priv, "authorize_uninstall", "dev", now.Unix()-1, now.Unix()+300), now); !errors.Is(e, replay) {
		t.Fatalf("%v", e)
	}
	want := []string{"handoff"}
	if !reflect.DeepEqual(f.ops, want) {
		t.Fatalf("%v", f.ops)
	}
}

// OFF: elevated local admin may uninstall without server authorization.
func TestOffAllowsAdminUninstallWithoutAuthorization(t *testing.T) {
	k, _ := keys(t)
	f := &fake{cfg: Config{AntiTamper: "off", Keys: k, Binding: b}}
	if e := Run(f, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	want := []string{"stop", "cleanup"}
	if !reflect.DeepEqual(f.ops, want) {
		t.Fatalf("%v", f.ops)
	}
}

// OFF still never accepts a forged authorization when one is supplied.
func TestOffRejectsInvalidSuppliedAuthorization(t *testing.T) {
	k, _ := keys(t)
	_, other := keys(t)
	f := &fake{cfg: Config{AntiTamper: "off", Keys: k, Binding: b}}
	if e := Run(f, grant(other, "authorize_uninstall", "dev", 1, 2), time.Now()); e == nil || len(f.ops) != 0 {
		t.Fatalf("e=%v ops=%v", e, f.ops)
	}
}

func TestUnknownProtectionModeRefused(t *testing.T) {
	k, _ := keys(t)
	f := &fake{cfg: Config{AntiTamper: "", Keys: k, Binding: b}}
	if Run(f, nil, time.Now()) == nil || len(f.ops) != 0 {
		t.Fatal("empty mode treated as OFF")
	}
}
