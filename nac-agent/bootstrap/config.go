package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"eguard-nac-agent/lifecycle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
)

var invalid = errors.New("invalid bootstrap configuration")

// AntiTamper returns the signed selection; the zero value never selects OFF.
func (v Verified) AntiTamper() string {
	if v.antiTamper == "off" {
		return "off"
	}
	return "on"
}

type Verified struct {
	antiTamper   string
	reportVPN    bool    // signed server capability; default off
	inventory    [2]bool // collect_software, collect_user (signed; default off)
	binding      lifecycle.Binding
	revision     uint64
	origin, path string
	ca           []byte
	keys         map[string]ed25519.PublicKey
	fingerprint  [32]byte
	timing       [4]time.Duration
}

// CollectSoftware / CollectUser return the signed opt-in selections. Absent
// fields (older configs) mean off.
func (v Verified) ReportVPN() bool { return v.reportVPN }

func (v Verified) CollectSoftware() bool { return v.inventory[0] }
func (v Verified) CollectUser() bool     { return v.inventory[1] }

func (v Verified) Binding() lifecycle.Binding  { return v.binding }
func (v Verified) Revision() uint64            { return v.revision }
func (v Verified) Origin() string              { return v.origin }
func (v Verified) JournalPath() string         { return v.path }
func (v Verified) ServerCADER() []byte         { return bytes.Clone(v.ca) }
func (v Verified) MachineCertSHA256() [32]byte { return v.fingerprint }
func (v Verified) LifecycleKeys() map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for k, b := range v.keys {
		m[k] = bytes.Clone(b)
	}
	return m
}
func (v Verified) Timing() (time.Duration, time.Duration, time.Duration, time.Duration) {
	return v.timing[0], v.timing[1], v.timing[2], v.timing[3]
}

// strictValue rejects duplicate keys, nulls and excess nesting before decoding.
func strictValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return invalid
	}
	t, e := d.Token()
	if e != nil || t == nil {
		return invalid
	}
	if delim, ok := t.(json.Delim); ok {
		if delim != '{' {
			return invalid
		}
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			s, ok := k.(string)
			if e != nil || !ok || seen[s] {
				return invalid
			}
			seen[s] = true
			if strictValue(d, depth+1) != nil {
				return invalid
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return invalid
		}
	}
	return nil
}
func object(raw []byte, names string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if strictValue(d, 0) != nil {
		return nil, invalid
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, invalid
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, invalid
	}
	if names != "" {
		fields := strings.Fields(names)
		if len(m) != len(fields) {
			return nil, invalid
		}
		for _, k := range fields {
			if _, ok := m[k]; !ok {
				return nil, invalid
			}
		}
	}
	return m, nil
}
func text(m map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(m[k], &s)
	return s
}
func number(m map[string]json.RawMessage, k string) uint64 {
	var n uint64
	_ = json.Unmarshal(m[k], &n)
	return n
}
func b64(s string) []byte {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil
	}
	return b
}
func Verify(raw []byte, pin ed25519.PublicKey, b lifecycle.Binding, floor uint64, path string) (Verified, error) {
	bad := Verified{}
	if len(raw) > 256*1024 || len(pin) != ed25519.PublicKeySize || floor == 0 {
		return bad, invalid
	}
	// Path supplied by an independently trusted installation; lexical check only,
	// not proof of ACLs, reparse-point safety, or filesystem ownership.
	if !validJournalPath(path) {
		return bad, invalid
	}
	env, e := object(raw, "version payload_b64 signature_b64")
	if e != nil || number(env, "version") != 1 {
		return bad, invalid
	}
	payload := b64(text(env, "payload_b64"))
	sig := b64(text(env, "signature_b64"))
	if len(payload) == 0 || len(payload) > 65536 || len(sig) != 64 || !ed25519.Verify(pin, append([]byte("eguard-nac-boot-config/v1\x00"), payload...), sig) {
		return bad, invalid
	}
	fields := "version purpose issuer device_id tenant_id site_id enrollment_id revision https_origin server_ca_der_b64 lifecycle_keys machine_cert_sha256 journal_path interval_seconds backoff_seconds collect_timeout_seconds send_timeout_seconds"
	parsed, err := object(payload, "")
	if err != nil {
		return bad, invalid
	}
	mode := "on" // Legacy signed v1 configs retain protection.
	if _, present := parsed["anti_tamper"]; present {
		fields += " anti_tamper"
		mode = text(parsed, "anti_tamper")
		if mode != "on" && mode != "off" {
			return bad, invalid
		}
	}
	reportVPN := false
	if _, present := parsed["report_vpn"]; present {
		fields += " report_vpn"
		switch text(parsed, "report_vpn") {
		case "on":
			reportVPN = true
		case "off":
		default:
			return bad, invalid
		}
	}
	var inventory [2]bool
	for i, k := range []string{"collect_software", "collect_user"} {
		if _, present := parsed[k]; present {
			fields += " " + k
			switch text(parsed, k) {
			case "on":
				inventory[i] = true
			case "off":
			default:
				return bad, invalid
			}
		}
	}
	m, e := object(payload, fields)
	if e != nil || number(m, "version") != 1 || text(m, "purpose") != "eguard-nac-boot-config" {
		return bad, invalid
	}
	for k, want := range map[string]string{"issuer": b.Issuer, "device_id": b.DeviceID, "tenant_id": b.TenantID, "site_id": b.SiteID, "enrollment_id": b.EnrollmentID} {
		if want == "" || len(want) > 128 || text(m, k) != want {
			return bad, invalid
		}
	}
	v := Verified{reportVPN: reportVPN, antiTamper: mode, inventory: inventory, binding: b, revision: number(m, "revision"), origin: text(m, "https_origin"), path: text(m, "journal_path"), ca: b64(text(m, "server_ca_der_b64")), keys: map[string]ed25519.PublicKey{}}
	if v.revision < floor || v.path != path {
		return bad, invalid
	}
	u, e := url.Parse(v.origin)
	if e != nil || !validOriginHost(u) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return bad, invalid
	}
	ca, e := x509.ParseCertificate(v.ca)
	if e != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return bad, invalid
	}
	keys, e := object(m["lifecycle_keys"], "")
	if e != nil || len(keys) == 0 || len(keys) > 16 {
		return bad, invalid
	}
	for k := range keys {
		p := b64(text(keys, k))
		if len(k) == 0 || len(k) > 128 || len(p) != 32 {
			return bad, invalid
		}
		v.keys[k] = p
	}
	s := text(m, "machine_cert_sha256")
	fp, e := hex.DecodeString(s)
	if e != nil || len(fp) != 32 || hex.EncodeToString(fp) != s {
		return bad, invalid
	}
	copy(v.fingerprint[:], fp)
	if v.fingerprint == [32]byte{} {
		return bad, invalid
	}
	for i, k := range []string{"interval_seconds", "backoff_seconds", "collect_timeout_seconds", "send_timeout_seconds"} {
		n := number(m, k)
		max := uint64(3600)
		if i >= 2 {
			max = 60
		}
		if n == 0 || n > max {
			return bad, invalid
		}
		v.timing[i] = time.Duration(n) * time.Second
	}
	return v, nil
}
