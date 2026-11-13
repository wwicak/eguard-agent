package bootstrap

import (
	"bytes"
	"testing"
)

func TestSignedVPNSelection(t *testing.T) {
	f := newBootFixture(t)
	v, e := verify(f, f.payload())
	if e != nil || v.ReportVPN() {
		t.Fatalf("default off: %v", e)
	}
	for _, s := range []string{"on", "off"} {
		p := bytes.Replace(f.payload(), []byte(`"version":1`), []byte(`"report_vpn":"`+s+`","version":1`), 1)
		v, e = verify(f, p)
		if e != nil || v.ReportVPN() != (s == "on") {
			t.Fatalf("%s: %v", s, e)
		}
	}
	for _, bad := range []string{`true`, `null`, `"ON"`, `""`} {
		reject(t, f, bytes.Replace(f.payload(), []byte(`"version":1`), []byte(`"report_vpn":`+bad+`,"version":1`), 1))
	}
}
