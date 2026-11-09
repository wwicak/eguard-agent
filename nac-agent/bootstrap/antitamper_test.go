package bootstrap

import (
	"bytes"
	"testing"
)

func TestSignedAntiTamperSelection(t *testing.T) {
	f := newBootFixture(t)
	for _, mode := range []string{"on", "off"} {
		t.Run(mode, func(t *testing.T) {
			p := bytes.Replace(f.payload(), []byte(`"version":1`), []byte(`"anti_tamper":"`+mode+`","version":1`), 1)
			v, e := verify(f, p)
			if e != nil {
				t.Fatal(e)
			}
			getter, ok := any(v).(interface{ AntiTamper() string })
			if !ok || getter.AntiTamper() != mode {
				t.Fatal("missing verified selection")
			}
		})
	}
	for _, value := range []string{`null`, `false`, `0`, `"OFF"`, `""`, `{}`} {
		p := bytes.Replace(f.payload(), []byte(`"version":1`), []byte(`"anti_tamper":`+value+`,"version":1`), 1)
		reject(t, f, p)
	}
	v, e := verify(f, f.payload())
	if e != nil {
		t.Fatal(e)
	}
	getter, ok := any(v).(interface{ AntiTamper() string })
	if !ok || getter.AntiTamper() != "on" {
		t.Fatal("legacy config must not disable protection")
	}
}
