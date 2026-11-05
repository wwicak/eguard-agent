package bootstrap

import (
	"bytes"
	"testing"
)

func TestSignedInventorySelection(t *testing.T) {
	f := newBootFixture(t)
	v, e := verify(f, f.payload())
	if e != nil || v.CollectSoftware() || v.CollectUser() {
		t.Fatalf("absent fields must mean off: %v", e)
	}
	p := bytes.Replace(f.payload(), []byte(`"version":1`), []byte(`"collect_software":"on","collect_user":"off","version":1`), 1)
	v, e = verify(f, p)
	if e != nil || !v.CollectSoftware() || v.CollectUser() {
		t.Fatalf("software on / user off: %v", e)
	}
	for _, bad := range []string{`"collect_user":true`, `"collect_user":"ON"`, `"collect_software":null`, `"collect_software":""`} {
		reject(t, f, bytes.Replace(f.payload(), []byte(`"version":1`), []byte(bad+`,"version":1`), 1))
	}
}
