package upgrade

import "testing"

func TestVersions(t *testing.T) {
	for _, x := range []struct {
		old, next     string
		reinstall, ok bool
	}{
		{"1.2.3", "1.2.4", false, true}, {"1.2.3", "1.2.3", false, false}, {"1.2.3", "1.2.3", true, true}, {"2.0.0", "1.0.0", true, false}, {"unknown", "0.1.0", false, true}, {"0.0.0-dev", "0.1.0", false, true}, {"1.0.0", "garbage", false, false}, {"1.0.0", "01.2.3", false, false}, {"1.0.0-rc.2", "1.0.0-rc.10", false, true}, {"1.0.0", "1.0.0-rc.1", false, false}, {"1.0.0+a", "1.0.0+b", false, false}, {"", "1.0.0-01", false, false},
	} {
		if e := CheckVersion(x.old, x.next, x.reinstall); (e == nil) != x.ok {
			t.Errorf("%+v: %v", x, e)
		}
	}
}
