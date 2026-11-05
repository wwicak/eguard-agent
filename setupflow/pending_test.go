package setupflow

import (
	"reflect"
	"testing"
)

func TestRemovePendingNAC(t *testing.T) {
	in := []string{`\??\C:\Program Files\eGuard NAC\eguard-nac-service.exe`, "", `\??\C:\Other\x.exe`, "", `\??\C:\Program Files\eGuard NAC\old.exe`, `\??\C:\Else\new.exe`, `\??\C:\Program Files\eGuard NAC-old\x`, ""}
	want := []string{`\??\C:\Other\x.exe`, "", `\??\C:\Program Files\eGuard NAC-old\x`, ""}
	if got := RemovePendingNAC(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	if got := RemovePendingNAC([]string{"orphan"}); !reflect.DeepEqual(got, []string{"orphan"}) {
		t.Fatal(got)
	}
}

func TestRemovePendingNACObservedWindowsPrefix(t *testing.T) {
	in := []string{`*1\??\C:\Program Files\eGuard NAC\eguard-nac-service.exe`, ``, `\??\C:\Other\x.dll`, ``}
	out := RemovePendingNAC(in)
	if len(out) != 2 || out[0] != `\??\C:\Other\x.dll` {
		t.Fatalf("%q", out)
	}
}
