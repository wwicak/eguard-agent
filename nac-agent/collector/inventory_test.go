package collector

import (
	"eguard-nac-agent/core"
	"fmt"
	"strings"
	"testing"
)

func TestNormalizeSoftware(t *testing.T) {
	in := []core.SoftwareItem{
		{Name: " Zoom ", Version: "6.1", Publisher: "Zoom"},
		{Name: "7-Zip 23.01 (x64)", Version: "23.01", Publisher: "Igor Pavlov"},
		{Name: "zoom", Version: "6.1"},
		{Name: "", Version: "1"},
		{Name: "Bad\x07Name", Version: "1\n"},
	}
	out, tr := NormalizeSoftware(in)
	if tr || len(out) != 3 || out[0].Name != "7-Zip 23.01 (x64)" || out[1].Name != "BadName" || out[1].Version != "1" || out[2].Name != "Zoom" {
		t.Fatalf("%+v %v", out, tr)
	}
	many := make([]core.SoftwareItem, core.MaxSoftwareItems+5)
	for i := range many {
		many[i] = core.SoftwareItem{Name: fmt.Sprintf("app-%05d", i) + strings.Repeat("x", i%300), Version: "1"}
	}
	out, tr = NormalizeSoftware(many)
	if !tr || len(out) != core.MaxSoftwareItems {
		t.Fatalf("bound: %d %v", len(out), tr)
	}
	for _, it := range out {
		if len(it.Name) > core.MaxInventoryText {
			t.Fatal("text bound")
		}
	}
	if out, _ := NormalizeSoftware(nil); out == nil {
		t.Fatal("empty list must be [] not null")
	}
}

func TestCleanUser(t *testing.T) {
	if CleanUser("  CORP\\budi \r") != "CORP\\budi" || CleanUser("") != "" {
		t.Fatal(CleanUser("  CORP\\budi \r"))
	}
}
