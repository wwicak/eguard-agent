package avvendor

import (
	"os"
	"regexp"
	"testing"
)

// Registry map keys are variable fields, so the compiler does not reject a
// duplicated entry (the later one silently wins). Merge-conflict resolution
// has produced duplicates before; keep the literal one line per vendor.
func TestRegistryLiteralHasNoDuplicateEntries(t *testing.T) {
	src, err := os.ReadFile("registry.go")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)var registry = map\[string\]Descriptor\{(.*?)\n\}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("registry literal not found")
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\.ID:`).FindAllSubmatch(block[1], -1) {
		name := string(m[1])
		if seen[name] {
			t.Fatalf("duplicate registry entry %s", name)
		}
		seen[name] = true
	}
	if len(seen) != len(All()) {
		t.Fatalf("registry literal has %d entries, All() has %d", len(seen), len(All()))
	}
}
