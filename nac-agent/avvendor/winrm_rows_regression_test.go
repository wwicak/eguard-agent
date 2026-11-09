package avvendor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Enumerate returns the lowercase property keys of a WinRM XmlFragment;
// another page may contain unrelated rows even when WQL filters on Name.
type winRMRows struct {
	Session
	query string
	rows  []map[string]string
}

func (s winRMRows) RegistryString(context.Context, string, string) RegistryResult {
	return RegistryResult{Status: RegistryNotFound}
}
func (s winRMRows) Enumerate(_ context.Context, q string) ([]map[string]string, error) {
	if q == s.query {
		return s.rows, nil
	}
	return nil, nil
}
func TestWinRMServiceRowsAreUnorderedAndCaseInsensitive(t *testing.T) {
	for _, tc := range []struct{ id, query, name string }{
		{"cylance", cylanceServiceQuery, "CylanceSvc"},
		{"eset", esetServiceQuery, "ekrn"},
		{"symantec", sepServiceQuery, "SepMasterService"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			d, _ := Lookup(tc.id)
			s := winRMRows{query: tc.query, rows: []map[string]string{{"name": "unrelated", "state": "Stopped"}, {"name": strings.ToUpper(tc.name), "state": "running"}}}
			got, err := d.Collect(context.Background(), s, time.Now())
			if err != nil || got.Active != "enabled" || got.Absent {
				t.Fatalf("observation=%+v err=%v", got, err)
			}
		})
	}
}
func TestAVGDirectoryWinRMNameNotFileName(t *testing.T) {
	s := winRMRows{query: avgDefsQuery, rows: []map[string]string{{"name": `C:\Program Files\AVG\Antivirus\defs\26102201`, "creationdate": "20261022100000.000000+000"}}}
	got, err := collectAVG(context.Background(), s, time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC))
	if err != nil || got.SignatureLastUpdated.Format("2006-01-02") != "2026-10-22" {
		t.Fatalf("observation=%+v err=%v", got, err)
	}
}
