//go:build windows

package cleanup

import (
	"os"
	"strings"
	"testing"
)

// Static guard for the M79 regression: deleting the protected service must not
// request SERVICE_ALL_ACCESS (mgr.OpenService). Runtime proof is the VM e2e.
func TestMarkServiceForDeletionRequestsDeleteOnly(t *testing.T) {
	b, e := os.ReadFile("windows.go")
	if e != nil {
		t.Fatal(e)
	}
	body := string(b)
	i := strings.Index(body, "func (w Windows) MarkServiceForDeletion")
	j := strings.Index(body[i:], "\n}\n")
	f := body[i : i+j]
	if strings.Contains(f, "m.OpenService(") || !strings.Contains(f, "windows.DELETE") {
		t.Fatal("MarkServiceForDeletion must open the service with DELETE only")
	}
}
