package installtransaction

import "testing"

// mgr.CreateService stores syscall.EscapeArg(exepath); a path with spaces is
// quoted. Config().BinaryPathName returns that stored command line, so the
// ownership check must compare against the quoted image path, not the raw path.
func TestExpectedImagePathMatchesSCMQuoting(t *testing.T) {
	want := `"C:\Program Files\eGuard NAC\eguard-nac-service.exe"`
	if got := expectedImagePath(); got != want {
		t.Fatalf("expectedImagePath()=%q want %q", got, want)
	}
	if expectedImagePath() == BinaryPath {
		t.Fatal("unquoted path would never match SCM BinaryPathName for a path with spaces")
	}
}
