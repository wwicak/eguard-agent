package selfenroll

import (
	"strings"
	"testing"
)

func TestCodeFromInstallerName(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"plain", "eGuard-NAC-Setup-1.2.3-x64_K7Q2M-9XRTA.exe", "K7Q2M-9XRTA"},
		{"spaced duplicate", "setup_K7Q2M-9XRTA (1).exe", "K7Q2M-9XRTA"},
		{"duplicate", "setup_K7Q2M-9XRTA(2).exe", "K7Q2M-9XRTA"},
		{"lowercase", "setup_k7q2m-9xrta.EXE", "K7Q2M-9XRTA"},
		{"version underscores", "setup_1_2_x64_K7Q2M-9XRTA.exe", "K7Q2M-9XRTA"},
		{"wrong length", "setup_K7Q2M-9XRT.exe", ""},
		{"no code", "setup.exe", ""},
		{"traversal", "../setup_K7Q2M-9XRTA.exe", ""},
		{"windows path", `..\setup_K7Q2M-9XRTA.exe`, ""},
		{"invalid character", "setup_K7Q2M-9XRT0.exe", ""},
		{"missing dash", "setup_K7Q2M9XRTA.exe", ""},
		{"bad suffix", "setup_K7Q2M-9XRTA(x).exe", ""},
		{"empty suffix", "setup_K7Q2M-9XRTA().exe", ""},
		{"multiple suffixes", "setup_K7Q2M-9XRTA(1)(2).exe", ""},
		{"extra space", "setup_K7Q2M-9XRTA  (1).exe", ""},
		{"very long", strings.Repeat("x", 10000) + "_K7Q2M-9XRTA.exe", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CodeFromInstallerName(tt.input)
			if got != tt.want || ok != (tt.want != "") {
				t.Fatalf("got (%q, %v), want %q", got, ok, tt.want)
			}
		})
	}
}
