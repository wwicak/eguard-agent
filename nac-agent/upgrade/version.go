// Package upgrade implements local administrator binary replacement policy.
package upgrade

import (
	"errors"
	"regexp"
	"strings"
)

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func numeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
func parse(s string) []string {
	m := semver.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	for _, p := range strings.Split(m[4], ".") {
		if numeric(p) && len(p) > 1 && p[0] == '0' {
			return nil
		}
	}
	return m
}
func numcmp(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}
func compare(a, b []string) int {
	for i := 1; i <= 3; i++ {
		if c := numcmp(a[i], b[i]); c != 0 {
			return c
		}
	}
	if a[4] == b[4] {
		return 0
	}
	if a[4] == "" {
		return 1
	}
	if b[4] == "" {
		return -1
	}
	ap, bp := strings.Split(a[4], "."), strings.Split(b[4], ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		x, y := ap[i], bp[i]
		c := strings.Compare(x, y)
		if numeric(x) && numeric(y) {
			c = numcmp(x, y)
		} else if numeric(x) {
			c = -1
		} else if numeric(y) {
			c = 1
		}
		if c != 0 {
			return c
		}
	}
	if len(ap) < len(bp) {
		return -1
	}
	return 1
}

// CheckVersion treats legacy unstamped binaries as older than any valid release.
func CheckVersion(installed, next string, reinstall bool) error {
	n := parse(next)
	if n == nil {
		return errors.New("new version must be valid semver")
	}
	o := parse(installed)
	if o == nil || installed == "0.0.0-dev" {
		return nil
	}
	c := compare(n, o)
	if c > 0 || c == 0 && reinstall {
		return nil
	}
	return errors.New("downgrade or same version refused (same version requires --reinstall)")
}
