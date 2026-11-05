// Package clockguard keeps a durable high-water mark of trusted time so a clock
// rolled back across a reboot cannot re-open an expired Temporary session or let
// a stale authorization pass. It never moves time forward on its own and never
// extends freshness: on rollback it reports ErrRollback (fail closed).
package clockguard

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Tolerance absorbs normal NTP step corrections.
const Tolerance = 5 * time.Minute

var (
	ErrRollback = errors.New("system clock is earlier than the last trusted time")
	ErrCorrupt  = errors.New("clock high-water file invalid")
)

// Load returns the zero time when no file exists yet.
func Load(path string) (time.Time, error) {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return time.Time{}, nil
	}
	if e != nil {
		return time.Time{}, e
	}
	s := strings.TrimSpace(string(b))
	v, e := strconv.ParseInt(s, 10, 64)
	if e != nil || v <= 0 || v > 1<<40 || s != strconv.FormatInt(v, 10) {
		return time.Time{}, ErrCorrupt
	}
	return time.Unix(v, 0), nil
}

// Raise persists t atomically if it is later than the stored mark.
func Raise(path string, t time.Time) error {
	hw, e := Load(path)
	if e != nil && !errors.Is(e, ErrCorrupt) {
		return e
	}
	if e == nil && !t.After(hw) {
		return nil
	}
	tmp, e := os.CreateTemp(filepath.Dir(path), ".clock-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if _, e = tmp.WriteString(strconv.FormatInt(t.Unix(), 10)); e == nil {
		e = tmp.Sync()
	}
	if ce := tmp.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp.Name(), path)
}

// Effective is the time used for expiry decisions: never earlier than the mark.
func Effective(now, hw time.Time) time.Time {
	if now.Before(hw) {
		return hw
	}
	return now
}

// Check fails closed when the clock is earlier than the mark by more than Tolerance.
func Check(now, hw time.Time) error {
	if !hw.IsZero() && now.Before(hw.Add(-Tolerance)) {
		return ErrRollback
	}
	return nil
}
