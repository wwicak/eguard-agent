package servicehost

import (
	"errors"
	"testing"
)

// The factory's reason (e.g. clock rollback) must survive for the event log,
// while callers can still match ErrConfigurationRequired.
func TestFactoryFailureKeepsCause(t *testing.T) {
	cause := errors.New("system clock is earlier than the last trusted time")
	err := Run(func() (Runner, error) { return nil, cause }, make(chan Command), nil)
	if !errors.Is(err, ErrConfigurationRequired) || !errors.Is(err, cause) {
		t.Fatalf("err=%v", err)
	}
}
