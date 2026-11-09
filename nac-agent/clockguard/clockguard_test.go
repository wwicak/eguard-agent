package clockguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMissingFileIsZeroAndRaiseOnlyIncreases(t *testing.T) {
	p := filepath.Join(t.TempDir(), "clock.hw")
	hw, e := Load(p)
	if e != nil || !hw.IsZero() {
		t.Fatalf("hw=%v e=%v", hw, e)
	}
	t1 := time.Unix(1_800_000_000, 0)
	if e := Raise(p, t1); e != nil {
		t.Fatal(e)
	}
	if e := Raise(p, t1.Add(-time.Hour)); e != nil {
		t.Fatal(e)
	}
	if hw, _ := Load(p); !hw.Equal(t1) {
		t.Fatalf("lowered to %v", hw)
	}
	if e := Raise(p, t1.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if hw, _ := Load(p); !hw.Equal(t1.Add(time.Minute)) {
		t.Fatalf("not raised: %v", hw)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "clock.hw")
	for _, bad := range []string{"", "abc", "-5", "1800000000 junk", "99999999999999999999"} {
		os.WriteFile(p, []byte(bad), 0600)
		if _, e := Load(p); e == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEffectiveNowNeverBelowHighWater(t *testing.T) {
	hw := time.Unix(1_800_000_000, 0)
	if got := Effective(hw.Add(-48*time.Hour), hw); !got.Equal(hw) {
		t.Fatalf("rolled-back clock not clamped: %v", got)
	}
	if got := Effective(hw.Add(time.Hour), hw); !got.Equal(hw.Add(time.Hour)) {
		t.Fatalf("forward time altered: %v", got)
	}
}

func TestCheckDetectsRollbackBeyondTolerance(t *testing.T) {
	hw := time.Unix(1_800_000_000, 0)
	if e := Check(hw.Add(-Tolerance+time.Second), hw); e != nil {
		t.Fatalf("small skew rejected: %v", e)
	}
	if e := Check(hw.Add(-Tolerance-time.Second), hw); !errors.Is(e, ErrRollback) {
		t.Fatalf("rollback not detected: %v", e)
	}
	if e := Check(time.Unix(5, 0), time.Time{}); e != nil {
		t.Fatalf("no high-water must not reject: %v", e)
	}
}
