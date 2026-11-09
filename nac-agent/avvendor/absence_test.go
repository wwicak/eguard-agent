package avvendor

import (
	"context"
	"errors"
	"testing"
	"time"
)

type absentServiceSession struct {
	Session
	err error
}

func (s absentServiceSession) Enumerate(_ context.Context, _ string) ([]map[string]string, error) {
	return nil, s.err
}

func TestCleanServiceAbsence(t *testing.T) {
	for _, id := range []string{"360safe", "activevirusshield", "avira", "caetrust", "cylance", "escan", "estsoft", "hauri", "ivanti-landesk", "k7", "ntw", "rising", "webroot"} {
		t.Run(id, func(t *testing.T) {
			d, _ := Lookup(id)
			for _, tc := range []struct {
				name   string
				err    error
				cancel bool
				absent bool
			}{{"clean", nil, false, true}, {"denied", errors.New("denied"), false, false}, {"provider", errors.New("provider"), false, false}, {"cancel", nil, true, false}} {
				t.Run(tc.name, func(t *testing.T) {
					ctx := context.Background()
					if tc.cancel {
						var cancel context.CancelFunc
						ctx, cancel = context.WithCancel(ctx)
						cancel()
						defer cancel()
					}
					got, _ := d.Collect(ctx, absentServiceSession{err: tc.err}, time.Now())
					if got.Absent != tc.absent || got.Active != "unknown" || !got.SignatureLastUpdated.IsZero() {
						t.Fatalf("%+v", got)
					}
				})
			}
		})
	}
}
