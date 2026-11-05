package transport

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrustedTimeRecheckedAfterSuccessfulSend(t *testing.T) {
	f := makeCerts(t)
	var received atomic.Int32
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) { received.Add(1); accepted(w) })
	var advanced atomic.Bool
	cfg := config(s, f)
	cfg.Now = func() (time.Time, error) {
		now := time.Now()
		if advanced.Load() {
			now = now.Add(24 * time.Hour)
		}
		return now, nil
	}
	c, e := NewClient(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.CloseIdleConnections()
	if e = c.SendPosture(context.Background(), posture()); e != nil {
		t.Fatal(e)
	}
	advanced.Store(true)
	if e = c.SendPosture(context.Background(), posture()); e == nil {
		t.Fatal("expired server accepted after prior successful send")
	}
	if received.Load() != 1 {
		t.Fatal("second posture reached server")
	}
}
