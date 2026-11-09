package transport

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrustedTimeRejectsServerCertificate(t *testing.T) {
	for _, failClock := range []bool{false, true} {
		f := makeCerts(t)
		var received atomic.Int32
		s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) { received.Add(1); accepted(w) })
		cfg := config(s, f)
		field := reflect.ValueOf(&cfg).Elem().FieldByName("Now")
		if !field.IsValid() {
			t.Fatal("missing trusted TLS time input")
		}
		field.Set(reflect.ValueOf(func() (time.Time, error) {
			if failClock {
				return time.Time{}, errors.New("unknown time")
			}
			return time.Now().Add(24 * time.Hour), nil
		}))
		c, e := NewClient(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer c.CloseIdleConnections()
		if e = c.SendPosture(context.Background(), posture()); e == nil {
			t.Fatal("untrusted temporal certificate accepted")
		}
		if received.Load() != 0 {
			t.Fatal("posture reached server")
		}
	}
}
