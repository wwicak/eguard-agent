package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"eguard-nac-agent/core"
)

func TestSubmissionSameBytesAndKeyAcrossManualRetryTLS(t *testing.T) {
	f := makeCerts(t)
	type capture struct {
		key  string
		body []byte
	}
	seen := make(chan capture, 4)
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
		}
		seen <- capture{r.Header.Get("Idempotency-Key"), raw}
		accepted(w)
	})
	c, e := NewClient(config(s, f))
	if e != nil {
		t.Fatal(e)
	}
	sub, e := PreparePosture(posture())
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = c.SendSubmission(context.Background(), sub); e != nil {
			t.Fatal(e)
		}
	}
	a, b := <-seen, <-seen
	if len(a.key) != 32 || a.key != b.key || !bytes.Equal(a.body, b.body) {
		t.Fatal("manual retry changed request id or body")
	}
	var p core.Posture
	if e = json.Unmarshal(a.body, &p); e != nil || p.AgentType != "nac" {
		t.Fatal("invalid posture body", e)
	}
	next, e := PreparePosture(posture())
	if e != nil {
		t.Fatal(e)
	}
	if e = c.SendSubmission(context.Background(), next); e != nil {
		t.Fatal(e)
	}
	newer := <-seen
	if newer.key == a.key {
		t.Fatal("fresh preparation reused request ID")
	}
}
func TestSubmissionDeepImmutableFromPostureAndConcurrentSend(t *testing.T) {
	f := makeCerts(t)
	seen := make(chan []byte, 16)
	keys := make(chan string, 16)
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
		}
		seen <- b
		keys <- r.Header.Get("Idempotency-Key")
		accepted(w)
	})
	c, e := NewClient(config(s, f))
	if e != nil {
		t.Fatal(e)
	}
	p := posture()
	p.Firewall["domain"] = core.Evidence{Source: "before"}
	p.Adapters = []core.Adapter{{Name: "before"}}
	sub, e := PreparePosture(p)
	if e != nil {
		t.Fatal(e)
	}
	p.Firewall["domain"] = core.Evidence{Source: "after"}
	p.Adapters[0].Name = "after"
	p.OS = "after"
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- c.SendSubmission(context.Background(), sub) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	first := <-seen
	key := <-keys
	if key == "" {
		t.Fatal("missing key")
	}
	var snap core.Posture
	if e = json.Unmarshal(first, &snap); e != nil {
		t.Fatal(e)
	}
	if snap.OS != "synthetic" || snap.Firewall["domain"].Source != "before" || snap.Adapters[0].Name != "before" {
		t.Fatal("caller mutation changed prepared bytes")
	}
	for i := 1; i < 12; i++ {
		if b := <-seen; !bytes.Equal(b, first) {
			t.Fatal("concurrent send mutated body")
		}
		if k := <-keys; k != key {
			t.Fatal("concurrent send mutated key")
		}
	}
}
func TestSubmissionRejectsZeroForgedAndOversizedBeforeDispatch(t *testing.T) {
	f := makeCerts(t)
	var hits atomic.Int32
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); accepted(w) })
	c, e := NewClient(config(s, f))
	if e != nil {
		t.Fatal(e)
	}
	good, e := PreparePosture(posture())
	if e != nil {
		t.Fatal(e)
	}
	// Tests inside package can simulate a forged internal value; external callers cannot set private fields.
	bad := good
	bad.body = "X" + good.body[1:]
	for _, sub := range []Submission{{}, bad} {
		if e = c.SendSubmission(context.Background(), sub); e == nil {
			t.Fatal("zero/forged submission accepted")
		}
	}
	p := posture()
	p.OS = string(bytes.Repeat([]byte("x"), 65536))
	if _, e := PreparePosture(p); e == nil {
		t.Fatal("oversized preparation accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("invalid submission dispatched")
	}
}
func TestSendPostureWrapperCreatesNewSubmissionEachInvocation(t *testing.T) {
	f := makeCerts(t)
	keys := make(chan string, 2)
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) { keys <- r.Header.Get("Idempotency-Key"); accepted(w) })
	c, e := NewClient(config(s, f))
	if e != nil {
		t.Fatal(e)
	}
	p := posture()
	for i := 0; i < 2; i++ {
		if e := c.SendPosture(context.Background(), p); e != nil {
			t.Fatal(e)
		}
	}
	a, b := <-keys, <-keys
	if len(a) != 32 || len(b) != 32 || a == b {
		t.Fatal("wrapper invocations must have distinct request ids")
	}
}
