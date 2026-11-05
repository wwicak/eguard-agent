package transport

import (
	"net/http"
	"testing"
)

type closeProbe struct{ closed bool }

func (p *closeProbe) RoundTrip(*http.Request) (*http.Response, error) { panic("unexpected request") }
func (p *closeProbe) CloseIdleConnections()                           { p.closed = true }
func TestClientReleasesOwnedTransport(t *testing.T) {
	p := &closeProbe{}
	c := &Client{http: &http.Client{Transport: p}}
	c.CloseIdleConnections()
	if !p.closed {
		t.Fatal("owned transport not closed")
	}
}

func TestClientExposesIdleConnectionRelease(t *testing.T) {
	c := &Client{}
	closer, ok := any(c).(interface{ CloseIdleConnections() })
	if !ok {
		t.Fatal("transport has no idle connection release")
	}
	closer.CloseIdleConnections()
	var nilClient *Client
	any(nilClient).(interface{ CloseIdleConnections() }).CloseIdleConnections()
}
