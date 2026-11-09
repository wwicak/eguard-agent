package transport

import (
	"context"
	"eguard-nac-agent/core"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestSendInventory(t *testing.T) {
	f := makeCerts(t)
	var got core.Inventory
	var path string
	reply := `{"accepted":true}`
	srv := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(reply))
	})
	c, err := NewClient(config(srv, f))
	if err != nil {
		t.Fatal(err)
	}
	inv := core.Inventory{AgentType: "nac", ObservedAt: time.Now().UTC(), SoftwareCollected: true, Software: []core.SoftwareItem{{Name: "Zoom", Version: "6"}}}
	if err := c.SendInventory(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/nac/inventory" || len(got.Software) != 1 || got.Software[0].Name != "Zoom" {
		t.Fatalf("%s %+v", path, got)
	}
	reply = `{"accepted":false}`
	if c.SendInventory(context.Background(), inv) == nil {
		t.Fatal("non-accepted ack must fail")
	}
}
