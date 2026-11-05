package servicefactory

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
)

// Uninstall request hand-off. With Anti-Tamper ON an administrator cannot stop
// the service, so nac-setup drops the signed authorization into the protected
// provisioning root (writable only by SYSTEM/Administrators). The running
// service (SYSTEM) verifies it, stops its own runner, records the grant in the
// journal (replay/sequence enforcement) and performs official cleanup.
const (
	RequestFile = "uninstall-request.json"
	ResultFile  = "uninstall-result.txt"
	maxRequest  = 64 * 1024
)

func writeResult(root, s string) { _ = os.WriteFile(filepath.Join(root, ResultFile), []byte(s), 0600) }

func readRequest(root string) ([]byte, bool) {
	p := filepath.Join(root, RequestFile)
	f, e := os.Open(p)
	if e != nil {
		return nil, false
	}
	b, e := io.ReadAll(io.LimitReader(f, maxRequest+1))
	f.Close()
	_ = os.Remove(p) // consumed whether valid or not
	if e != nil || len(b) > maxRequest {
		return nil, true
	}
	return b, true
}

// verifyRequest performs every check that does not need the journal.
func verifyRequest(raw []byte, keys map[string]ed25519.PublicKey, b lifecycle.Binding, now time.Time) error {
	g, e := lifecycle.VerifyEnvelope(raw, keys, b)
	if e != nil || g.Action != "authorize_uninstall" || lifecycle.ValidateAcceptance(g, now.Unix()) != nil {
		return errors.New("authorization invalid for this device")
	}
	return nil
}

// watchRequests polls for a request; returns a verified envelope (and cancels
// the runner through stop) or nil when ctx ends. Invalid requests are reported
// and the service keeps running.
// remote carries grants delivered by the eGuard server (posture acknowledgement);
// they are verified exactly like a local request. Invalid server grants are
// ignored without writing a result file (nobody local is waiting).
func watchRequests(ctx context.Context, root string, poll time.Duration, keys map[string]ed25519.PublicKey, b lifecycle.Binding, now func() (time.Time, error), stop context.CancelFunc, remote <-chan []byte) []byte {
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		var raw []byte
		found, fromServer := false, false
		select {
		case <-ctx.Done():
			return nil
		case raw = <-remote:
			found, fromServer = true, true
		case <-t.C:
			raw, found = readRequest(root)
		}
		if !found {
			continue
		}
		if fromServer {
			if at, e := now(); e != nil || verifyRequest(raw, keys, b, at) != nil {
				continue
			}
			stop()
			return raw
		}
		at, e := now()
		if e == nil {
			e = verifyRequest(raw, keys, b, at)
		}
		if e != nil {
			writeResult(root, "rejected: "+e.Error())
			continue
		}
		stop()
		return raw
	}
}

func acceptRequest(root string, raw []byte, keys map[string]ed25519.PublicKey, b lifecycle.Binding, now time.Time) error {
	j, e := journal.Open(filepath.Join(root, "journal.db"), journal.Binding{Device: b.DeviceID, Tenant: b.TenantID, Site: b.SiteID, Enrollment: b.EnrollmentID})
	if e != nil {
		return e
	}
	_, e = lifecycle.Accept(j, raw, keys, b, now.Unix())
	return errors.Join(e, j.Close())
}
