// Package boundary runs a single fixed, local NAC collector process with bounded output.
// The service must reside in ACL-protected, signed installation before use on real hosts.
package boundary

import (
	"bytes"
	"context"
	"eguard-nac-agent/avvendor"
	"eguard-nac-agent/core"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const MaxOutput = 256 * 1024

var ErrBusy = errors.New("collector already running")
var slot = make(chan struct{}, 1)

type limited struct {
	bytes.Buffer
	exceeded bool
}

func (l *limited) Write(b []byte) (int, error) {
	n := len(b)
	if l.Len()+n > MaxOutput {
		l.exceeded = true
		available := MaxOutput - l.Len()
		if available > 0 {
			_, _ = l.Buffer.Write(b[:available])
		}
		return n, nil
	}
	_, _ = l.Buffer.Write(b)
	return n, nil
}

// Collect invokes only the owning service executable with one fixed internal verb.
// Path comes from os.Executable, not network, config, CLI or request input.
func Collect(ctx context.Context, executable string) (core.Posture, error) {
	if !filepath.IsAbs(executable) {
		return core.Posture{}, errors.New("collector path not absolute")
	}
	return run(ctx, func() *exec.Cmd { return exec.Command(executable, "--nac-fixed-collect") })
}

// run reaps the child even on timeout and refuses malformed/oversized evidence.
// A separate process isolates blocking COM/WMI from the service's SCM stop path.
func run(ctx context.Context, command func() *exec.Cmd) (core.Posture, error) {
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	default:
		return core.Posture{}, ErrBusy
	}
	if err := ctx.Err(); err != nil {
		return core.Posture{}, err
	}
	cmd := command()
	if cmd == nil {
		return core.Posture{}, errors.New("missing fixed collector command")
	}
	// On Windows a kill-on-close Job Object contains child processes. On Unix
	// a dedicated process group is terminated. No shell is ever used.
	prepare(cmd)
	gateRead, gateWrite, pipeErr := os.Pipe()
	if pipeErr != nil {
		return core.Posture{}, pipeErr
	}
	defer gateWrite.Close()
	cmd.Stdin = gateRead
	cmd.WaitDelay = time.Second
	out := &limited{}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	started := time.Now()
	if err := cmd.Start(); err != nil {
		gateRead.Close()
		return core.Posture{}, err
	}
	// Close parent's read end: only the child retains it. No writer is inherited.
	gateRead.Close()
	stopTree, attachErr := attach(cmd)
	if attachErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return core.Posture{}, errors.New("collector isolation unavailable")
	}
	defer stopTree()
	if err := ctx.Err(); err != nil {
		stopTree()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return core.Posture{}, err
	}
	if _, err := gateWrite.Write([]byte{gateByte}); err != nil {
		stopTree()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return core.Posture{}, errors.New("collector gate release failed")
	}
	_ = gateWrite.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		stopTree()
		_ = cmd.Process.Kill()
		err = <-done
		if err == nil {
			err = ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return core.Posture{}, ctx.Err()
	}
	if err != nil {
		return core.Posture{}, errors.New("collector process failed")
	}
	if out.exceeded {
		return core.Posture{}, errors.New("collector output limit exceeded")
	}
	var p core.Posture
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		return core.Posture{}, errors.New("collector output invalid")
	}
	if p.AgentType != "nac" || p.ObservedAt.IsZero() || p.ObservedAt.After(time.Now()) || p.TTL <= 0 || p.TTL > 5*time.Minute || time.Since(started) > p.TTL || !p.Fresh(time.Now()) || len(p.Adapters) > 512 || len(p.AV.Products) > 64 || len(p.Firewall) != 3 || !validTri(p.Domain.PartOfDomain) || !validTri(p.Domain.Match) || !validTri(p.AV.Installed) || !validTri(p.AV.Running) || !validTri(p.AV.Updated) {
		return core.Posture{}, errors.New("collector evidence invalid")
	}
	for _, profile := range []string{"domain", "private", "public"} {
		e, ok := p.Firewall[profile]
		if !ok || !validTri(e.Value) {
			return core.Posture{}, errors.New("collector firewall evidence invalid")
		}
	}
	if len(p.Hostname) > 63 {
		return core.Posture{}, errors.New("collector hostname invalid")
	}
	if p.Device != nil && (!validTri(p.Device.SecureBoot.Value) || !validTri(p.Device.BitlockerOS.Value) || !validTri(p.Device.PendingReboot.Value)) {
		return core.Posture{}, errors.New("collector device evidence invalid")
	}
	if p.Defender != nil && !validTri(p.Defender.Realtime.Value) {
		return core.Posture{}, errors.New("collector defender evidence invalid")
	}
	if err := ValidateVendors(p.AV.Vendors, time.Now()); err != nil {
		return core.Posture{}, err
	}
	primary := 0
	for _, a := range p.Adapters {
		if a.Primary {
			primary++
		}
		if primary > 1 {
			return core.Posture{}, errors.New("multiple primary adapters")
		}
		if !validTri(a.RouteStatus) || (a.ActiveRoute && a.RouteStatus != core.Yes) || (a.Kind != "unknown" && a.Kind != "virtual" && a.Kind != "physical") {
			return core.Posture{}, errors.New("collector adapter evidence invalid")
		}
	}
	return p, nil
}
func validTri(t core.Tri) bool { return t == core.Yes || t == core.No || t == core.Unknown }

// ValidateVendors accepts only reviewed vendor IDs, one entry each, with a
// known state and no future or impossible signature date.
func ValidateVendors(vs []core.AVVendorEvidence, now time.Time) error {
	if len(vs) > core.MaxAVVendors {
		return errors.New("collector vendor evidence invalid")
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if !avvendor.Allowed(v.ID) || seen[v.ID] || (v.Active != "enabled" && v.Active != "disabled" && v.Active != "unknown" && v.Active != "absent") {
			return errors.New("collector vendor evidence invalid")
		}
		seen[v.ID] = true
		if v.SignatureLastUpdated != nil && (v.Active == "absent" || v.SignatureLastUpdated.After(now.Add(time.Minute)) || v.SignatureLastUpdated.Year() < 1971) {
			return errors.New("collector vendor date invalid")
		}
	}
	return nil
}
