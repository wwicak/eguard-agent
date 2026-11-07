//go:build linux || darwin

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// UnixProvider exposes only acquisition dependencies; production commands and argv
// are fixed by the collectors, never supplied by policy or network input.
type UnixProvider struct {
	Root string
	Run  func(context.Context, string, ...string) ([]byte, error)
	Now  func() time.Time
}

func nativeProvider() UnixProvider { return UnixProvider{Root: "/", Run: runUnix, Now: time.Now} }

type boundedOutput struct{ b []byte }

func (w *boundedOutput) Write(p []byte) (int, error) {
	if len(w.b)+len(p) > 2<<20 {
		return 0, io.ErrShortBuffer
	}
	w.b = append(w.b, p...)
	return len(p), nil
}
func runUnix(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	w := new(boundedOutput)
	c.Stdout = w
	c.Stderr = io.Discard
	e := c.Run()
	return w.b, e
}
func (u UnixProvider) path(p string) string { return filepath.Join(u.Root, strings.TrimPrefix(p, "/")) }
func (u UnixProvider) read(p string) []byte {
	f, e := os.Open(u.path(p))
	if e != nil {
		return nil
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 2<<20))
	if e != nil || len(b) >= 2<<20 {
		return nil
	}
	return b
}
func (u UnixProvider) command(ctx context.Context, n string, a ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return u.Run(ctx, n, a...)
}
func ev(t core.Tri, s string) core.Evidence { return core.Evidence{Value: t, Source: s} }
func applyRoute(p *core.Posture, name, source string) {
	for i := range p.Adapters {
		a := &p.Adapters[i]
		a.RouteSource = source
		if name != "" && a.Name == name {
			a.RouteStatus = core.Yes
			a.ActiveRoute = true
		}
	}
}
func applyDomain(p *core.Posture, d, expected, source string) {
	p.Domain = core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown, Source: source}
	if d != "" {
		p.Domain.Domain = d
		p.Domain.PartOfDomain = core.Yes
		if expected != "" {
			p.Domain.Match = core.No
			if strings.EqualFold(d, expected) {
				p.Domain.Match = core.Yes
			}
		}
	}
}
func addAV(p *core.Posture, name string, running, updated core.Tri) {
	p.AV.Installed = core.Yes
	p.AV.Products = append(p.AV.Products, core.AVProductEvidence{Name: name, Source: "Unix fixed provider"})
	if p.AV.Running != core.Yes {
		p.AV.Running = running
	}
	if running == core.Yes && updated == core.Yes {
		p.AV.Updated = core.Yes
	}
}
