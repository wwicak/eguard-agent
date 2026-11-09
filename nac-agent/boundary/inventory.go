package boundary

import (
	"bytes"
	"context"
	"eguard-nac-agent/core"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// InventoryVerb is the fixed internal verb; its two arguments are fixed
// tokens chosen from the signed configuration, never free text.
const InventoryVerb = "--nac-fixed-inventory"

func flag(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// CollectInventory runs the owning executable with the fixed inventory verb in
// the same isolated, bounded child as posture collection.
func CollectInventory(ctx context.Context, executable string, software, user bool) (core.Inventory, error) {
	if !filepath.IsAbs(executable) {
		return core.Inventory{}, errors.New("collector path not absolute")
	}
	if !software && !user {
		return core.Inventory{}, errors.New("inventory not enabled")
	}
	return runInventory(ctx, func() *exec.Cmd { return exec.Command(executable, InventoryVerb, flag(software), flag(user)) }, software, user)
}

type limitedN struct {
	bytes.Buffer
	max      int
	exceeded bool
}

func (l *limitedN) Write(b []byte) (int, error) {
	if l.Len()+len(b) > l.max {
		l.exceeded = true
		return len(b), nil
	}
	_, _ = l.Buffer.Write(b)
	return len(b), nil
}

func runInventory(ctx context.Context, command func() *exec.Cmd, software, user bool) (core.Inventory, error) {
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	default:
		return core.Inventory{}, ErrBusy
	}
	cmd := command()
	prepare(cmd)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return core.Inventory{}, err
	}
	defer gateWrite.Close()
	cmd.Stdin = gateRead
	cmd.WaitDelay = time.Second
	out := &limitedN{max: core.MaxInventoryBytes}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		gateRead.Close()
		return core.Inventory{}, err
	}
	gateRead.Close()
	stopTree, err := attach(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return core.Inventory{}, errors.New("collector isolation unavailable")
	}
	defer stopTree()
	if _, err := gateWrite.Write([]byte{gateByte}); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return core.Inventory{}, errors.New("collector gate release failed")
	}
	_ = gateWrite.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		stopTree()
		_ = cmd.Process.Kill()
		<-done
		return core.Inventory{}, ctx.Err()
	}
	if err != nil || out.exceeded {
		return core.Inventory{}, errors.New("inventory collector failed or exceeded its output limit")
	}
	var inv core.Inventory
	d := json.NewDecoder(bytes.NewReader(out.Bytes()))
	d.DisallowUnknownFields()
	if err := d.Decode(&inv); err != nil {
		return core.Inventory{}, errors.New("inventory output invalid")
	}
	if err := ValidateInventory(inv, software, user); err != nil {
		return core.Inventory{}, err
	}
	return inv, nil
}

// ValidateInventory enforces the shape the server accepts.
func ValidateInventory(inv core.Inventory, software, user bool) error {
	if inv.AgentType != "nac" || inv.ObservedAt.IsZero() || inv.ObservedAt.After(time.Now().Add(time.Minute)) || len(inv.Software) > core.MaxSoftwareItems || len(inv.Updates) > 400 || len(inv.Services) > 400 || len(inv.Errors) > 8 || len(inv.User) > 128 {
		return errors.New("inventory evidence invalid")
	}
	if (inv.SoftwareCollected && !software) || (inv.UserCollected && !user) || (!inv.SoftwareCollected && len(inv.Software) > 0) || (!inv.UserCollected && inv.User != "") || (inv.UpdatesCollected && !software) || (inv.ServicesCollected && !software) || (!inv.UpdatesCollected && len(inv.Updates) > 0) || (!inv.ServicesCollected && len(inv.Services) > 0) {
		return errors.New("inventory contains data that was not enabled")
	}
	for _, u := range inv.Updates {
		if u.ID == "" || len(u.ID) > 128 || len(u.InstalledOn) > 128 || len(u.Description) > 128 {
			return errors.New("inventory update invalid")
		}
	}
	for _, s := range inv.Services {
		if s.Name == "" || len(s.Name) > 128 || len(s.DisplayName) > 128 || len(s.StartMode) > 128 {
			return errors.New("inventory service invalid")
		}
	}
	for _, s := range inv.Software {
		if s.Name == "" || len(s.Name) > core.MaxInventoryText || len(s.Version) > core.MaxInventoryText || len(s.Publisher) > core.MaxInventoryText {
			return errors.New("inventory software entry invalid")
		}
	}
	return nil
}
