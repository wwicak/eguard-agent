//go:build windows

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"time"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows/registry"
)

// uninstallRoots are the documented locations of installed programs
// (64-bit, 32-bit on 64-bit Windows). Read-only; per-user hives are not read.
var uninstallRoots = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

func softwareNative() ([]core.SoftwareItem, error) {
	var items []core.SoftwareItem
	var firstErr error
	opened := 0
	for _, root := range uninstallRoots {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			if firstErr == nil && err != registry.ErrNotExist {
				firstErr = err
			}
			continue
		}
		opened++
		names, _ := k.ReadSubKeyNames(-1)
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			if sc, _, err := sk.GetIntegerValue("SystemComponent"); err == nil && sc == 1 {
				sk.Close()
				continue
			}
			if parent, _, err := sk.GetStringValue("ParentKeyName"); err == nil && parent != "" {
				sk.Close() // updates/patches of another product
				continue
			}
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			pub, _, _ := sk.GetStringValue("Publisher")
			sk.Close()
			if name != "" {
				items = append(items, core.SoftwareItem{Name: name, Version: ver, Publisher: pub})
			}
		}
		k.Close()
	}
	if opened == 0 && firstErr != nil {
		return nil, firstErr
	}
	return items, nil
}

func userNative() (string, error) {
	var cs []struct{ UserName *string }
	err := comThread(func() error { return wmi.Query("SELECT UserName FROM Win32_ComputerSystem", &cs) })
	if err != nil || len(cs) != 1 {
		return "", err
	}
	if cs[0].UserName == nil {
		return "", nil
	}
	return *cs[0].UserName, nil
}

func trim128(s string) string {
	if len(s) > 128 {
		return s[:128]
	}
	return s
}

// CollectInventory reads only what the signed configuration enabled.
func CollectInventory(ctx context.Context, software, user bool) core.Inventory {
	inv := core.Inventory{AgentType: "nac", Software: []core.SoftwareItem{}, Errors: []string{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if software {
			if list, err := softwareNative(); err != nil {
				inv.Errors = append(inv.Errors, "installed software unavailable")
			} else {
				inv.SoftwareCollected = true
				inv.Software, inv.SoftwareTruncated = NormalizeSoftware(list)
			}
			var updates []struct {
				HotFixID    string
				InstalledOn string
				Description string
			}
			if err := wmi.Query("SELECT HotFixID, InstalledOn, Description FROM Win32_QuickFixEngineering", &updates); err == nil {
				inv.UpdatesCollected = true
				for _, u := range updates {
					if len(inv.Updates) >= 400 {
						break
					}
					inv.Updates = append(inv.Updates, core.UpdateItem{ID: trim128(u.HotFixID), InstalledOn: trim128(u.InstalledOn), Description: trim128(u.Description)})
				}
			} else {
				inv.Errors = append(inv.Errors, "installed updates unavailable")
			}
			var services []struct {
				Name        string
				DisplayName string
				StartMode   string
			}
			if err := wmi.Query("SELECT Name, DisplayName, StartMode FROM Win32_Service WHERE State='Running'", &services); err == nil {
				inv.ServicesCollected = true
				for _, s := range services {
					if len(inv.Services) >= 400 {
						break
					}
					inv.Services = append(inv.Services, core.ServiceItem{Name: trim128(s.Name), DisplayName: trim128(s.DisplayName), StartMode: trim128(s.StartMode)})
				}
			} else {
				inv.Errors = append(inv.Errors, "running services unavailable")
			}
		}
		if user {
			if u, err := userNative(); err != nil {
				inv.Errors = append(inv.Errors, "signed-in user unavailable")
			} else {
				inv.UserCollected = true
				inv.User = CleanUser(u)
			}
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return core.Inventory{AgentType: "nac", Software: []core.SoftwareItem{}, Errors: []string{"inventory collection deadline exceeded"}, ObservedAt: time.Now().UTC()}
	}
	inv.ObservedAt = time.Now().UTC()
	return inv
}
