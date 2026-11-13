//go:build windows

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"eguard-nac-agent/selfenroll"
	"errors"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

// Native calls are confined to one worker: slow WMI cannot indefinitely block Stop,
// and repeated collection cannot spawn unbounded blocked COM threads.
var nativeSlot = make(chan struct{}, 1)

func CollectNative(ctx context.Context, expectedDomain string) core.Posture {
	now := time.Now().UTC()
	fallback := Collect(now)
	fallback.TTL = 0 // a failed or timed-out native snapshot cannot be treated as fresh
	select {
	case nativeSlot <- struct{}{}:
	case <-ctx.Done():
		fallback.Errors = append(fallback.Errors, "native collector unavailable: "+ctx.Err().Error())
		return fallback
	}
	result := make(chan core.Posture, 1)
	go func() { defer func() { <-nativeSlot }(); result <- collectWindows(time.Now().UTC(), expectedDomain) }()
	select {
	case p := <-result:
		if ctx.Err() != nil {
			fallback.Errors = append(fallback.Errors, "native collection deadline exceeded")
			return fallback
		}
		p.ObservedAt = time.Now().UTC() // successful completion, not start of WMI acquisition
		return p
	case <-ctx.Done():
		fallback.Errors = append(fallback.Errors, "native collection deadline: "+ctx.Err().Error())
		return fallback
	}
}
func collectWindows(now time.Time, expected string) core.Posture {
	p := Collect(now)
	p.Errors = nil
	p.OS = "unknown"
	if version := windows.RtlGetVersion(); version != nil {
		p.OS = fmt.Sprintf("%s/%s", osBuild(version.MajorVersion, version.MinorVersion, version.BuildNumber), runtime.GOARCH)
	} else {
		p.Errors = append(p.Errors, "RtlGetVersion unavailable")
	}
	if hostname, err := windows.ComputerName(); err == nil {
		p.Hostname = selfenroll.CleanHostname(hostname)
	}
	p.Domain = domainNative(expected)
	p.Device = deviceNative()
	p.Defender = defenderNative()
	if adapters := adaptersNative(&p); adapters != nil {
		p.Adapters = RelevantAdapters(adapters)
	}
	p.Firewall = firewallNative(&p)
	p.AV = antivirusNative(&p)
	vctx, cancel := context.WithTimeout(context.Background(), vendorBudget)
	names := make([]string, 0, len(p.AV.Products))
	for _, pr := range p.AV.Products {
		names = append(names, pr.Name)
	}
	p.AV.Vendors = vendorsNative(vctx, names)
	cancel()
	return p
}
func signal(ok bool, source string) core.Evidence {
	v := core.No
	if ok {
		v = core.Yes
	}
	return core.Evidence{Value: v, Source: source}
}
func unavailable(source string) core.Evidence {
	return core.Evidence{Value: core.Unknown, Source: source, Error: "provider unavailable"}
}
func deviceNative() *core.DeviceEvidence {
	d := &core.DeviceEvidence{SecureBoot: unavailable("MSFT_SecureBoot"), BitlockerOS: unavailable("Win32_EncryptableVolume"), PendingReboot: unavailable("Windows Update registry")}
	var secure []struct{ SecureBootEnabled bool }
	if err := wmi.QueryNamespace("SELECT SecureBootEnabled FROM MSFT_SecureBoot", &secure, `root\WMI`); err == nil && len(secure) == 1 {
		d.SecureBoot = signal(secure[0].SecureBootEnabled, "MSFT_SecureBoot")
	}
	var volumes []struct{ ProtectionStatus uint32 }
	drive := strings.ToUpper(os.Getenv("SystemDrive"))
	if len(drive) == 2 && drive[1] == ':' && drive[0] >= 'A' && drive[0] <= 'Z' {
		if err := wmi.QueryNamespace("SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='"+drive+"'", &volumes, `root\CIMV2\Security\MicrosoftVolumeEncryption`); err == nil && len(volumes) == 1 && volumes[0].ProtectionStatus <= 1 {
			d.BitlockerOS = signal(volumes[0].ProtectionStatus == 1, "Win32_EncryptableVolume")
		}
	}
	rebootKeys := []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`}
	known := true
	pending := false
	for _, path := range rebootKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err == nil {
			k.Close()
			pending = true
		} else if err != registry.ErrNotExist {
			known = false
		}
	}
	if pending {
		d.PendingReboot = signal(true, "Windows Update / CBS registry")
	} else if known {
		d.PendingReboot = signal(false, "Windows Update / CBS registry")
	}
	var disks []struct{ FreeSpace *uint64 }
	if len(drive) == 2 && drive[1] == ':' && drive[0] >= 'A' && drive[0] <= 'Z' {
		if err := wmi.Query("SELECT FreeSpace FROM Win32_LogicalDisk WHERE DeviceID='"+drive+"'", &disks); err == nil && len(disks) == 1 {
			d.FreeDiskBytes = disks[0].FreeSpace
		}
	}
	return d
}
func defenderNative() *core.DefenderEvidence {
	d := &core.DefenderEvidence{Realtime: unavailable("MSFT_MpComputerStatus")}
	var records []struct {
		RealTimeProtectionEnabled bool
		AntivirusSignatureAge     uint32
	}
	if err := wmi.QueryNamespace("SELECT RealTimeProtectionEnabled, AntivirusSignatureAge FROM MSFT_MpComputerStatus", &records, `root\Microsoft\Windows\Defender`); err == nil && len(records) == 1 {
		d.Realtime = signal(records[0].RealTimeProtectionEnabled, "MSFT_MpComputerStatus")
		age := records[0].AntivirusSignatureAge * 24
		d.SignatureAgeHours = &age
	}
	return d
}
func domainNative(expected string) core.DomainEvidence {
	var name *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &name, &status); err != nil {
		return core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown, Source: "NetGetJoinInformation", Error: "join information unavailable"}
	}
	if name != nil {
		defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	}
	if status != uint32(windows.NetSetupDomainName) {
		if status != uint32(windows.NetSetupWorkgroupName) && status != uint32(windows.NetSetupUnjoined) {
			return core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown, Source: "NetGetJoinInformation", Error: "unrecognized join state"}
		}
		d := normalizeDomain(false, "", expected)
		d.Source = "NetGetJoinInformation"
		return d
	}
	domain := ""
	if name != nil {
		domain = windows.UTF16PtrToString(name)
	}
	d := normalizeDomain(true, domain, expected)
	d.Domain = domain
	d.Source = "NetGetJoinInformation"
	if expected == "" {
		d.Error = "expected domain not provisioned; domain match unknown"
	}
	return d
}
func boolPtr(v bool) *bool { return &v }
func adaptersNative(p *core.Posture) []core.Adapter {
	// GetAdaptersAddresses exposes physical address and interface type; Go net supplies
	// address strings with prefix lengths. Index joins are read-only and never identity proof.
	var size uint32 = 16 * 1024
	for attempt := 0; attempt < 3; attempt++ {
		if size > 4*1024*1024 {
			break
		}
		buffer := make([]byte, size)
		err := windows.GetAdaptersAddresses(0, 0, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			p.Errors = append(p.Errors, "GetAdaptersAddresses failed")
			return nil
		}
		var out []core.Adapter
		var indices []uint32
		ifaces, ifaceErr := net.Interfaces()
		if ifaceErr != nil {
			p.Errors = append(p.Errors, "interface address enumeration unavailable")
		}
		for a, n := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), 0; a != nil && n < 512; a, n = a.Next, n+1 {
			name := windows.UTF16PtrToString(a.FriendlyName)
			kind := "unknown"
			source := "GetAdaptersAddresses IfType + name heuristic"
			switch a.IfType {
			case 24, 53, 131:
				kind = adapterKind(name, boolPtr(false)) // loopback / tunnel
			default:
				kind = Classify(name + " " + windows.UTF16PtrToString(a.Description))
			}
			// IfType alone cannot prove physical hardware. PnP PhysicalAdapter evidence below.
			mac := ""
			if a.PhysicalAddressLength > 0 && a.PhysicalAddressLength <= uint32(len(a.PhysicalAddress)) {
				mac = net.HardwareAddr(a.PhysicalAddress[:a.PhysicalAddressLength]).String()
			}
			item := core.Adapter{Name: name, MAC: mac, Kind: kind, KindSource: source, RouteStatus: core.Unknown}
			indices = append(indices, a.IfIndex)
			for _, iface := range ifaces {
				if uint32(iface.Index) == a.IfIndex {
					addresses, e := iface.Addrs()
					if e == nil {
						for _, address := range addresses {
							item.Addresses = append(item.Addresses, address.String())
						}
					}
					break
				}
			}
			out = append(out, item)
		}
		if len(out) >= 512 {
			p.Errors = append(p.Errors, "adapter count truncated at 512")
		}
		// Read PnP hardware classification and locally configured default routes via WMI.
		var hardware []struct {
			InterfaceIndex  uint32
			PhysicalAdapter *bool
		}
		if err := wmi.Query("SELECT InterfaceIndex, PhysicalAdapter FROM Win32_NetworkAdapter WHERE InterfaceIndex IS NOT NULL", &hardware); err == nil {
			byIndex := map[uint32]*bool{}
			for _, item := range hardware {
				byIndex[item.InterfaceIndex] = item.PhysicalAdapter
			}
			for i := range out {
				if physical, ok := byIndex[indices[i]]; indices[i] != 0 && ok && physical != nil {
					if out[i].Kind != "virtual" {
						out[i].Kind = adapterKind(out[i].Name, physical)
					}
					out[i].KindSource = "Win32_NetworkAdapter.PhysicalAdapter + adapter name"
				}
			}
		} else {
			p.Errors = append(p.Errors, "PnP physical adapter provenance unavailable")
		}
		var table *windows.MibIpForwardTable2
		if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil || table == nil {
			if table != nil {
				windows.FreeMibTable(unsafe.Pointer(table))
			}
			p.Errors = append(p.Errors, "IP Helper route table unavailable")
		} else {
			// The Windows API allocates this table; release it on all paths.
			func() {
				defer windows.FreeMibTable(unsafe.Pointer(table))
				if table.NumEntries > 65536 {
					p.Errors = append(p.Errors, "route table exceeds safety limit")
					return
				}
				for _, row := range table.Rows() {
					if row.DestinationPrefix.PrefixLength != 0 {
						continue
					}
					family := row.DestinationPrefix.Prefix.Family
					if family != windows.AF_INET && family != windows.AF_INET6 {
						continue
					}
					// /0 with all-zero address denotes the IPv4 or IPv6 default route.
					prefix := (*windows.RawSockaddrInet6)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
					if family == windows.AF_INET {
						v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
						if v4.Addr != [4]byte{} {
							continue
						}
					} else if prefix.Addr != [16]byte{} {
						continue
					}
					for i := range out {
						if indices[i] != 0 && indices[i] == row.InterfaceIndex {
							out[i].RouteStatus = core.Yes
							out[i].ActiveRoute = true
							out[i].RouteSource = "GetIpForwardTable2 default IPv4/IPv6 route"
						}
					}
				}
			}()
		}
		runtime.KeepAlive(buffer)
		return out
	}
	p.Errors = append(p.Errors, "adapter buffer exceeded limit")
	return nil
}
func firewallNative(p *core.Posture) map[string]core.Evidence {
	raw := map[string]bool{}
	err := comThread(func() error {
		obj, e := oleutil.CreateObject("HNetCfg.FwPolicy2")
		if e != nil {
			return e
		}
		defer obj.Release()
		dispatch, e := obj.QueryInterface(ole.IID_IDispatch)
		if e != nil {
			return e
		}
		defer dispatch.Release()
		for name, bit := range map[string]int{"domain": 1, "private": 2, "public": 4} {
			v, e := oleutil.GetProperty(dispatch, "FirewallEnabled", bit)
			if e != nil {
				continue
			}
			enabled, ok := v.Value().(bool)
			_ = v.Clear()
			if ok {
				raw[name] = enabled
			}
		}
		return nil
	})
	result := normalizeFirewall(raw)
	if err != nil {
		p.Errors = append(p.Errors, "INetFwPolicy2 unavailable")
		for key, v := range result {
			v.Error = "COM firewall query failed"
			result[key] = v
		}
	}
	return result
}
func antivirusNative(p *core.Posture) core.AVEvidence {
	var records []struct {
		DisplayName  string
		ProductState uint32
	}
	err := wmi.QueryNamespace("SELECT DisplayName, ProductState FROM AntiVirusProduct", &records, `root\SecurityCenter2`)
	products := make([]AVProduct, 0, len(records))
	if err == nil {
		for _, record := range records {
			if len(products) >= 64 {
				p.Errors = append(p.Errors, "AV inventory truncated at 64 products")
				break
			}
			products = append(products, AVProduct{Name: record.DisplayName, State: record.ProductState})
		}
	} else {
		p.Errors = append(p.Errors, "SecurityCenter2 unavailable")
	}
	var defender []struct {
		AMServiceEnabled          bool
		RealTimeProtectionEnabled bool
		AntivirusSignatureAge     uint32
	}
	defenderErr := wmi.QueryNamespace("SELECT AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge FROM MSFT_MpComputerStatus", &defender, `root\Microsoft\Windows\Defender`)
	d := DefenderStatus{}
	if defenderErr == nil && len(defender) > 0 {
		d = DefenderStatus{Present: true, AMRunning: defender[0].AMServiceEnabled, Realtime: defender[0].RealTimeProtectionEnabled, SignaturesAge: int(defender[0].AntivirusSignatureAge)}
	} else if defenderErr != nil {
		p.Errors = append(p.Errors, "Defender WMI status unavailable")
	}
	a := normalizeAV(products, d)
	a.Source = "SecurityCenter2 + Defender WMI (read-only)"
	for _, product := range products {
		a.Products = append(a.Products, core.AVProductEvidence{Name: product.Name, State: product.State, Source: "SecurityCenter2"})
	}
	if err != nil && defenderErr != nil {
		a.Error = "AV providers unavailable"
	} else if len(products) > 0 && a.Running == core.Unknown {
		a.Error = "vendor SecurityCenter2 state opaque; running/updated unknown unless independent Defender evidence"
	}
	return a
}
func comThread(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		var oleErr *ole.OleError
		if !errors.As(err, &oleErr) || (oleErr.Code() != ole.S_OK && oleErr.Code() != 1) {
			return err
		}
	}
	defer ole.CoUninitialize()
	return fn()
}
