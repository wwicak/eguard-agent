//go:build windows

package collector

import (
	"context"
	"eguard-nac-agent/avvendor"
	"eguard-nac-agent/core"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// localAVSession answers the reviewed avvendor rules on this machine with
// the same read-only surface the WinRM/DCOM collectors use remotely: WQL in
// root\cimv2 (Win32_Service / Win32_Directory / CIM_DataFile metadata only)
// and HKLM registry values. Every read is bounded; nothing is written.
type localAVSession struct {
	defender avvendor.Observation
}

const (
	avMaxRows    = 256
	avMaxBytes   = 64 * 1024
	avMaxEntries = 256
)

var errAVQuery = errors.New("query not allowed")

func avQueryAllowed(q string) bool {
	u := strings.ToUpper(q)
	if !strings.HasPrefix(u, "SELECT ") || strings.ContainsAny(q, ";") {
		return false
	}
	for _, from := range []string{" FROM WIN32_SERVICE ", " FROM WIN32_SERVICE", " FROM WIN32_DIRECTORY ", " FROM CIM_DATAFILE "} {
		if strings.Contains(u+" ", from) {
			return true
		}
	}
	return false
}

// Enumerate runs one fixed vendor WQL and returns rows with lower-case keys.
// CIM datetimes are kept in WMI DMTF form (yyyymmddHHMMSS.ffffff+UUU), the
// same text WinRM/DCOM deliver to the vendor date parsers.
func (s localAVSession) Enumerate(ctx context.Context, query string) ([]map[string]string, error) {
	if !avQueryAllowed(query) || ctx.Err() != nil {
		return nil, errAVQuery
	}
	return wqlRows(ctx, `root\cimv2`, query)
}

// wqlRows runs one fixed WQL via SWbemLocator and returns the selected
// columns as text; a NULL property is omitted from the row (never "").
func wqlRows(ctx context.Context, namespace, query string) ([]map[string]string, error) {
	cols := wqlColumns(query)
	if len(cols) == 0 {
		return nil, errAVQuery
	}
	var rows []map[string]string
	err := comThread(func() error {
		unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
		if err != nil {
			return err
		}
		defer unknown.Release()
		locator, err := unknown.QueryInterface(ole.IID_IDispatch)
		if err != nil {
			return err
		}
		defer locator.Release()
		svcRaw, err := oleutil.CallMethod(locator, "ConnectServer", nil, namespace)
		if err != nil {
			return err
		}
		svc := svcRaw.ToIDispatch()
		defer svcRaw.Clear()
		resRaw, err := oleutil.CallMethod(svc, "ExecQuery", query)
		if err != nil {
			return err
		}
		res := resRaw.ToIDispatch()
		defer resRaw.Clear()
		countVar, err := oleutil.GetProperty(res, "Count")
		if err != nil {
			return err
		}
		count := int(countVar.Val)
		_ = countVar.Clear()
		if count > avMaxRows {
			return errors.New("too many rows")
		}
		total := 0
		for i := 0; i < count; i++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			itemRaw, err := oleutil.CallMethod(res, "ItemIndex", i)
			if err != nil {
				return err
			}
			item := itemRaw.ToIDispatch()
			row := map[string]string{}
			for _, c := range cols {
				v, err := oleutil.GetProperty(item, c)
				if err != nil {
					_ = itemRaw.Clear()
					return err
				}
				val := v.Value()
				if v.VT == ole.VT_NULL || val == nil {
					_ = v.Clear()
					continue
				}
				text := fmt.Sprint(val)
				_ = v.Clear()
				total += len(text)
				if total > avMaxBytes {
					_ = itemRaw.Clear()
					return errors.New("row data too large")
				}
				row[strings.ToLower(c)] = text
			}
			_ = itemRaw.Clear()
			rows = append(rows, row)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []map[string]string{}
	}
	return rows, nil
}

func wqlColumns(q string) []string {
	u := strings.ToUpper(q)
	i := strings.Index(u, " FROM ")
	if i < 7 {
		return nil
	}
	var out []string
	for _, c := range strings.Split(q[7:i], ",") {
		c = strings.TrimSpace(c)
		if c == "" || c == "*" || strings.ContainsAny(c, " ()") {
			return nil
		}
		out = append(out, c)
	}
	return out
}

func (localAVSession) open(key string) (registry.Key, avvendor.RegistryStatus) {
	if key == "" || len(key) > 1024 {
		return 0, avvendor.RegistryError
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	switch {
	case err == nil:
		return k, avvendor.RegistryFound
	case errors.Is(err, registry.ErrNotExist):
		return 0, avvendor.RegistryNotFound
	case errors.Is(err, errAccessDenied):
		return 0, avvendor.RegistryDenied
	}
	return 0, avvendor.RegistryError
}

func regResult(st avvendor.RegistryStatus, values ...string) avvendor.RegistryResult {
	if st != avvendor.RegistryFound {
		return avvendor.RegistryResult{Status: st}
	}
	size := 0
	for _, v := range values {
		size += len(v)
	}
	if size > avMaxBytes || len(values) > avMaxEntries {
		return avvendor.RegistryResult{Status: avvendor.RegistryError}
	}
	return avvendor.RegistryResult{Status: avvendor.RegistryFound, Values: values}
}

func valueStatus(err error) avvendor.RegistryStatus {
	switch {
	case errors.Is(err, registry.ErrNotExist):
		return avvendor.RegistryNotFound
	case errors.Is(err, errAccessDenied):
		return avvendor.RegistryDenied
	}
	return avvendor.RegistryError
}

func (s localAVSession) RegistryString(_ context.Context, key, name string) avvendor.RegistryResult {
	k, st := s.open(key)
	if st != avvendor.RegistryFound {
		return avvendor.RegistryResult{Status: st}
	}
	defer k.Close()
	v, typ, err := k.GetStringValue(name)
	if err != nil || (typ != registry.SZ && typ != registry.EXPAND_SZ) {
		if err == nil {
			return avvendor.RegistryResult{Status: avvendor.RegistryError}
		}
		return avvendor.RegistryResult{Status: valueStatus(err)}
	}
	return regResult(st, v)
}
func (s localAVSession) RegistryDWORD(_ context.Context, key, name string) avvendor.RegistryResult {
	k, st := s.open(key)
	if st != avvendor.RegistryFound {
		return avvendor.RegistryResult{Status: st}
	}
	defer k.Close()
	v, typ, err := k.GetIntegerValue(name)
	if err != nil {
		return avvendor.RegistryResult{Status: valueStatus(err)}
	}
	if typ != registry.DWORD {
		return avvendor.RegistryResult{Status: avvendor.RegistryError}
	}
	return regResult(st, strconv.FormatUint(v, 10))
}
func (s localAVSession) RegistryQWORD(_ context.Context, key, name string) avvendor.RegistryResult {
	k, st := s.open(key)
	if st != avvendor.RegistryFound {
		return avvendor.RegistryResult{Status: st}
	}
	defer k.Close()
	v, typ, err := k.GetIntegerValue(name)
	if err != nil {
		return avvendor.RegistryResult{Status: valueStatus(err)}
	}
	if typ != registry.QWORD {
		return avvendor.RegistryResult{Status: avvendor.RegistryError}
	}
	return regResult(st, strconv.FormatUint(v, 10))
}
func (s localAVSession) RegistryBinary(_ context.Context, key, name string) avvendor.RegistryResult {
	k, st := s.open(key)
	if st != avvendor.RegistryFound {
		return avvendor.RegistryResult{Status: st}
	}
	defer k.Close()
	v, typ, err := k.GetBinaryValue(name)
	if err != nil {
		return avvendor.RegistryResult{Status: valueStatus(err)}
	}
	if typ != registry.BINARY || len(v) > avMaxEntries {
		return avvendor.RegistryResult{Status: avvendor.RegistryError}
	}
	out := make([]string, len(v))
	for i, b := range v {
		out[i] = strconv.Itoa(int(b))
	}
	return regResult(st, out...)
}
func (s localAVSession) RegistryMultiString(_ context.Context, key, name string) avvendor.RegistryResult {
	k, st := s.open(key)
	if st != avvendor.RegistryFound {
		return avvendor.RegistryResult{Status: st}
	}
	defer k.Close()
	v, typ, err := k.GetStringsValue(name)
	if err != nil {
		return avvendor.RegistryResult{Status: valueStatus(err)}
	}
	if typ != registry.MULTI_SZ {
		return avvendor.RegistryResult{Status: avvendor.RegistryError}
	}
	return regResult(st, v...)
}
func (s localAVSession) RegistrySubkeys(_ context.Context, key string) avvendor.RegistryResult {
	k, st := s.open(key)
	if st != avvendor.RegistryFound {
		return avvendor.RegistryResult{Status: st}
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(avMaxEntries + 1)
	if err != nil && len(names) == 0 {
		return avvendor.RegistryResult{Status: avvendor.RegistryError}
	}
	if names == nil {
		names = []string{}
	}
	return regResult(st, names...)
}
func (s localAVSession) Defender() avvendor.Observation { return s.defender }

// defenderObservation maps MSFT_MpComputerStatus exactly like the WinRM
// collector: Active only in AMRunningMode "Normal" with AntivirusEnabled
// present; the signature date only when Active is known.
func defenderObservation(ctx context.Context) avvendor.Observation {
	obs := avvendor.Observation{Active: "unknown"}
	rows, err := wqlRows(ctx, `root\Microsoft\Windows\Defender`, "SELECT AMRunningMode, AntivirusEnabled, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus")
	if err != nil || len(rows) != 1 {
		return obs
	}
	r := rows[0]
	mode, okMode := r["amrunningmode"]
	enabled, okEnabled := r["antivirusenabled"]
	if okMode && okEnabled && strings.EqualFold(strings.TrimSpace(mode), "normal") {
		switch strings.ToLower(enabled) {
		case "true":
			obs.Active = "enabled"
		case "false":
			obs.Active = "disabled"
		}
	}
	if obs.Active != "unknown" {
		if t, ok := parseDMTF(r["antivirussignaturelastupdated"]); ok {
			obs.SignatureLastUpdated = t
		}
	}
	return obs
}

func vendorsNative(ctx context.Context, products []string) []core.AVVendorEvidence {
	return CollectVendorsPrioritized(ctx, localAVSession{defender: defenderObservation(ctx)}, time.Now().UTC(), products)
}

var errAccessDenied = windows.ERROR_ACCESS_DENIED
