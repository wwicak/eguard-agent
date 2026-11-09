// Package avvendor is the closed allowlist of verified signature-age collectors.
// Descriptors are immutable by convention; exported lookups return value copies.
package avvendor

import (
	"context"
	"sort"
	"sync"
	"time"
)

// RegistryStatus describes one HKLM read, not whether an AV is installed.
type RegistryStatus uint8

const (
	RegistryError RegistryStatus = iota // transport, shape, size or provider failure
	RegistryFound
	RegistryNotFound
	RegistryDenied
)

// RegistryResult is bounded to 64 KiB total and 256 entries. Scalar reads
// return exactly one entry (including an empty string); EnumKey may be empty.
// Binary entries are canonical decimal bytes (0..255). QWORD is decimal.
type RegistryResult struct {
	Status RegistryStatus
	Values []string
}

// Session only permits read-only HKLM StdRegProv and root/cimv2 WQL.
// Paths, value names and queries must be reviewed file-level vendor constants.
// Enumerate can also read CIM_DataFile metadata in root/cimv2; it never
// opens or copies file contents.
type Session interface {
	Enumerate(context.Context, string) ([]map[string]string, error)
	RegistryString(context.Context, string, string) RegistryResult
	RegistryDWORD(context.Context, string, string) RegistryResult
	RegistryQWORD(context.Context, string, string) RegistryResult
	RegistryBinary(context.Context, string, string) RegistryResult
	RegistryMultiString(context.Context, string, string) RegistryResult
	RegistrySubkeys(context.Context, string) RegistryResult
	Defender() Observation
}

// Observation is a provider assertion; unknown Active may still carry a date.
type Observation struct {
	Absent               bool   // clean, complete reads proved product not present
	Active               string // enabled, disabled, or unknown
	SignatureLastUpdated time.Time
}

// Collector runs on the bound endpoint session at the trusted collection instant.
// An error discards this vendor alone.
type Collector func(context.Context, Session, time.Time) (Observation, error)

type Descriptor struct {
	Collect Collector

	ID           string
	DisplayName  string
	Source       string
	Query        string // fixed, reviewed read-only query; never accept caller input
	ParseDate    func(string) (time.Time, bool)
	ExampleHours int
	TemplateID   string
	// StatusOnly marks a vendor with no local signature date (cloud/ML or
	// end-of-life products). It gets an "AV not active" draft instead of an
	// age template, which could only ever evaluate to Unknown.
	StatusOnly bool
}

var registryMu sync.RWMutex
var registry = map[string]Descriptor{
	defender.ID:          defender, // Register one reviewed vendor descriptor here.
	trellixENS.ID:        trellixENS,
	symantec.ID:          symantec,
	crowdstrike.ID:       crowdstrike,
	carbonblack.ID:       carbonblack,
	cylance.ID:           cylance,
	malwarebytes.ID:      malwarebytes,
	forefront.ID:         forefront,
	mse.ID:               mse,
	fortinet.ID:          fortinet,
	trendmicro.ID:        trendmicro,
	eset.ID:              eset,
	avast.ID:             avast,
	avg.ID:               avg,
	fsecure.ID:           fsecure,
	gdata.ID:             gdata,
	panda.ID:             panda,
	vipre.ID:             vipre,
	webroot.ID:           webroot,
	clamav.ID:            clamav,
	hauri.ID:             hauri,
	k7.ID:                k7,
	estsoft.ID:           estsoft,
	escan.ID:             escan,
	ivantiLandesk.ID:     ivantiLandesk,
	rising.ID:            rising,
	caetrust.ID:          caetrust,
	ntw.ID:               ntw,
	bitdefender.ID:       bitdefender,
	comodo.ID:            comodo,
	kaspersky.ID:         kaspersky,
	ahnlab.ID:            ahnlab,
	activevirusshield.ID: activevirusshield,
	sophos.ID:            sophos,
	avira.ID:             avira,
	safe360.ID:           safe360,
	paloalto.ID:          paloalto,
}

func Lookup(id string) (Descriptor, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	d, ok := registry[id]
	return d, ok
}
func All() []Descriptor {
	registryMu.RLock()
	defer registryMu.RUnlock()
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Descriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, registry[id])
	}
	return out
}
func Allowed(id string) bool { _, ok := Lookup(id); return ok }

// RegisterForTest temporarily installs a synthetic collector. Never use on a
// running server; tests must not run parallel while the override is installed.
func RegisterForTest(t interface{ Cleanup(func()) }, d Descriptor) {
	if d.ID == "" || d.Collect == nil {
		panic("test vendor requires ID and collector")
	}
	registryMu.Lock()
	if _, exists := registry[d.ID]; exists {
		registryMu.Unlock()
		panic("test vendor already registered")
	}
	registry[d.ID] = d
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		delete(registry, d.ID)
		registryMu.Unlock()
	})
}
