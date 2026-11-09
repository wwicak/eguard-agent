package collector

import (
	"eguard-nac-agent/core"
	"fmt"
	"strings"
)

type routeRecord struct {
	Index  uint32
	Prefix string
}

// Route presence is established only for an exact default prefix and matching nonzero index.
// No records, even from a successful query, do not prove absence of connectivity.
func routeEvidence(index uint32, ipv4, ipv6 []routeRecord, valid bool) core.Tri {
	if !valid || index == 0 {
		return core.Unknown
	}
	for _, r := range ipv4 {
		if r.Index == index && r.Prefix == "0.0.0.0/0" {
			return core.Yes
		}
	}
	for _, r := range ipv6 {
		if r.Index == index && strings.EqualFold(r.Prefix, "::/0") {
			return core.Yes
		}
	}
	return core.Unknown
}
func osBuild(major, minor, build uint32) string {
	if major == 0 || build == 0 {
		return "unknown"
	}
	return fmt.Sprintf("windows-%d.%d.%d", major, minor, build)
}
