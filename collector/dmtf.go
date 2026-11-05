package collector

import (
	"strconv"
	"time"
)

// parseDMTF parses a WMI DMTF datetime "yyyymmddHHMMSS.ffffff+UUU" (UUU =
// UTC offset in minutes). Anything else is not a date.
func parseDMTF(raw string) (time.Time, bool) {
	if len(raw) != 25 || raw[14] != '.' || (raw[21] != '+' && raw[21] != '-') {
		return time.Time{}, false
	}
	for i, c := range raw {
		if i == 14 || i == 21 {
			continue
		}
		if c < '0' || c > '9' {
			return time.Time{}, false
		}
	}
	mins, err := strconv.Atoi(raw[22:])
	if err != nil || mins > 14*60 {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102150405", raw[:14])
	if err != nil || t.Year() < 1971 {
		return time.Time{}, false
	}
	off := time.Duration(mins) * time.Minute
	if raw[21] == '+' {
		t = t.Add(-off)
	} else {
		t = t.Add(off)
	}
	return t.UTC(), true
}
