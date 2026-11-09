package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed read-only root/cimv2 query; the short service Name is not documented.
const ntwServiceQuery = `SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service WHERE DisplayName='Virus Chaser Spider NT' OR PathName LIKE '%\\Virus Chaser\\spidernt.exe%'`

var ntw = Descriptor{
	ID:          "ntw",
	DisplayName: "NTW Virus Chaser (EOL) (unverified)",
	Source:      "Win32_Service DisplayName Virus Chaser Spider NT / PathName SpiderNT.exe (root/cimv2; pihak ketiga F5/F6, https://daniweb.com/hardware-and-software/microsoft-windows/threads/16788/wmp-internal-application-erros-has-occurred dan https://seclists.org/fulldisclosure/2007/Aug/492); EOL pattern 5.0a/Plus 2009-07-01 (resmi F9, https://www.viruschaser.com/notice/notice_view/notice_no=3440?page=1&keywordSelect=&keyword=); belum diverifikasi lab (disetujui Boss)",
	Query:       ntwServiceQuery, StatusOnly: true, TemplateID: "av-not-active-ntw", Collect: collectNTW,
}

func collectNTW(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, ntwServiceQuery)
	if errCtx := ctx.Err(); errCtx != nil {
		return out, errCtx
	}
	if err != nil {
		return out, nil
	}
	if len(rows) == 0 {
		out.Absent = true
		return out, nil
	}
	// More than one candidate or contradictory evidence is ambiguous.
	found := false
	for _, row := range rows {
		if !strings.EqualFold(row["displayname"], "Virus Chaser Spider NT") && !strings.HasSuffix(strings.ToLower(row["pathname"]), `\virus chaser\spidernt.exe`) {
			continue
		}
		if found {
			return Observation{Active: "unknown"}, nil
		}
		found = true
		switch {
		case strings.EqualFold(row["startmode"], "Disabled"):
			out.Active = "disabled"
		case strings.EqualFold(row["state"], "Running"):
			out.Active = "enabled"
		case row["state"] != "":
			out.Active = "disabled"
		}
	}
	return out, nil
}
