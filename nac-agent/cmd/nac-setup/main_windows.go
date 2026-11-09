//go:build windows

// nac-setup is the elevated installer helper invoked by the NSIS wizard. Fixed verbs
// only; no arbitrary command execution.
//
//	nac-setup install <service.exe> <bootstrap.json> <activation.json>
//	nac-setup install-code <service.exe> <enrollment code>   (self-service)
//	nac-setup install-from-name <service.exe> <installer-filename>
//	nac-setup uninstall [authorization.json | /TOKEN=<token>]   (ON requires signed authorization)
//	nac-setup enroll  <bootstrap.json> <activation.json>   (provisioning only; tests)
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"eguard-nac-agent/admission"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/selfenroll"
	"eguard-nac-agent/setupflow"
	"eguard-nac-agent/uninstall"
	"golang.org/x/sys/windows"
)

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func main() {
	if elevated() {
		enableOwnerPrivileges()
	}
	switch {
	case len(os.Args) == 5 && os.Args[1] == "install":
		e := setupflow.Install(setupflow.Windows{SourceBinary: os.Args[2], Bootstrap: os.Args[3], Activation: os.Args[4]})
		if e != nil {
			fmt.Fprintln(os.Stderr, "Installation failed and was rolled back:", e)
			os.Exit(1)
		}
		fmt.Println("eGuard NAC installed, enrolled and running.")
	case len(os.Args) == 4 && (os.Args[1] == "install-code" || os.Args[1] == "install-from-name"):
		if !elevated() {
			fmt.Fprintln(os.Stderr, "Administrator rights are required.")
			os.Exit(5)
		}
		code := os.Args[3]
		if os.Args[1] == "install-from-name" {
			var ok bool
			code, ok = selfenroll.CodeFromInstallerName(code)
			if !ok {
				fmt.Fprintln(os.Stderr, "Installer filename has no valid enrollment code.")
				os.Exit(2)
			}
		}
		if e := installWithCode(os.Args[2], code); e != nil {
			fmt.Fprintln(os.Stderr, "Installation failed and was rolled back:", e)
			os.Exit(1)
		}
		fmt.Println("eGuard NAC enrolled with code, installed and running.")
	case len(os.Args) == 4 && os.Args[1] == "enroll":
		if !elevated() {
			fmt.Fprintln(os.Stderr, "Administrator rights are required.")
			os.Exit(5)
		}
		boot, e1 := os.ReadFile(os.Args[2])
		act, e2 := os.ReadFile(os.Args[3])
		if e1 != nil || e2 != nil {
			fmt.Fprintln(os.Stderr, "Enrollment files could not be read.")
			os.Exit(2)
		}
		// Wallclock at install time; activation validity is a short signed window.
		obs, e := admission.Install(provision.Root, boot, act, time.Now())
		if e != nil {
			fmt.Fprintln(os.Stderr, "Enrollment rejected:", e)
			os.Exit(1)
		}
		fmt.Printf("Enrolled: state=%s mode=%s revision=%d\n", obs.State, obs.Mode, obs.LifecycleRevision)
	case (len(os.Args) == 2 || len(os.Args) == 3) && os.Args[1] == "uninstall":
		if !elevated() {
			fmt.Fprintln(os.Stderr, "Administrator rights are required.")
			os.Exit(5)
		}
		var auth []byte
		if len(os.Args) == 3 {
			var e error
			if strings.HasPrefix(os.Args[2], "/TOKEN=") {
				// Offline: helpdesk reads out/pastes the signed authorization.
				if auth, e = uninstall.DecodeToken(strings.TrimPrefix(os.Args[2], "/TOKEN=")); e != nil {
					fmt.Fprintln(os.Stderr, "Uninstall token is not valid.")
					os.Exit(2)
				}
			} else if auth, e = os.ReadFile(os.Args[2]); e != nil {
				fmt.Fprintln(os.Stderr, "Authorization file could not be read.")
				os.Exit(2)
			}
		}
		if e := uninstall.Run(uninstall.Windows{}, auth, time.Now()); e != nil {
			fmt.Fprintln(os.Stderr, "Uninstall refused or failed:", e)
			os.Exit(1)
		}
		fmt.Println("eGuard NAC removed. Files in use are deleted at next restart.")
	default:
		fmt.Fprintln(os.Stderr, "usage: nac-setup install <service.exe> <bootstrap.json> <activation.json>")
		fmt.Fprintln(os.Stderr, "       nac-setup install-code <service.exe> <enrollment code>")
		fmt.Fprintln(os.Stderr, "       nac-setup install-from-name <service.exe> <installer-filename>")
		os.Exit(2)
	}
}
