//go:build linux || darwin

package main

import (
	"eguard-nac-agent/unixagent"
	"fmt"
	"os"
)

func main() {
	if e := unixagent.Main(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "eGuard NAC:", e)
		os.Exit(1)
	}
}
