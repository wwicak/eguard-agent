//go:build windows

// nac-inspect performs one local read-only posture snapshot for an authorized Windows VM.
// Output contains device identities; redirect only into a private temporary directory.
package main

import (
	"context"
	"eguard-nac-agent/boundary"
	"eguard-nac-agent/collector"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--nac-fixed-collect" {
		if boundary.AwaitGate(os.Stdin, boundary.GateTimeout) != nil {
			os.Exit(2)
		}
		p := collector.CollectNative(context.Background(), "")
		if err := json.NewEncoder(os.Stdout).Encode(p); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	path, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspection unavailable")
		os.Exit(1)
	}
	p, err := boundary.Collect(ctx, path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspection unavailable")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(p); err != nil {
		fmt.Fprintln(os.Stderr, "posture output unavailable")
		os.Exit(1)
	}
}
