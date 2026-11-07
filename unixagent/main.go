//go:build linux || darwin

package unixagent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"eguard-nac-agent/boundary"
	"eguard-nac-agent/collector"
	"eguard-nac-agent/core"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/servicefactory"
	"eguard-nac-agent/uninstall"
)

func Main(args []string) error {
	if len(args) == 1 && args[0] == "--nac-fixed-collect" {
		if e := boundary.AwaitGate(os.Stdin, boundary.GateTimeout); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(collector.CollectNative(context.Background(), ""))
	}
	if len(args) == 4 && args[0] == boundary.InventoryVerb {
		return errors.New("invalid inventory arguments")
	}
	if len(args) == 3 && args[0] == boundary.InventoryVerb && (args[1] == "on" || args[1] == "off") && (args[2] == "on" || args[2] == "off") {
		if e := boundary.AwaitGate(os.Stdin, boundary.GateTimeout); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(collector.CollectInventory(context.Background(), args[1] == "on", args[2] == "on"))
	}
	if len(args) == 0 {
		return serve()
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: eguard-nac status")
		}
		if _, e := provision.LoadConfig(provision.Root); e != nil {
			fmt.Println("Not enrolled or provisioning unavailable.")
			return nil
		}
		fmt.Println("Enrolled. Service health and lifecycle eligibility are not implied.")
		return nil
	case "enroll":
		f := flag.NewFlagSet("enroll", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		server := f.String("server", "", "")
		fp := f.String("fingerprint", "", "")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if f.NArg() != 1 {
			return errors.New("usage: eguard-nac enroll --server HOST:PORT --fingerprint HEX CODE")
		}
		if e := selfValidate(*server, *fp, f.Arg(0)); e != nil {
			return e
		}
		if os.Geteuid() != 0 {
			return errors.New("root privileges are required")
		}
		return Enroll(provision.Root, *server, *fp, f.Arg(0), runCommand)
	case "uninstall":
		f := flag.NewFlagSet("uninstall", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		token := f.String("token", "", "")
		file := f.String("authorization", "", "")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if f.NArg() != 0 || (*token != "" && *file != "") {
			return errors.New("usage: eguard-nac uninstall [--token TOKEN | --authorization FILE]")
		}
		if os.Geteuid() != 0 {
			return errors.New("root privileges are required")
		}
		var raw []byte
		var e error
		if *token != "" {
			raw, e = uninstall.DecodeToken(*token)
		} else if *file != "" {
			raw, e = os.ReadFile(*file)
		}
		if e != nil {
			return e
		}
		if len(raw) > 64<<10 {
			return errors.New("authorization exceeds limit")
		}
		return Remove(provision.Root, raw, runCommand)
	}
	return errors.New("usage: eguard-nac enroll | status | uninstall")
}

func serve() error {
	if _, e := os.Lstat(provision.Root + "/state.json"); os.IsNotExist(e) {
		fmt.Println("Not enrolled.")
		return nil
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	factory := servicefactory.New(servicefactory.Deps{Root: provision.Root, ResolveCredential: ResolveCredential(provision.Root), Now: func() (time.Time, error) { return time.Now(), nil }, Collect: func(ctx context.Context) (core.Posture, error) { return boundary.Collect(ctx, self) }, CollectInventory: func(ctx context.Context, s, u bool) (core.Inventory, error) {
		return boundary.CollectInventory(ctx, self, s, u)
	}, OnTerminal: func(_ string, _ [32]byte) error { return TerminalCleanup(provision.Root, runCommand) }})
	runner, e := factory()
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	e = runner(ctx)
	if errors.Is(e, servicefactory.ErrTerminal) {
		return nil
	}
	return e
}
