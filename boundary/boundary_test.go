package boundary

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("NAC_BOUNDARY_TEST_HELPER") != "1" {
		return
	}
	if os.Getenv("NAC_BOUNDARY_SCENARIO") != "ungated-grandchild" && AwaitGate(os.Stdin, GateTimeout) != nil {
		os.Exit(4)
	}
	switch os.Getenv("NAC_BOUNDARY_SCENARIO") {
	case "hang", "ungated-grandchild":
		time.Sleep(30 * time.Second)
	case "grandchild":
		child := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		child.Env = append(os.Environ(), "NAC_BOUNDARY_TEST_HELPER=1", "NAC_BOUNDARY_SCENARIO=ungated-grandchild")
		if child.Start() != nil {
			os.Exit(3)
		}
		_ = os.WriteFile(os.Getenv("NAC_TEST_PID_PATH"), []byte(strconv.Itoa(child.Process.Pid)), 0600)
		time.Sleep(30 * time.Second)
	case "oversize":
		os.Stdout.Write(make([]byte, 1<<20))
	case "malformed":
		os.Stdout.Write([]byte("not-json"))
	case "stale":
		os.Stdout.Write([]byte(`{"agent_type":"nac","observed_at":"2020-01-01T00:00:00Z","ttl":300000000000,"domain":{"part_of_domain":"unknown","match":"unknown"},"av":{"installed":"unknown","running":"unknown","updated":"unknown"},"firewall":{"domain":{"value":"unknown"},"private":{"value":"unknown"},"public":{"value":"unknown"}}}`))
	case "valid":
		os.Stdout.Write([]byte(`{"agent_type":"nac","observed_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","ttl":300000000000,"domain":{"part_of_domain":"unknown","match":"unknown"},"av":{"installed":"unknown","running":"unknown","updated":"unknown"},"firewall":{"domain":{"value":"unknown"},"private":{"value":"unknown"},"public":{"value":"unknown"}}}`))
	default:
		os.Exit(2)
	}
	os.Exit(0)
}
func TestBoundedOutputAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{{"valid", true}, {"hang", false}, {"oversize", false}, {"malformed", false}, {"stale", false}} {
		t.Run(tc.name, func(t *testing.T) {
			deadline := 400 * time.Millisecond
			if tc.valid {
				deadline = 3 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			p, err := run(ctx, func() *exec.Cmd {
				cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
				cmd.Env = append(os.Environ(), "NAC_BOUNDARY_TEST_HELPER=1", "NAC_BOUNDARY_SCENARIO="+tc.name)
				return cmd
			})
			if tc.valid && (err != nil || p.AgentType != "nac") {
				t.Fatalf("valid: %+v %v", p, err)
			}
			if !tc.valid && err == nil {
				t.Fatal("untrusted helper accepted")
			}
		})
	}
}
func TestRejectRelativeExecutable(t *testing.T) {
	_, err := Collect(context.Background(), "relative.exe")
	if err == nil {
		t.Fatal("relative executable accepted")
	}
}
func TestConcurrentLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_, _ = run(ctx, func() *exec.Cmd {
			close(started)
			c := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
			c.Env = append(os.Environ(), "NAC_BOUNDARY_TEST_HELPER=1", "NAC_BOUNDARY_SCENARIO=hang")
			return c
		})
		close(done)
	}()
	<-started
	for i := 0; i < 16; i++ {
		_, err := run(ctx, func() *exec.Cmd { return exec.Command(os.Args[0], "-test.run=^TestHelperProcess$") })
		if err != ErrBusy {
			t.Fatalf("overlapping collection accepted: %v", err)
		}
	}
	<-done
}
