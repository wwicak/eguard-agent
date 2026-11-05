package boundary

import (
	"errors"
	"io"
	"os"
	"time"
)

// AwaitGate must run before ANY fixed collector work. A child without a private
// inherited stdin handle, or whose parent dies before release, fails closed.
const gateByte byte = 0x47
const GateTimeout = 5 * time.Second

func AwaitGate(in *os.File, timeout time.Duration) error {
	if in == nil || timeout <= 0 {
		return errors.New("collector gate unavailable")
	}
	result := make(chan error, 1)
	go func() {
		var b [1]byte
		n, e := io.ReadFull(in, b[:])
		if e != nil {
			result <- e
			return
		}
		if n != 1 || b[0] != gateByte {
			result <- errors.New("collector gate invalid")
			return
		}
		result <- nil
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case e := <-result:
		return e
	case <-timer.C:
		_ = in.Close() // unblock read; no gate reader survives timeout
		return errors.New("collector gate timeout")
	}
}
