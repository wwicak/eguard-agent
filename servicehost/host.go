// Package servicehost owns the platform-neutral service lifecycle. It has no
// default bootstrap: callers must provide a verified runner factory.
package servicehost

import (
	"context"
	"errors"
	"time"
)

var ErrConfigurationRequired = errors.New("NAC verified bootstrap configuration required")
var ErrRunnerStopped = errors.New("NAC runner exited without a stop request")

type Status uint8

const (
	StartPending Status = iota + 1
	Running
	StopPending
)

type Command uint8

const (
	Stop Command = iota + 1
)

// Runner must honor cancellation and return; Run never abandons it. Factory
// must have verified trust/bootstrap before returning the runner and must not
// collect, send, or create a journal during failure paths.
type Runner func(context.Context) error
type Factory func() (Runner, error)

// Run calls Factory before Running. The sole runner executes serially. On Stop
// cancellation is cooperative; repeated StopPending notifications keep SCM
// informed while Run waits for the runner, without reporting a false success.
func Run(factory Factory, commands <-chan Command, report func(Status)) error {
	notify := func(s Status) {
		if report != nil {
			report(s)
		}
	}
	notify(StartPending)
	if factory == nil {
		return ErrConfigurationRequired
	}
	runner, err := factory()
	if err != nil {
		// Keep the factory's reason for the event log; still matchable.
		return errors.Join(ErrConfigurationRequired, err)
	}
	if runner == nil {
		return ErrConfigurationRequired
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	notify(Running)
	go func() { done <- runner(ctx) }()
	for {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
			return ErrRunnerStopped
		case cmd, ok := <-commands:
			if !ok || cmd == Stop {
				cancel()
				notify(StopPending)
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						notify(StopPending)
					case err := <-done:
						if err == nil || errors.Is(err, context.Canceled) {
							return nil
						}
						return err
					}
				}
			}
		}
	}
}
