package installtransaction

import (
	"context"
	"fmt"
	"time"
)

func rollback(ctx context.Context, a Adapter, interval time.Duration) error {
	s, err := a.Lookup(ctx)
	if err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	if s.State == Missing {
		return nil
	}
	if s.Binary != BinaryPath {
		return ErrExisting
	}
	if s.State != Stopped {
		if err = a.Stop(ctx); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err = ctx.Err(); err != nil {
				return err
			}
			s, err = a.Lookup(ctx)
			if err != nil {
				return err
			}
			if s.Binary != BinaryPath || s.State == Missing {
				return ErrExisting
			}
			if s.State == Stopped {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
	if err = a.Delete(ctx); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}
