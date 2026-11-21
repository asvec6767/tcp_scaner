package tcpcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestClassifyWrappedErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want State
	}{
		{"refused", syscall.ECONNREFUSED, Closed},
		{"network", syscall.ENETUNREACH, Unreachable},
		{"host", syscall.EHOSTUNREACH, Unreachable},
		{"system timeout", syscall.ETIMEDOUT, Timeout},
		{"dial deadline", context.DeadlineExceeded, Timeout},
		{"cancel", context.Canceled, Canceled},
		{"dns missing", &net.DNSError{IsNotFound: true}, Error},
		{"dns timeout", &net.DNSError{IsTimeout: true}, Timeout},
		{"dns refused is not closed", &net.DNSError{UnwrapErr: syscall.ECONNREFUSED}, Error},
		{"other", errors.New("connection refused"), Error},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := fmt.Errorf("wrapped: %w", &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: tt.err}})
			if got := classify(context.Background(), err); got != tt.want {
				t.Fatalf("classify(%v) = %s, want %s", err, got, tt.want)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if got := classify(ctx, err); got != Canceled {
				t.Fatalf("external cancellation lost: %s", got)
			}
		})
	}
}

// Моделирует интервал между дедлайном и публикацией Err
type pendingDeadline struct{ context.Context }

func (pendingDeadline) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

func TestClassifyExternalDeadlineBeforeErr(t *testing.T) {
	ctx := pendingDeadline{context.Background()}
	err := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	if got := classify(ctx, err); got != Canceled {
		t.Fatalf("expired external deadline classified as %s", got)
	}
	future, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if got := classify(future, err); got != Timeout {
		t.Fatalf("own timeout before external deadline classified as %s", got)
	}
}
