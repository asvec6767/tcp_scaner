package tcpcheck

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
)

func TestWrappedWinsockErrors(t *testing.T) {
	for code, want := range map[error]State{
		wsaECONNREFUSED: Closed,
		wsaENETUNREACH:  Unreachable,
		wsaEHOSTUNREACH: Unreachable,
		wsaETIMEDOUT:    Timeout,
	} {
		err := fmt.Errorf("wrapped: %w", &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: code}})
		if got := classify(context.Background(), err); got != want {
			t.Fatalf("classify(%v) = %s, want %s", err, got, want)
		}
	}
}
