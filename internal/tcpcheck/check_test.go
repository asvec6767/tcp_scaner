package tcpcheck_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/asvec6767/tcp_scaner/internal/tcpcheck"
)

func TestCheckOpen(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			listener := listen(t, host)
			addr := listener.Addr().(*net.TCPAddr)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			result := tcpcheck.Check(ctx, host, uint16(addr.Port), time.Second)
			elapsed := time.Since(start)
			if result.State != tcpcheck.Open || result.Err != nil {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.Host != host || result.Port != uint16(addr.Port) || !result.IP.Equal(addr.IP) {
				t.Fatalf("unexpected target: %+v", result)
			}
			if result.Duration < 0 || result.Duration > elapsed {
				t.Fatalf("duration %s outside [0, %s]", result.Duration, elapsed)
			}
			// Observe closure from the peer, without inspecting implementation.
			if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("connection not closed: n=%d, err=%v", n, err)
			}
		})
	}
}

func TestCheckCanceled(t *testing.T) {
	listener := listen(t, "127.0.0.1")
	addr := listener.Addr().(*net.TCPAddr)
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			start := time.Now()
			result := tcpcheck.Check(ctx, "127.0.0.1", uint16(addr.Port), time.Second)
			elapsed := time.Since(start)
			if result.State != tcpcheck.Canceled || !errors.Is(result.Err, ctx.Err()) {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.Host != "127.0.0.1" || result.Port != uint16(addr.Port) || result.IP != nil {
				t.Fatalf("unexpected target: %+v", result)
			}
			if result.Duration < 0 || result.Duration > elapsed {
				t.Fatalf("duration %s outside [0, %s]", result.Duration, elapsed)
			}
		})
	}
}

func listen(t *testing.T, host string) *net.TCPListener {
	t.Helper()
	addr := &net.TCPAddr{IP: net.ParseIP(host)}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		if host == "::1" {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}
