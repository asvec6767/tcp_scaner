package portscan_test

import (
	"context"
	"net"
	"testing"
	"time"

	portscan "github.com/asvec6767/tcp_scaner"
)

func TestLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	s, err := portscan.New(portscan.Config{Concurrency: 2, ConnectTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := portscan.Ports(addr.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := s.Scan(ctx, []string{" 127.0.0.1 ", "127.0.0.1"}, p)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				if count != 1 {
					t.Fatal(count)
				}
				return
			}
			count++
			if r.Host != " 127.0.0.1 " || r.Port != uint16(addr.Port) || r.State != portscan.Open || r.Err != nil || !r.IP.Equal(addr.IP) || r.Duration < 0 {
				t.Fatal(r)
			}
		case <-ctx.Done():
			t.Fatal("scan did not close")
		}
	}
}
