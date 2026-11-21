package portscan

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/asvec6767/tcp_scaner/internal/tcpcheck"
)

func TestResultFromCheck(t *testing.T) {
	wantErr := errors.New("original connection error")
	for _, tt := range []struct {
		internal tcpcheck.State
		public   State
		value    string
	}{
		{tcpcheck.Open, Open, "open"},
		{tcpcheck.Closed, Closed, "closed"},
		{tcpcheck.Timeout, Timeout, "timeout"},
		{tcpcheck.Unreachable, Unreachable, "unreachable"},
		{tcpcheck.Canceled, Canceled, "canceled"},
		{tcpcheck.Error, Error, "error"},
	} {
		t.Run(tt.value, func(t *testing.T) {
			var err error
			if tt.internal != tcpcheck.Open {
				err = wantErr
			}
			input := tcpcheck.Result{
				Host: "example.com", IP: net.IP{127, 0, 0, 1}, Port: 443,
				State: tt.internal, Duration: time.Millisecond, Err: err,
			}
			got := resultFromCheck(input)
			if got.Host != input.Host || got.Port != input.Port ||
				got.Duration != input.Duration || got.Err != err ||
				got.State != tt.public || string(got.State) != tt.value || !got.IP.Equal(input.IP) {
				t.Fatalf("conversion changed check data: %+v", got)
			}
			input.IP[0] = 9
			if got.IP[0] != 127 {
				t.Fatal("public result shares mutable IP with check")
			}
		})
	}
	if got := resultFromCheck(tcpcheck.Result{}); got.IP != nil {
		t.Fatal("absent IP was synthesized")
	}
}

func TestNormalizeTargetsAdapter(t *testing.T) {
	hosts := []string{" EXAMPLE.Com. ", "example.com", "::ffff:192.0.2.1", "192.0.2.1"}
	got, err := (targetsAdapter{}).Normalize(hosts)
	want := []target{
		{host: hosts[0], address: "example.com"},
		{host: hosts[2], address: "192.0.2.1"},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize() = %#v, %v", got, err)
	}
	hosts[0] = "changed.example"
	if !reflect.DeepEqual(got, want) {
		t.Fatal("adapter retained input storage")
	}
	if got, err := (targetsAdapter{}).Normalize([]string{"localhost", "bad:80"}); got != nil || err == nil {
		t.Fatal(got, err)
	}
}

func TestCheckConnectionCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(testContext(t))
	cancel()
	r := (tcpcheckAdapter{}).Check(ctx, "127.0.0.1", 80, time.Second)
	if r.Host != "127.0.0.1" || r.Port != 80 || r.State != Canceled ||
		!errors.Is(r.Err, context.Canceled) || r.IP != nil {
		t.Fatalf("unexpected adapted check: %+v", r)
	}
}
