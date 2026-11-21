package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type normalizeFunc func([]string) ([]target, error)

func (f normalizeFunc) Normalize(hosts []string) ([]target, error) {
	return f(hosts)
}

type checkFunc func(context.Context, string, uint16, time.Duration) Result

func (f checkFunc) Check(ctx context.Context, address string, port uint16, timeout time.Duration) Result {
	return f(ctx, address, port, timeout)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func scannerWith(t *testing.T, n int, f checkFunc) *Scanner {
	t.Helper()
	s, err := New(Config{Concurrency: n, ConnectTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s.checker = f
	return s
}

func receive[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case v, ok := <-ch:
		if !ok {
			t.Fatal("channel closed unexpectedly")
		}
		return v
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
		var zero T
		return zero
	}
}

func collect(t *testing.T, ctx context.Context, ch <-chan Result) []Result {
	t.Helper()
	var results []Result
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return results
			}
			results = append(results, r)
		case <-ctx.Done():
			t.Fatal("result channel did not close")
			return nil
		}
	}
}

func TestValidation(t *testing.T) {
	for _, c := range []Config{{}, {-1, time.Second}, {1, 0}, {0, time.Second}, {1, -1}} {
		if s, err := New(c); err == nil || s != nil {
			t.Fatalf("New(%+v) = %v, %v", c, s, err)
		}
	}
	s := scannerWith(t, 1, func(context.Context, string, uint16, time.Duration) Result {
		t.Error("check called for invalid input")
		return Result{}
	})
	p, _ := Ports(80)
	ctx := testContext(t)
	for _, hosts := range [][]string{nil, {}, {""}, {"ok.example", "bad:80"}, {"http://example.com"}, {"[::1]"}} {
		if ch, err := s.Scan(ctx, hosts, p); err == nil || ch != nil {
			t.Fatal(hosts, ch, err)
		}
	}
	if ch, err := s.Scan(ctx, []string{"localhost"}, PortSet{}); err == nil || ch != nil {
		t.Fatal(ch, err)
	}
	if ch, err := s.Scan(nil, []string{"localhost"}, p); err == nil || ch != nil {
		t.Fatal(ch, err)
	}
	for _, deadline := range []bool{false, true} {
		var canceled context.Context
		var cancel context.CancelFunc
		if deadline {
			canceled, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
		} else {
			canceled, cancel = context.WithCancel(ctx)
			cancel()
		}
		ch, err := s.Scan(canceled, []string{"localhost"}, p)
		if ch != nil || !errors.Is(err, canceled.Err()) {
			t.Fatal(ch, err)
		}
		cancel()
	}
	var zero Scanner
	if ch, err := zero.Scan(ctx, []string{"localhost"}, p); err == nil || ch != nil {
		t.Fatal(ch, err)
	}
	// Errors from the consumer dependency are preserved, not reconstructed.
	want := errors.New("normalization failed")
	s.targets = normalizeFunc(func([]string) ([]target, error) { return nil, want })
	if ch, err := s.Scan(ctx, []string{"localhost"}, p); ch != nil || err != want {
		t.Fatal(ch, err)
	}
}

func TestPairsStatesAndSnapshots(t *testing.T) {
	ctx := testContext(t)
	states := []State{Open, Closed, Timeout, Unreachable, Canceled, Error}
	wantStates := []State{Open, Closed, Timeout, Unreachable, Canceled, Error}
	wantErr := fmt.Errorf("original: %w", errors.New("connection failure"))
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	s := scannerWith(t, 1, func(ctx context.Context, h string, p uint16, d time.Duration) Result {
		if h != "example.com" && h != "192.0.2.1" {
			t.Errorf("connection address %q", h)
		}
		if d != time.Second {
			t.Errorf("timeout %v", d)
		}
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-ctx.Done():
		}
		i := int(p) - 1
		var err error
		if i != 0 {
			err = wantErr
		}
		return Result{Host: h, Port: p, IP: net.IP{127, 0, 0, 1}, State: states[i], Duration: time.Duration(p), Err: err}
	})
	hosts := []string{" EXAMPLE.Com. ", "example.com", "::ffff:192.0.2.1", "192.0.2.1"}
	p, _ := Ports(1, 2, 3, 4, 5, 6, 1)
	ch, err := s.Scan(ctx, hosts, p)
	if err != nil {
		t.Fatal(err)
	}
	receive(t, ctx, started)
	hosts[0] = "mutated.example"
	p.Values()[0] = 999
	close(gate)
	got := collect(t, ctx, ch)
	if len(got) != 12 {
		t.Fatalf("got %d results", len(got))
	}
	seen := map[string]bool{}
	for _, r := range got {
		if r.Host != " EXAMPLE.Com. " && r.Host != "::ffff:192.0.2.1" {
			t.Fatal(r)
		}
		key := fmt.Sprintf("%s:%d", r.Host, r.Port)
		if seen[key] {
			t.Fatal("duplicate", key)
		}
		seen[key] = true
		i := int(r.Port) - 1
		if r.State != wantStates[i] || string(r.State) != string(states[i]) || r.Duration != time.Duration(r.Port) || !r.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatal(r)
		}
		if i == 0 && r.Err != nil || i != 0 && r.Err != wantErr {
			t.Fatal("error not preserved", r)
		}
	}
	got[0].IP[0] = 99
	if got[1].IP[0] == 99 {
		t.Fatal("results share mutable IP")
	}
}

func TestIndependentConcurrentPoolsAndReuse(t *testing.T) {
	ctx := testContext(t)
	const n = 3
	started := make(chan struct{}, 2*n)
	gate := make(chan struct{})
	var active, peak atomic.Int32
	s := scannerWith(t, n, func(ctx context.Context, h string, p uint16, d time.Duration) Result {
		a := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); a > old; old = peak.Load() {
			if peak.CompareAndSwap(old, a) {
				break
			}
		}
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-ctx.Done():
		}
		return Result{Port: p, State: Open}
	})
	const pairs = 4 * n
	p, _ := Range(1, pairs)
	// Simultaneous calls must both reach their own limit, not share a semaphore.
	channels := make(chan (<-chan Result), 2)
	var calls sync.WaitGroup
	for i := 0; i < 2; i++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			ch, err := s.Scan(ctx, []string{"localhost"}, p)
			if err != nil {
				t.Error(err)
			}
			channels <- ch
		}()
	}
	calls.Wait()
	a, b := <-channels, <-channels
	for i := 0; i < 2*n; i++ {
		receive(t, ctx, started)
	}
	if active.Load() != 2*n {
		t.Fatal("pools not independent", active.Load())
	}
	close(gate)
	if len(collect(t, ctx, a)) != pairs || len(collect(t, ctx, b)) != pairs {
		t.Fatal("missing pairs")
	}
	for i := 0; i < 2; i++ {
		ch, err := s.Scan(ctx, []string{"localhost"}, p)
		if err != nil {
			t.Fatal(err)
		}
		if len(collect(t, ctx, ch)) != pairs {
			t.Fatal("reuse failed")
		}
	}
	if active.Load() != 0 || peak.Load() > 2*n {
		t.Fatal(active.Load(), peak.Load())
	}
	// Sequential reuse must obey one pool's bound as well.
	peak.Store(0)
	ch, err := s.Scan(ctx, []string{"localhost"}, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(collect(t, ctx, ch)) != pairs || peak.Load() > n {
		t.Fatal("per-call concurrency exceeded", peak.Load())
	}
}

func TestCancelActiveChecks(t *testing.T) {
	guard := testContext(t)
	ctx, cancel := context.WithCancel(guard)
	defer cancel()
	const n = 4
	started, stopped := make(chan struct{}, n), make(chan struct{}, n)
	finish := make(chan struct{})
	var finishOnce sync.Once
	release := func() { finishOnce.Do(func() { close(finish) }) }
	t.Cleanup(release)
	var calls atomic.Int32
	s := scannerWith(t, n, func(ctx context.Context, h string, p uint16, d time.Duration) Result {
		calls.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		stopped <- struct{}{}
		<-finish
		return Result{Port: p, State: Canceled, Err: ctx.Err()}
	})
	p, _ := Range(1, 65535)
	ch, err := s.Scan(ctx, []string{"localhost"}, p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		receive(t, guard, started)
	}
	cancel()
	for i := 0; i < n; i++ {
		receive(t, guard, stopped)
	}
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatal("results closed before active checks returned")
		}
		t.Fatal("result delivered before the check returned")
	default:
	}
	release()
	collect(t, guard, ch)
	if calls.Load() != n {
		t.Fatal("new checks after cancellation", calls.Load())
	}
}

func TestBackpressureAndAbandonedReader(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelEarly), func(t *testing.T) {
			guard := testContext(t)
			ctx, cancel := context.WithCancel(guard)
			defer cancel()
			// With a single worker and a one-result buffer, the second completed
			// check cannot be followed by a third until reading (or cancellation).
			completed := make(chan uint16, 100)
			var count atomic.Int32
			s := scannerWith(t, 1, func(ctx context.Context, h string, p uint16, d time.Duration) Result {
				count.Add(1)
				completed <- p
				return Result{Port: p, State: Open}
			})
			p, _ := Range(1, 100)
			ch, err := s.Scan(ctx, []string{"localhost"}, p)
			if err != nil {
				t.Fatal(err)
			}
			receive(t, guard, completed)
			receive(t, guard, completed)
			if count.Load() != 2 {
				t.Fatal("unbounded work without reader", count.Load())
			}
			if cancelEarly {
				cancel()
				// Observe closure even when the worker was blocked on delivery.
				got := collect(t, guard, ch)
				if len(got) > 2 || count.Load() != 2 {
					t.Fatal("work continued after cancellation", len(got), count.Load())
				}
			} else {
				got := collect(t, guard, ch)
				if len(got) != 100 {
					t.Fatal("slow reader lost results", len(got))
				}
			}
		})
	}
}

func TestNormalizerSnapshotAndCancellation(t *testing.T) {
	guard := testContext(t)
	ctx, cancel := context.WithCancel(guard)
	defer cancel()
	s := scannerWith(t, 1, func(context.Context, string, uint16, time.Duration) Result {
		t.Error("unexpected check")
		return Result{}
	})
	hosts := []string{"localhost"}
	s.targets = normalizeFunc(func(h []string) ([]target, error) {
		h[0] = "changed"
		cancel()
		return []target{{host: "localhost", address: "localhost"}}, nil
	})
	p, _ := Ports(80)
	ch, err := s.Scan(ctx, hosts, p)
	if ch != nil || !errors.Is(err, context.Canceled) || !reflect.DeepEqual(hosts, []string{"localhost"}) {
		t.Fatal(ch, err, hosts)
	}
}
