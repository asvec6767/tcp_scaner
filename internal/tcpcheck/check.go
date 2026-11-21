// пакет tcpcheck выполняет одну проверку TCP-соединения
package tcpcheck

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

// результат проверки TCP-соединения
type State string

const (
	Open        State = "open"
	Closed      State = "closed"
	Timeout     State = "timeout"
	Unreachable State = "unreachable"
	Canceled    State = "canceled"
	Error       State = "error"
)

// фактический IP адрес или ошибка
type Result struct {
	Host     string
	IP       net.IP // заполняется только при успешном подключении
	Port     uint16
	State    State
	Duration time.Duration // включает в себя разрешение DNS и настройку подключения
	Err      error
}

// разовая проверка
// подключение немедленно завершается; ошибка закрытия не отменяет успеха соединения
func Check(ctx context.Context, host string, port uint16, timeout time.Duration) Result {
	dialer := net.Dialer{Timeout: timeout}
	result := Result{Host: host, Port: port}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	result.Duration = time.Since(start)
	result.Err = err
	if err != nil {
		result.State = classify(ctx, err)
		return result
	}
	addr := conn.RemoteAddr()
	_ = conn.Close()
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		result.IP = append(net.IP(nil), tcpAddr.IP...)
	}
	result.State = Open
	return result
}

func classify(ctx context.Context, err error) State {
	if ctx.Err() != nil {
		return Canceled
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.Timeout() {
			return Timeout
		}
		return Error
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		return Timeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return Closed
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return Unreachable
	}
	return platformState(err)
}
