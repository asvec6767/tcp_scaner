package tcpcheck

import (
	"errors"
	"syscall"
)

// Коды Winsock отличаются от POSIX-совместимых значений errno SYSCALL'ов
// Эти значения определены в Windows Sockets API (коды ошибок WSA)
const (
	wsaENETUNREACH  syscall.Errno = 10051
	wsaETIMEDOUT    syscall.Errno = 10060
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTUNREACH syscall.Errno = 10065
)

func platformState(err error) State {
	switch {
	case errors.Is(err, wsaETIMEDOUT):
		return Timeout
	case errors.Is(err, wsaECONNREFUSED):
		return Closed
	case errors.Is(err, wsaENETUNREACH), errors.Is(err, wsaEHOSTUNREACH):
		return Unreachable
	default:
		return Error
	}
}
