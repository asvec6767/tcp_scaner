package portscan

import (
	"context"
	"net"
	"time"

	"github.com/asvec6767/tcp_scaner/internal/targets"
	"github.com/asvec6767/tcp_scaner/internal/tcpcheck"
)

type targetsAdapter struct{}

func (targetsAdapter) Normalize(hosts []string) ([]target, error) {
	normalized, err := targets.Normalize(hosts)
	if err != nil {
		return nil, err
	}
	result := make([]target, len(normalized))
	for i, t := range normalized {
		result[i] = target{host: t.Host, address: t.Address}
	}
	return result, nil
}

type tcpcheckAdapter struct{}

func (tcpcheckAdapter) Check(ctx context.Context, address string, port uint16, timeout time.Duration) Result {
	return resultFromCheck(tcpcheck.Check(ctx, address, port, timeout))
}

func resultFromCheck(r tcpcheck.Result) Result {
	return Result{
		Host:     r.Host,
		IP:       append(net.IP(nil), r.IP...),
		Port:     r.Port,
		State:    State(r.State),
		Duration: r.Duration,
		Err:      r.Err,
	}
}
