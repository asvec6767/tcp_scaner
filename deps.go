package portscan

import (
	"context"
	"time"
)

type targetNormalizer interface {
	Normalize([]string) ([]target, error)
}

type connectionChecker interface {
	Check(context.Context, string, uint16, time.Duration) Result
}
