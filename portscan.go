// пакет portscan обеспечивает ограниченное потоковое сканирование TCP портов
package portscan

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/asvec6767/tcp_scaner/internal/tcpcheck"
)

// устанавливает строго положительные ограничения без значений по умолчанию
type Config struct {
	Concurrency    int
	ConnectTimeout time.Duration
}

// результат разовой проверки TCP-соединения
type State string

const (
	Open        State = State(tcpcheck.Open)
	Closed      State = State(tcpcheck.Closed)
	Timeout     State = State(tcpcheck.Timeout)
	Unreachable State = State(tcpcheck.Unreachable)
	Canceled    State = State(tcpcheck.Canceled)
	Error       State = State(tcpcheck.Error)
)

// фактический IP адрес или ошибка TCP-соединения
type Result struct {
	Host     string
	IP       net.IP // заполняется только при успешном подключении
	Port     uint16
	State    State
	Duration time.Duration // включает в себя разрешение DNS и настройку подключения
	Err      error
}

// неизменяем и безопасен для параллельных нескольких пулов
type Scanner struct {
	config  Config
	targets targetNormalizer
	checker connectionChecker
}

// проверяет конфигурацию и создает сканер
func New(config Config) (*Scanner, error) {
	if config.Concurrency <= 0 || config.ConnectTimeout <= 0 {
		return nil, fmt.Errorf("portscan: concurrency and connect timeout must be positive")
	}
	return &Scanner{
		config:  config,
		targets: targetsAdapter{},
		checker: tcpcheckAdapter{},
	}, nil
}

// Scan синхронно проверяет все входные данные
func (s *Scanner) Scan(ctx context.Context, hosts []string, set PortSet) (<-chan Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("portscan: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.targets == nil || s.checker == nil || s.config.Concurrency <= 0 || s.config.ConnectTimeout <= 0 {
		return nil, fmt.Errorf("portscan: scanner must be constructed with New")
	}
	values := set.Values()
	if len(values) == 0 {
		return nil, fmt.Errorf("portscan: port set is empty")
	}
	normalized, err := s.targets.Normalize(append([]string(nil), hosts...))
	if err != nil {
		return nil, err
	}
	// собственные снапшоты перед return'ом
	normalized = append([]target(nil), normalized...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.scan(ctx, normalized, values), nil
}

// пустой по умолчанию изменяемыц сет портов
type PortSet struct{ values []uint16 }

// проверяет и удаляет дубликаты номеров сохраняя порядок
func Ports(numbers ...int) (PortSet, error) {
	values := make([]uint16, 0, len(numbers))
	seen := make(map[uint16]bool, len(numbers))
	for _, n := range numbers {
		if n < 1 || n > 65535 {
			return PortSet{}, fmt.Errorf("ports: port %d outside 1–65535", n)
		}
		p := uint16(n)
		if !seen[p] {
			seen[p] = true
			values = append(values, p)
		}
	}
	return PortSet{values}, nil
}

// создает включающий с обеих сторон возрастающий диапазон
func Range(from, to int) (PortSet, error) {
	if from < 1 || to > 65535 || from > to {
		return PortSet{}, fmt.Errorf("ports: invalid range %d–%d", from, to)
	}
	values := make([]uint16, to-from+1)
	for i := range values {
		values[i] = uint16(from + i)
	}
	return PortSet{values}, nil
}

// объединяет сеты сохраняя порядок
func Merge(sets ...PortSet) PortSet {
	var values []uint16
	seen := make(map[uint16]bool)
	for _, set := range sets {
		for _, p := range set.values {
			if !seen[p] {
				seen[p] = true
				values = append(values, p)
			}
		}
	}
	return PortSet{values}
}

// возвращает снапшот значений для параллельного чтения и изменения
func (s PortSet) Values() []uint16 { return append([]uint16(nil), s.values...) }
