// Package targets проверяет и нормализует цели без сети
package targets

import (
	"fmt"
	"net/netip"
	"strings"
)

// разделяет исходное значение для результата и хост для подключения.
type Target struct {
	Host    string // исходная строка
	Address string // нормализованный IP или DNS
}

// Normalize проверяет весь список и удаляет дубликаты по Address
// При любой ошибке возвращает nil, без части списка
func Normalize(hosts []string) ([]Target, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("targets: host list is empty")
	}
	result := make([]Target, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for i, host := range hosts {
		address, err := normalize(host)
		if err != nil {
			return nil, fmt.Errorf("targets: host[%d] %q: %w", i, host, err)
		}
		if !seen[address] {
			seen[address] = true
			result = append(result, Target{Host: host, Address: address})
		}
	}
	return result, nil
}

func normalize(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("host is empty after trimming whitespace")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", fmt.Errorf("IPv6 zones are not supported")
		}
		return ip.Unmap().String(), nil
	}
	if strings.Trim(host, "0123456789.") == "" {
		return "", fmt.Errorf("invalid IPv4 address")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) == 0 || len(host) > 253 {
		return "", fmt.Errorf("DNS name must contain 1 to 253 bytes without the final dot")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("DNS labels must contain 1 to 63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("DNS label must not start or end with a hyphen")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return "", fmt.Errorf("expected an IP without brackets/zone or an ASCII DNS name (letters, digits, hyphens and dots)")
			}
		}
	}
	return host, nil
}
