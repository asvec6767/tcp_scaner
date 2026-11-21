package targets_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/asvec6767/tcp_scaner/internal/targets"
)

func TestNormalizeValid(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, tt := range []struct{ host, address string }{
		{"127.0.0.1", "127.0.0.1"},
		{"0.0.0.0", "0.0.0.0"},
		{"255.255.255.255", "255.255.255.255"},
		{"2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"::", "::"},
		{"::1", "::1"},
		{"::FFFF:192.0.2.1", "192.0.2.1"},
		{"\t EXAMPLE.Com. \n", "example.com"},
		{"\u2003 192.0.2.1 \u2003", "192.0.2.1"},
		{"LOCALHOST", "localhost"},
		{"a", "a"},
		{"3com.123", "3com.123"},
		{"123.example", "123.example"},
		{"xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"},
		{"a-b.example", "a-b.example"},
		{strings.Repeat("a", 63), strings.Repeat("a", 63)},
		{maxName, maxName},
		{maxName + ".", maxName},
	} {
		t.Run(tt.host, func(t *testing.T) {
			got, err := targets.Normalize([]string{tt.host})
			want := []targets.Target{{Host: tt.host, Address: tt.address}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("Normalize() = %#v, %v; want %#v", got, err, want)
			}
		})
	}
}

func TestNormalizeInvalid(t *testing.T) {
	for _, host := range []string{
		"", " \t\n", "https://example.com", "example.com/path", "user@example.com",
		"example.com:80", "127.0.0.1:80", "[::1]", "[::1]:80",
		"2001:db8:::1", "fe80::1%eth0", "fe80::1%1", "192.0.2.1%zone",
		"256.1.2.3", "01.2.3.4", "1.2.3", "1.2.3.4.5", "123", "1.2.3.4.",
		".", "..", "example..com", ".example", "example.com..",
		"-example.com", "example-.com", "a_b.example", "a b.example", "a\tb.example",
		"пример.рф", "192.0.2.0/24", "::/0",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "a",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	} {
		t.Run(host, func(t *testing.T) {
			// Ошибка после корректной цели не должна возвращать частичный успех.
			got, err := targets.Normalize([]string{"valid.example", host})
			if err == nil || got != nil {
				t.Fatalf("Normalize() = %#v, %v; want nil and error", got, err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%q", host)) || !strings.Contains(err.Error(), "host[1]") {
				t.Fatalf("error does not identify original target: %v", err)
			}
		})
	}
}

func TestNormalizeEmpty(t *testing.T) {
	for _, hosts := range [][]string{nil, {}} {
		if got, err := targets.Normalize(hosts); got != nil || err == nil {
			t.Fatalf("Normalize(%v) = %#v, %v; want nil and error", hosts, got, err)
		}
	}
}

func TestNormalizeDuplicatesAndOrder(t *testing.T) {
	hosts := []string{" EXAMPLE.com. ", "2001:0DB8::1", "example.COM", "192.0.2.1", "2001:db8:0:0::1", "::ffff:c000:201", "other.example", "192.0.2.1"}
	original := append([]string(nil), hosts...)
	want := []targets.Target{
		{Host: hosts[0], Address: "example.com"},
		{Host: hosts[1], Address: "2001:db8::1"},
		{Host: hosts[3], Address: "192.0.2.1"},
		{Host: hosts[6], Address: "other.example"},
	}
	got, err := targets.Normalize(hosts)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize() = %#v, %v; want %#v", got, err, want)
	}
	if !reflect.DeepEqual(hosts, original) {
		t.Fatalf("input changed: %#v", hosts)
	}
	// Повторный вызов не разделяет изменяемый результат с предыдущим.
	got[0].Host = "changed"
	again, err := targets.Normalize(hosts)
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatalf("second Normalize() = %#v, %v; want %#v", again, err, want)
	}
}
