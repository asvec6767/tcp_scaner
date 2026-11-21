package portscan_test

import (
	"reflect"
	"testing"

	portscan "github.com/asvec6767/tcp_scaner"
)

func TestPorts(t *testing.T) {
	input := []int{65535, 1, 80, 1}
	s, err := portscan.Ports(input...)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 2
	want := []uint16{65535, 1, 80}
	if !reflect.DeepEqual(s.Values(), want) {
		t.Fatal(s.Values())
	}
	copy := s.Values()
	copy[0] = 3
	if !reflect.DeepEqual(s.Values(), want) {
		t.Fatal("mutable storage exposed")
	}
	for _, n := range []int{-1, 0, 65536} {
		if s, err := portscan.Ports(80, n); err == nil || len(s.Values()) != 0 {
			t.Fatalf("Ports(%d): %v %v", n, s, err)
		}
	}
	if s, err := portscan.Ports(); err != nil || len(s.Values()) != 0 {
		t.Fatal(s, err)
	}
}

func TestRangeAndMerge(t *testing.T) {
	for _, bounds := range [][2]int{{0, 1}, {-1, 80}, {1, 65536}, {80, 1}, {65536, 65536}, {0, 0}} {
		if s, err := portscan.Range(bounds[0], bounds[1]); err == nil || len(s.Values()) != 0 {
			t.Fatal(bounds, s, err)
		}
	}
	all, err := portscan.Range(1, 65535)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range all.Values() {
		if int(p) != i+1 {
			t.Fatal(i, p)
		}
	}
	if len(all.Values()) != 65535 {
		t.Fatal("incomplete range")
	}
	a, _ := portscan.Range(1, 3)
	b, _ := portscan.Ports(3, 65535, 1)
	m := portscan.Merge(a, b, portscan.PortSet{})
	if !reflect.DeepEqual(m.Values(), []uint16{1, 2, 3, 65535}) {
		t.Fatal(m.Values())
	}
	m.Values()[0] = 9
	if a.Values()[0] != 1 || m.Values()[0] != 1 {
		t.Fatal("shared mutable data")
	}
	if len(portscan.Merge().Values()) != 0 {
		t.Fatal("nonempty union")
	}
	single, err := portscan.Range(65535, 65535)
	if err != nil || !reflect.DeepEqual(single.Values(), []uint16{65535}) {
		t.Fatal(single, err)
	}
}
