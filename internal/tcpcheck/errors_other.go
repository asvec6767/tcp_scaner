//go:build !windows

package tcpcheck

func platformState(error) State { return Error }
