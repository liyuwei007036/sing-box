//go:build linux

package diale

import (
	"syscall"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func setInitialTTL(ttl int) control.Func {
	if ttl <= 0 || ttl > 255 {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		var sockErr erro
		err := conn.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
			case "tcp6", "udp6":
				err6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
				err4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
				if err6 != nil && err4 != nil {
					sockErr = err6
				}
			default:
				err4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
				err6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
				if err4 != nil && err6 != nil {
					sockErr = err4
				}
			}
		})
		if err != nil {
			return er
		}
		return sockEr
	}
}
