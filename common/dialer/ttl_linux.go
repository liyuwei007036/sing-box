//go:build linux

package dialer

import (
	"syscall"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

// windowsTCPReceiveBuffer sets a 10 MiB socket receive buffer ceiling (~20 MiB
// after kernel doubling; with Linux's default tcp_adv_win_scale=1, tcp_space is
// ~10 MiB, strictly within (8 MiB, 16 MiB]) so tcp_select_initial_window natively
// chooses Window Scale = 8 (matching Windows 10/11) without desyncing kernel state.
const windowsTCPReceiveBuffer = 10 * 1024 * 1024

func setInitialTTL(ttl int) control.Func {
	if ttl <= 0 || ttl > 255 {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		var sockErr error
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
			if ttl == WindowsInitialTTL && (network == "tcp" || network == "tcp4" || network == "tcp6") {
				// Best-effort: let Linux natively negotiate WSCALE=8 on Windows-emulated TCP SYNs.
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, windowsTCPReceiveBuffer); err != nil {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, windowsTCPReceiveBuffer)
				}
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
