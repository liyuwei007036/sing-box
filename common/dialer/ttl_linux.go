//go:build linux

package dialer

import (
	"syscall"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

const (
	// windowsTCPReceiveBuffer sets a 10 MiB socket receive buffer ceiling (~20 MiB
	// after kernel doubling; with Linux's default tcp_adv_win_scale=1, tcp_space is
	// ~10 MiB, strictly within (8 MiB, 16 MiB]) so tcp_select_initial_window natively
	// chooses Window Scale = 8 (matching Windows 10/11) without desyncing kernel state.
	windowsTCPReceiveBuffer = 10 * 1024 * 1024

	// appleTCPReceiveBuffer sets a 3 MiB socket receive buffer ceiling (~6 MiB
	// after kernel doubling; tcp_space ~3 MiB, strictly within (2 MiB, 4 MiB]) so
	// tcp_select_initial_window natively chooses Window Scale = 6 (matching Apple XNU
	// macOS / iOS) without desyncing kernel state.
	appleTCPReceiveBuffer = 3 * 1024 * 1024
)

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

func setAppleEgress(canMark bool) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil
		}
		return conn.Control(func(fd uintptr) {
			// Best-effort: let Linux natively negotiate WSCALE=6 for Apple XNU TCP SYNs.
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, appleTCPReceiveBuffer); err != nil {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, appleTCPReceiveBuffer)
			}
			if canMark {
				// Best-effort: tag this direct TCP socket so the output NFQUEUE rule
				// rewrites ONLY its initial SYN to native Apple XNU options.
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(AppleEgressMark))
			}
		})
	}
}
