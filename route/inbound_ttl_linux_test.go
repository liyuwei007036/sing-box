//go:build linux

package route

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/sagernet/nftables"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"golang.org/x/sys/unix"
)

func TestInboundTTLObserverTCPAndUDP(t *testing.T) {
	obs, err := newInboundTTLObserver(log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatalf("newInboundTTLObserver: %v", err)
	}
	defer func() {
		if err := obs.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	// 1. Test TCP with TTL=128 (Windows) and TTL=64 (Linux).
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer ln.Close()

	dialWithTTL := func(ttl int) netip.AddrPort {
		d := net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				var sockErr error
				if err := c.Control(func(fd uintptr) {
					sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
				}); err != nil {
					return err
				}
				return sockErr
			},
		}
		done := make(chan netip.AddrPort, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			done <- c.RemoteAddr().(*net.TCPAddr).AddrPort()
		}()
		c, err := d.DialContext(context.Background(), "tcp4", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial tcp ttl=%d: %v", ttl, err)
		}
		defer c.Close()
		return <-done
	}

	winTCP := dialWithTTL(128)
	if !obs.IsWindowsSource(C.TypeVLESS, winTCP.Addr(), winTCP.Port()) {
		t.Fatalf("expected TCP src %v (TTL 128) to be detected as Windows", winTCP)
	}

	linuxTCP := dialWithTTL(64)
	if obs.IsWindowsSource(C.TypeVLESS, linuxTCP.Addr(), linuxTCP.Port()) {
		t.Fatalf("expected TCP src %v (TTL 64) to be detected as non-Windows", linuxTCP)
	}

	// 2. Test UDP (e.g. Hysteria2) with TTL=128 and TTL=64.
	srvPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer srvPC.Close()

	sendUDPWithTTL := func(ttl int) netip.AddrPort {
		lc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				var sockErr error
				if err := c.Control(func(fd uintptr) {
					sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
				}); err != nil {
					return err
				}
				return sockErr
			},
		}
		cliPC, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("udp client ttl=%d: %v", ttl, err)
		}
		defer cliPC.Close()
		if _, err := cliPC.WriteTo([]byte("hello"), srvPC.LocalAddr()); err != nil {
			t.Fatalf("udp write ttl=%d: %v", ttl, err)
		}
		buf := make([]byte, 64)
		_, addr, err := srvPC.ReadFrom(buf)
		if err != nil {
			t.Fatalf("udp read ttl=%d: %v", ttl, err)
		}
		return addr.(*net.UDPAddr).AddrPort()
	}

	winUDP := sendUDPWithTTL(128)
	if !obs.IsWindowsSource(C.TypeHysteria2, winUDP.Addr(), winUDP.Port()) {
		t.Fatalf("expected UDP src %v (TTL 128) to be detected as Windows", winUDP)
	}

	linuxUDP := sendUDPWithTTL(64)
	if obs.IsWindowsSource(C.TypeHysteria2, linuxUDP.Addr(), linuxUDP.Port()) {
		t.Fatalf("expected UDP src %v (TTL 64) to be detected as non-Windows", linuxUDP)
	}

	// 3. Test IPv6 TCP Hop Limit (128 vs 64).
	if ln6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer ln6.Close()
		dialV6 := func(hops int) netip.AddrPort {
			d := net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					var sockErr error
					if err := c.Control(func(fd uintptr) {
						sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, hops)
					}); err != nil {
						return err
					}
					return sockErr
				},
			}
			done := make(chan netip.AddrPort, 1)
			go func() {
				c, err := ln6.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				done <- c.RemoteAddr().(*net.TCPAddr).AddrPort()
			}()
			c, err := d.DialContext(context.Background(), "tcp6", ln6.Addr().String())
			if err != nil {
				t.Fatalf("dial tcp6 hops=%d: %v", hops, err)
			}
			defer c.Close()
			return <-done
		}
		winV6 := dialV6(128)
		if !obs.IsWindowsSource(C.TypeVLESS, winV6.Addr(), winV6.Port()) {
			t.Fatalf("expected IPv6 TCP src %v (HopLimit 128) to be detected as Windows", winV6)
		}
		linV6 := dialV6(64)
		if obs.IsWindowsSource(C.TypeVLESS, linV6.Addr(), linV6.Port()) {
			t.Fatalf("expected IPv6 TCP src %v (HopLimit 64) to be detected as non-Windows", linV6)
		}
	}

	// 4. Test self-healing after external nftables table deletion.
	obs.nftConn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: obs.tableName})
	if err := obs.nftConn.Flush(); err != nil {
		t.Fatalf("simulate external nft table deletion: %v", err)
	}
	obs.ensureNftTable()
	winAfterHeal := dialWithTTL(128)
	if !obs.IsWindowsSource(C.TypeVLESS, winAfterHeal.Addr(), winAfterHeal.Port()) {
		t.Fatalf("expected TCP src %v (TTL 128) to be detected after nft table self-heal", winAfterHeal)
	}
}
