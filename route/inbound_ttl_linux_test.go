//go:build linux

package route

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/sagernet/nftables"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

func TestInboundTTLObserverThreeOS(t *testing.T) {
	obs, err := newInboundTTLObserver(log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatalf("newInboundTTLObserver: %v", err)
	}
	defer func() {
		if err := obs.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	d, err := dialer.NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatalf("NewDefault: %v", err)
	}

	// 1. IPv4 TCP: Windows(128), Apple relay(255), Linux relay(192), Linux direct(64), Apple direct(64 + XNU SYN opts)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer ln.Close()
	dst4 := M.ParseSocksaddr(ln.Addr().String())

	dialTCP4 := func(ctx context.Context) netip.AddrPort {
		done := make(chan netip.AddrPort, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			done <- c.RemoteAddr().(*net.TCPAddr).AddrPort()
		}()
		c, err := d.DialContext(ctx, "tcp4", dst4)
		if err != nil {
			t.Fatalf("dial tcp4: %v", err)
		}
		defer c.Close()
		return <-done
	}

	checkProfile := func(name, inboundType string, ap netip.AddrPort, want inboundOSProfile) {
		t.Helper()
		got := obs.LookupOSProfile(inboundType, ap.Addr(), ap.Port())
		if got != want {
			t.Fatalf("%s (%v): got profile=%d, want %d", name, ap, got, want)
		}
	}

	checkProfile("IPv4 TCP Windows(128)", C.TypeVLESS, dialTCP4(dialer.WithInitialTTL(context.Background(), dialer.WindowsInitialTTL)), inboundOSWindows)
	checkProfile("IPv4 TCP Apple relay(255)", C.TypeVLESS, dialTCP4(dialer.WithInitialTTL(context.Background(), dialer.AppleRelayTTL)), inboundOSApple)
	checkProfile("IPv4 TCP Linux relay(192)", C.TypeVLESS, dialTCP4(dialer.WithInitialTTL(context.Background(), dialer.LinuxRelayTTL)), inboundOSLinux)
	checkProfile("IPv4 TCP Linux direct(64)", C.TypeVLESS, dialTCP4(context.Background()), inboundOSLinux)
	if obs.synRW != nil {
		// Dialing with WithAppleEgress produces a real kernel Apple XNU TCP SYN
		// (TTL=64, options [2,1,3,1,1,8,4,0,0]) which NFLOG must classify as Apple.
		checkProfile("IPv4 TCP Apple direct(64+XNU opts)", C.TypeVLESS, dialTCP4(dialer.WithAppleEgress(context.Background())), inboundOSApple)
	}

	// 2. IPv4 UDP (Hysteria2/TUIC): Windows(128), Apple relay(255), Linux relay(192), Direct UDP(64 -> Apple fallback)
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

	checkProfile("IPv4 UDP Windows(128)", C.TypeHysteria2, sendUDPWithTTL(128), inboundOSWindows)
	checkProfile("IPv4 UDP Apple relay(255)", C.TypeHysteria2, sendUDPWithTTL(255), inboundOSApple)
	checkProfile("IPv4 UDP Linux relay(192)", C.TypeHysteria2, sendUDPWithTTL(192), inboundOSLinux)
	checkProfile("IPv4 UDP direct(64 -> Apple fallback)", C.TypeHysteria2, sendUDPWithTTL(64), inboundOSApple)

	// 3. IPv6 TCP HopLimit & direct Apple SYN (84B = 40B IPv6 + 44B Apple TCP SYN within snaplen=128)
	if ln6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer ln6.Close()
		dst6 := M.ParseSocksaddr(ln6.Addr().String())
		dialTCP6 := func(ctx context.Context) netip.AddrPort {
			done := make(chan netip.AddrPort, 1)
			go func() {
				c, err := ln6.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				done <- c.RemoteAddr().(*net.TCPAddr).AddrPort()
			}()
			c, err := d.DialContext(ctx, "tcp6", dst6)
			if err != nil {
				t.Fatalf("dial tcp6: %v", err)
			}
			defer c.Close()
			return <-done
		}
		checkProfile("IPv6 TCP Windows(128)", C.TypeVLESS, dialTCP6(dialer.WithInitialTTL(context.Background(), dialer.WindowsInitialTTL)), inboundOSWindows)
		checkProfile("IPv6 TCP Apple relay(255)", C.TypeVLESS, dialTCP6(dialer.WithInitialTTL(context.Background(), dialer.AppleRelayTTL)), inboundOSApple)
		checkProfile("IPv6 TCP Linux relay(192)", C.TypeVLESS, dialTCP6(dialer.WithInitialTTL(context.Background(), dialer.LinuxRelayTTL)), inboundOSLinux)
		checkProfile("IPv6 TCP Linux direct(64)", C.TypeVLESS, dialTCP6(context.Background()), inboundOSLinux)
		if obs.synRW != nil {
			checkProfile("IPv6 TCP Apple direct(64+XNU opts)", C.TypeVLESS, dialTCP6(dialer.WithAppleEgress(context.Background())), inboundOSApple)
		}
	}

	// 4. Test self-healing after external nftables table deletion.
	obs.nftConn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: obs.tableName})
	if err := obs.nftConn.Flush(); err != nil {
		t.Fatalf("simulate external nft table deletion: %v", err)
	}
	obs.ensureNftTable()
	checkProfile("IPv4 TCP Windows after nft self-heal", C.TypeVLESS, dialTCP4(dialer.WithInitialTTL(context.Background(), dialer.WindowsInitialTTL)), inboundOSWindows)
}
