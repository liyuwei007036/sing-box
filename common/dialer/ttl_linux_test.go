//go:build linux

package dialer

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

func getSocketIPv4TTL(t *testing.T, sc syscall.Conn) int {
	t.Helper()
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var ttl int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ttl, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("GetsockoptInt(IP_TTL): %v", sockErr)
	}
	return ttl
}

func TestDefaultDialerContextInitialTTL(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	d, err := NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatalf("NewDefault: %v", err)
	}
	dst := M.ParseSocksaddr(ln.Addr().String())

	// Default context uses Linux default TTL (64).
	cDefault, err := d.DialContext(context.Background(), "tcp", dst)
	if err != nil {
		t.Fatalf("default DialContext: %v", err)
	}
	defer cDefault.Close()
	if got := getSocketIPv4TTL(t, cDefault.(syscall.Conn)); got != 64 {
		t.Fatalf("default TCP TTL = %d, want 64", got)
	}

	// Windows context uses initial TTL 128 on TCP and UDP sockets.
	ctxWin := WithInitialTTL(context.Background(), WindowsInitialTTL)
	cWin, err := d.DialContext(ctxWin, "tcp", dst)
	if err != nil {
		t.Fatalf("win DialContext: %v", err)
	}
	defer cWin.Close()
	if got := getSocketIPv4TTL(t, cWin.(syscall.Conn)); got != 128 {
		t.Fatalf("win TCP TTL = %d, want 128", got)
	}

	pcWin, err := d.ListenPacket(ctxWin, dst)
	if err != nil {
		t.Fatalf("win ListenPacket: %v", err)
	}
	defer pcWin.Close()
	if got := getSocketIPv4TTL(t, pcWin.(syscall.Conn)); got != 128 {
		t.Fatalf("win UDP TTL = %d, want 128", got)
	}
}
