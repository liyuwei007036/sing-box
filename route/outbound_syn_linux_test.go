//go:build linux

package route

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

func extractOptionKinds(opts []byte) ([]byte, uint8) {
	var kinds []byte
	var wscale uint8
	for i := 0; i < len(opts); {
		k := opts[i]
		kinds = append(kinds, k)
		if k == 0 {
			break
		}
		if k == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		if k == 3 && l == 3 {
			wscale = opts[i+2]
		}
		i += l
	}
	return kinds, wscale
}

func TestOutboundSYNRewriterWindowsFingerprint(t *testing.T) {
	obs, err := newInboundTTLObserver(log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatalf("newInboundTTLObserver: %v", err)
	}
	defer func() {
		if err := obs.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	if obs.synRW == nil {
		t.Fatalf("expected outboundSYNRewriter to be active on Linux kernel")
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	rawFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("raw socket: %v", err)
	}
	defer unix.Close(rawFD)

	type capturedSYN struct {
		ttl    uint8
		doff   int
		win    uint16
		kinds  []byte
		wscale uint8
	}
	capturedCh := make(chan capturedSYN, 8)
	stopCap := make(chan struct{})
	defer close(stopCap)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := unix.Recvfrom(rawFD, buf, 0)
			if err != nil {
				select {
				case <-stopCap:
					return
				default:
					continue
				}
			}
			if n < 40 {
				continue
			}
			ihl := int(buf[0]&0x0f) * 4
			if ihl < 20 || n < ihl+20 {
				continue
			}
			dp := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
			flags := buf[ihl+13]
			if dp == port && (flags&0x17) == 0x02 {
				doff := int(buf[ihl+12]>>4) * 4
				if n < ihl+doff {
					continue
				}
				kinds, ws := extractOptionKinds(buf[ihl+20 : ihl+doff])
				capturedCh <- capturedSYN{
					ttl:    buf[8],
					doff:   doff,
					win:    binary.BigEndian.Uint16(buf[ihl+14 : ihl+16]),
					kinds:  kinds,
					wscale: ws,
				}
			}
		}
	}()

	d, err := dialer.NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatalf("NewDefault: %v", err)
	}
	dst := M.ParseSocksaddr(ln.Addr().String())

	// 1. Windows flow (TTL=128): must rewrite TCP SYN options to native Windows 10/11
	//    layout [2, 1, 3, 1, 1, 4] (MSS, NOP, WS=8, NOP, NOP, SACK_PERM) with NO TS,
	//    and full bidirectional TCP echo must succeed.
	ctxWin := dialer.WithInitialTTL(context.Background(), dialer.WindowsInitialTTL)
	cWin, err := d.DialContext(ctxWin, "tcp", dst)
	if err != nil {
		t.Fatalf("win dial: %v", err)
	}
	msg := []byte("hello-windows-syn-fingerprint")
	if _, err := cWin.Write(msg); err != nil {
		t.Fatalf("win write: %v", err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(cWin, echo); err != nil {
		t.Fatalf("win read echo: %v", err)
	}
	_ = cWin.Close()
	if !bytes.Equal(echo, msg) {
		t.Fatalf("echo mismatch: got %q want %q", echo, msg)
	}

	var winSYN capturedSYN
	select {
	case winSYN = <-capturedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for captured Windows SYN")
	}
	wantWinKinds := []byte{2, 1, 3, 1, 1, 4}
	if winSYN.ttl != 128 || winSYN.doff != 32 || !bytes.Equal(winSYN.kinds, wantWinKinds) || winSYN.wscale != 8 {
		t.Fatalf("Windows SYN mismatch: ttl=%d doff=%d win=%d kinds=%v ws=%d (want ttl=128 doff=32 kinds=%v ws=8)",
			winSYN.ttl, winSYN.doff, winSYN.win, winSYN.kinds, winSYN.wscale, wantWinKinds)
	}
	t.Logf("VERIFIED Windows SYN: TTL=%d DOFF=%d WIN=%d KINDS=%v WSCALE=%d",
		winSYN.ttl, winSYN.doff, winSYN.win, winSYN.kinds, winSYN.wscale)

	// 2. Linux flow (TTL=64): must remain completely untouched (keeps Linux TS option 8).
	cLin, err := d.DialContext(context.Background(), "tcp", dst)
	if err != nil {
		t.Fatalf("linux dial: %v", err)
	}
	_ = cLin.Close()

	var linSYN capturedSYN
	select {
	case linSYN = <-capturedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for captured Linux SYN")
	}
	if linSYN.ttl != 64 || !bytes.Contains(linSYN.kinds, []byte{8}) {
		t.Fatalf("Linux SYN unexpectedly modified: ttl=%d doff=%d kinds=%v ws=%d",
			linSYN.ttl, linSYN.doff, linSYN.kinds, linSYN.wscale)
	}
	t.Logf("VERIFIED Linux SYN untouched: TTL=%d DOFF=%d WIN=%d KINDS=%v WSCALE=%d",
		linSYN.ttl, linSYN.doff, linSYN.win, linSYN.kinds, linSYN.wscale)
}
