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

func TestOutboundSYNRewriterThreeOSFingerprints(t *testing.T) {
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

	dialAndEcho := func(ctx context.Context, payload string) capturedSYN {
		t.Helper()
		c, err := d.DialContext(ctx, "tcp", dst)
		if err != nil {
			t.Fatalf("dial (%s): %v", payload, err)
		}
		msg := []byte(payload)
		if _, err := c.Write(msg); err != nil {
			_ = c.Close()
			t.Fatalf("write (%s): %v", payload, err)
		}
		echo := make([]byte, len(msg))
		if _, err := io.ReadFull(c, echo); err != nil {
			_ = c.Close()
			t.Fatalf("read echo (%s): %v", payload, err)
		}
		_ = c.Close()
		if !bytes.Equal(echo, msg) {
			t.Fatalf("echo mismatch: got %q want %q", echo, msg)
		}
		select {
		case syn := <-capturedCh:
			return syn
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for captured SYN (%s)", payload)
			return capturedSYN{}
		}
	}

	// 1. Windows flow: TTL=128, DOFF=32, KINDS=[2,1,3,1,1,4] (no TS), WSCALE=8
	winSYN := dialAndEcho(dialer.WithInitialTTL(context.Background(), dialer.WindowsInitialTTL), "hello-windows-syn")
	wantWinKinds := []byte{2, 1, 3, 1, 1, 4}
	if winSYN.ttl != 128 || winSYN.doff != 32 || !bytes.Equal(winSYN.kinds, wantWinKinds) || winSYN.wscale != 8 {
		t.Fatalf("Windows SYN mismatch: ttl=%d doff=%d win=%d kinds=%v ws=%d (want ttl=128 doff=32 kinds=%v ws=8)",
			winSYN.ttl, winSYN.doff, winSYN.win, winSYN.kinds, winSYN.wscale, wantWinKinds)
	}
	t.Logf("VERIFIED Windows SYN: TTL=%d DOFF=%d WIN=%d KINDS=%v WSCALE=%d",
		winSYN.ttl, winSYN.doff, winSYN.win, winSYN.kinds, winSYN.wscale)

	// 2. Apple macOS/iOS flow: TTL=64, DOFF=44, WIN=65535, KINDS=[2,1,3,1,1,8,4,0], WSCALE=6
	appleSYN := dialAndEcho(dialer.WithAppleEgress(context.Background()), "hello-apple-xnu-syn")
	wantAppleKinds := []byte{2, 1, 3, 1, 1, 8, 4, 0}
	if appleSYN.ttl != 64 || appleSYN.doff != 44 || appleSYN.win != 65535 || !bytes.Equal(appleSYN.kinds, wantAppleKinds) || appleSYN.wscale != 6 {
		t.Fatalf("Apple SYN mismatch: ttl=%d doff=%d win=%d kinds=%v ws=%d (want ttl=64 doff=44 win=65535 kinds=%v ws=6)",
			appleSYN.ttl, appleSYN.doff, appleSYN.win, appleSYN.kinds, appleSYN.wscale, wantAppleKinds)
	}
	t.Logf("VERIFIED Apple XNU SYN: TTL=%d DOFF=%d WIN=%d KINDS=%v WSCALE=%d",
		appleSYN.ttl, appleSYN.doff, appleSYN.win, appleSYN.kinds, appleSYN.wscale)

	// 3. Linux/Android flow: TTL=64, DOFF=40, untouched Linux options [2,4,8,1,3]
	linSYN := dialAndEcho(context.Background(), "hello-linux-syn")
	wantLinuxKinds := []byte{2, 4, 8, 1, 3}
	if linSYN.ttl != 64 || linSYN.doff != 40 || !bytes.Equal(linSYN.kinds, wantLinuxKinds) {
		t.Fatalf("Linux SYN unexpectedly modified: ttl=%d doff=%d win=%d kinds=%v ws=%d",
			linSYN.ttl, linSYN.doff, linSYN.win, linSYN.kinds, linSYN.wscale)
	}
	t.Logf("VERIFIED Linux SYN untouched: TTL=%d DOFF=%d WIN=%d KINDS=%v WSCALE=%d",
		linSYN.ttl, linSYN.doff, linSYN.win, linSYN.kinds, linSYN.wscale)
}
