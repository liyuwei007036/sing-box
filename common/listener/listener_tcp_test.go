package listener

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type testConnHandler struct {
	accepted chan struct {
		remoteAddr string
		data       string
	}
}

func (h *testConnHandler) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	h.accepted <- struct {
		remoteAddr string
		data       string
	}{
		remoteAddr: metadata.Source.String(),
		data:       string(buf[:n]),
	}
}

func TestProxyProtocolListener(t *testing.T) {
	handler := &testConnHandler{
		accepted: make(chan struct {
			remoteAddr string
			data       string
		}, 1),
	}

	options := option.ListenOptions{
		ListenPort:    0,
		ProxyProtocol: true,
	}

	l := &Listener{
		ctx:           context.Background(),
		logger:        log.NewNOPFactory().NewLogger(""),
		listenOptions: options,
		connHandler:   handler,
	}

	tcpListener, err := l.ListenTCP()
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer tcpListener.Close()

	go l.loopTCPIn()

	// Dial to listener
	client, err := net.Dial("tcp", tcpListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// Send PROXY v1 header followed by application data
	fmt.Fprintf(client, "PROXY TCP4 203.0.113.195 127.0.0.1 54321 443\r\nTLS_CLIENT_HELLO_DATA")

	select {
	case res := <-handler.accepted:
		if res.remoteAddr != "203.0.113.195:54321" {
			t.Errorf("expected remote addr 203.0.113.195:54321, got %s", res.remoteAddr)
		}
		if res.data != "TLS_CLIENT_HELLO_DATA" {
			t.Errorf("expected data TLS_CLIENT_HELLO_DATA, got %s", res.data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}
}

func TestProxyProtocolAcceptNoHeader(t *testing.T) {
	handler := &testConnHandler{
		accepted: make(chan struct {
			remoteAddr string
			data       string
		}, 1),
	}

	options := option.ListenOptions{
		ListenPort:                  0,
		ProxyProtocol:               true,
		ProxyProtocolAcceptNoHeader: true,
	}

	l := &Listener{
		ctx:           context.Background(),
		logger:        log.NewNOPFactory().NewLogger(""),
		listenOptions: options,
		connHandler:   handler,
	}

	tcpListener, err := l.ListenTCP()
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer tcpListener.Close()

	go l.loopTCPIn()

	client, err := net.Dial("tcp", tcpListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// Send raw data without PROXY header
	fmt.Fprintf(client, "PLAIN_RAW_DATA")

	select {
	case res := <-handler.accepted:
		if res.data != "PLAIN_RAW_DATA" {
			t.Errorf("expected data PLAIN_RAW_DATA, got %s", res.data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}
}
