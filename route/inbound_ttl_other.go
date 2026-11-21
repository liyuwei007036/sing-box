//go:build !linux

package route

import (
	"net/netip"

	"github.com/sagernet/sing-box/log"
)

type inboundTTLObserver struct{}

func newInboundTTLObserver(log.ContextLogger) (*inboundTTLObserver, error) {
	return nil, nil
}

func (*inboundTTLObserver) IsWindowsSource(string, netip.Addr, uint16) bool {
	return false
}

func (*inboundTTLObserver) Group() uint16 {
	return 0
}

func (*inboundTTLObserver) Close() error {
	return nil
}
