package dialer

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// WindowsInitialTTL is the default IPv4 TTL / IPv6 Hop Limit of Windows TCP/IP
// stacks, preserved end-to-end across sing-box egress and chained proxy hops.
const WindowsInitialTTL = 128

type initialTTLKey struct{}

// WithInitialTTL returns a context instructing DefaultDialer to set the initial
// IPv4 IP_TTL / IPv6 IPV6_UNICAST_HOPS on newly dialed sockets.
func WithInitialTTL(ctx context.Context, ttl int) context.Context {
	if ttl <= 0 || ttl > 255 {
		return ctx
	}
	return context.WithValue(ctx, initialTTLKey{}, ttl)
}

// InitialTTLFromContext extracts the requested initial IP TTL / Hop Limit from ctx.
func InitialTTLFromContext(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	ttl, _ := ctx.Value(initialTTLKey{}).(int)
	if ttl <= 0 || ttl > 255 {
		return 0
	}
	return ttl
}

// IsWindowsTTLContext reports whether ctx requests Windows initial TTL (128).
func IsWindowsTTLContext(ctx context.Context) bool {
	return InitialTTLFromContext(ctx) == WindowsInitialTTL
}

type ttlDialer struct {
	inner N.Dialer
	ttl   int
}

// WrapWithInitialTTL wraps d so every outbound dial/listen carries ttl in ctx.
func WrapWithInitialTTL(d N.Dialer, ttl int) N.Dialer {
	if d == nil || ttl <= 0 || ttl > 255 {
		return d
	}
	return ttlDialer{inner: d, ttl: ttl}
}

func (d ttlDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.inner.DialContext(WithInitialTTL(ctx, d.ttl), network, destination)
}

func (d ttlDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.inner.ListenPacket(WithInitialTTL(ctx, d.ttl), destination)
}
