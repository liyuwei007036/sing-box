package dialer

import (
	"context"
	"net"
	"sync"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// WindowsInitialTTL is the default IPv4 TTL / IPv6 Hop Limit of Windows TCP/IP
// stacks, preserved end-to-end across sing-box egress and chained proxy hops.
const WindowsInitialTTL = 128

// LinuxRelayTTL is the distinct IPv4 TTL / IPv6 Hop Limit used on proxy relay
// hops to signal an explicitly classified Linux / Android client downstream.
const LinuxRelayTTL = 192

// AppleRelayTTL is the distinct IPv4 TTL / IPv6 Hop Limit used on proxy relay
// hops to signal an originating Apple (macOS / iOS / iPadOS) client downstream.
const AppleRelayTTL = 255

// AppleEgressMark is the internal Linux SO_MARK applied to direct outbound TCP
// sockets carrying Apple client traffic (only when no user routing_mark or
// auto_redirect mark is configured) so the output NFQUEUE rewriter rewrites
// ONLY those SYNs to native Apple XNU TCP options while keeping TTL=64.
const AppleEgressMark uint32 = 0x51a9

type initialTTLKey struct{}
type appleEgressKey struct{}

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

// WithAppleEgress returns a context instructing DefaultDialer to emulate native
// Apple XNU (macOS / iOS) TCP SYN parameters on direct outbound sockets.
func WithAppleEgress(ctx context.Context) context.Context {
	return context.WithValue(ctx, appleEgressKey{}, true)
}

// IsAppleEgressContext reports whether ctx requests native Apple egress emulation.
func IsAppleEgressContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(appleEgressKey{}).(bool)
	return v
}

// TTLClientPool lazily caches companion multiplexed outbound clients keyed by
// non-zero initial TTL (e.g., 128 for Windows, 255 for Apple relay hops) so
// multiplexed transports never mix OS fingerprints on the same outer socket.
type TTLClientPool[T any] struct {
	mu      sync.Mutex
	clients map[int]T
	factory func(ttl int) (T, error)
}

func (p *TTLClientPool[T]) Init(factory func(ttl int) (T, error)) {
	p.factory = factory
}

func (p *TTLClientPool[T]) Get(ctx context.Context, fallback T) (T, error) {
	ttl := InitialTTLFromContext(ctx)
	if ttl <= 0 || p.factory == nil {
		return fallback, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clients == nil {
		p.clients = make(map[int]T, 2)
	}
	if c, ok := p.clients[ttl]; ok {
		return c, nil
	}
	c, err := p.factory(ttl)
	if err != nil {
		var zero T
		return zero, err
	}
	p.clients[ttl] = c
	return c, nil
}

func (p *TTLClientPool[T]) ForEach(fn func(T)) {
	p.mu.Lock()
	snapshot := make([]T, 0, len(p.clients))
	for _, c := range p.clients {
		snapshot = append(snapshot, c)
	}
	p.mu.Unlock()
	for _, c := range snapshot {
		fn(c)
	}
}

func (p *TTLClientPool[T]) TakeAll() []T {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.clients) == 0 {
		return nil
	}
	out := make([]T, 0, len(p.clients))
	for _, c := range p.clients {
		out = append(out, c)
	}
	p.clients = nil
	return out
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
