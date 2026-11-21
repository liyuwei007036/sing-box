package v2ray

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	N "github.com/sagernet/sing/common/network"
)

type ttlSplitClientTransport struct {
	base    adapter.V2RayClientTransport
	ttlPool dialer.TTLClientPool[adapter.V2RayClientTransport]
}

var (
	_ adapter.V2RayClientTransport          = (*ttlSplitClientTransport)(nil)
	_ adapter.V2RayMultiplexClientTransport = (*ttlSplitClientTransport)(nil)
	_ adapter.IdleConnectionKeeper          = (*ttlSplitClientTransport)(nil)
)

func wrapMultiplexClientTransport(
	base adapter.V2RayClientTransport,
	d N.Dialer,
	tlsConfig tls.Config,
	factory func(d N.Dialer, tlsCfg tls.Config) (adapter.V2RayClientTransport, error),
) adapter.V2RayClientTransport {
	if base == nil {
		return nil
	}
	t := &ttlSplitClientTransport{base: base}
	t.ttlPool.Init(func(ttl int) (adapter.V2RayClientTransport, error) {
		var clonedTLS tls.Config
		if tlsConfig != nil {
			clonedTLS = tlsConfig.Clone()
		}
		return factory(dialer.WrapWithInitialTTL(d, ttl), clonedTLS)
	})
	return t
}

func (t *ttlSplitClientTransport) selectTransport(ctx context.Context) (adapter.V2RayClientTransport, error) {
	return t.ttlPool.Get(ctx, t.base)
}

func (t *ttlSplitClientTransport) DialContext(ctx context.Context) (net.Conn, error) {
	tr, err := t.selectTransport(ctx)
	if err != nil {
		return nil, err
	}
	return tr.DialContext(ctx)
}

func (t *ttlSplitClientTransport) MultiplexEnabled() bool {
	if m, ok := t.base.(adapter.V2RayMultiplexClientTransport); ok {
		return m.MultiplexEnabled()
	}
	return true
}

func (t *ttlSplitClientTransport) SetKeepIdleConnections(keep bool) {
	if k, ok := t.base.(adapter.IdleConnectionKeeper); ok {
		k.SetKeepIdleConnections(keep)
	}
	t.ttlPool.ForEach(func(tr adapter.V2RayClientTransport) {
		if k, ok := tr.(adapter.IdleConnectionKeeper); ok {
			k.SetKeepIdleConnections(keep)
		}
	})
}

func (t *ttlSplitClientTransport) CloseIdleConnections() {
	if k, ok := t.base.(adapter.IdleConnectionKeeper); ok {
		k.CloseIdleConnections()
	}
	t.ttlPool.ForEach(func(tr adapter.V2RayClientTransport) {
		if k, ok := tr.(adapter.IdleConnectionKeeper); ok {
			k.CloseIdleConnections()
		}
	})
}

func (t *ttlSplitClientTransport) Close() error {
	err := t.base.Close()
	for _, tr := range t.ttlPool.TakeAll() {
		if tr != nil {
			if trErr := tr.Close(); trErr != nil && err == nil {
				err = trErr
			}
		}
	}
	return err
}
