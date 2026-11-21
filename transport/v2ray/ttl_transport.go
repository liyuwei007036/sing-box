package v2ray

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	N "github.com/sagernet/sing/common/network"
)

type ttlSplitClientTransport struct {
	base   adapter.V2RayClientTransport
	winMu  sync.Mutex
	win    adapter.V2RayClientTransport
	newWin func() (adapter.V2RayClientTransport, error)
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
	return &ttlSplitClientTransport{
		base: base,
		newWin: func() (adapter.V2RayClientTransport, error) {
			var winTLS tls.Config
			if tlsConfig != nil {
				winTLS = tlsConfig.Clone()
			}
			return factory(dialer.WrapWithInitialTTL(d, dialer.WindowsInitialTTL), winTLS)
		},
	}
}

func (t *ttlSplitClientTransport) selectTransport(ctx context.Context) (adapter.V2RayClientTransport, error) {
	if !dialer.IsWindowsTTLContext(ctx) || t.newWin == nil {
		return t.base, nil
	}
	t.winMu.Lock()
	defer t.winMu.Unlock()
	if t.win == nil {
		w, err := t.newWin()
		if err != nil {
			return nil, err
		}
		t.win = w
	}
	return t.win, nil
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
	t.winMu.Lock()
	win := t.win
	t.winMu.Unlock()
	if win != nil {
		if k, ok := win.(adapter.IdleConnectionKeeper); ok {
			k.SetKeepIdleConnections(keep)
		}
	}
}

func (t *ttlSplitClientTransport) CloseIdleConnections() {
	if k, ok := t.base.(adapter.IdleConnectionKeeper); ok {
		k.CloseIdleConnections()
	}
	t.winMu.Lock()
	win := t.win
	t.winMu.Unlock()
	if win != nil {
		if k, ok := win.(adapter.IdleConnectionKeeper); ok {
			k.CloseIdleConnections()
		}
	}
}

func (t *ttlSplitClientTransport) Close() error {
	err := t.base.Close()
	t.winMu.Lock()
	win := t.win
	t.win = nil
	t.winMu.Unlock()
	if win != nil {
		if winErr := win.Close(); winErr != nil && err == nil {
			err = winErr
		}
	}
	return err
}
