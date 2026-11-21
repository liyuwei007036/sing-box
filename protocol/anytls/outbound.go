package anytls

import (
	"context"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AnyTLSOutboundOptions](registry, C.TypeAnyTLS, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	dialer        tls.Dialer
	server        M.Socksaddr
	tlsConfig     tls.Config
	clientOptions anytls.ClientOptions
	client        *anytls.Client
	uotClient     *uot.Client
	winMu         sync.Mutex
	winClient     *anytls.Client
	winUOTClient  *uot.Client
	logger        log.ContextLogger
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSOutboundOptions) (adapter.Outbound, error) {
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeAnyTLS, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		server:  options.ServerOptions.Build(),
		logger:  logger,
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.DialerOptions.TCPFastOpen {
		return nil, E.New("tcp_fast_open is not supported with anytls outbound")
	}

	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	outbound.tlsConfig = tlsConfig

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}

	outbound.dialer = tls.NewDialer(outboundDialer, tlsConfig)

	outbound.clientOptions = anytls.ClientOptions{
		Password:                 options.Password,
		ClientMetadata:           options.ClientMetadata,
		DialOut:                  outbound.dialOut,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(),
		MinIdleSession:           options.MinIdleSession,
		Logger:                   logger,
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	client, err := anytls.NewClient(h.clientOptions)
	if err != nil {
		return err
	}
	h.client = client
	scope.Add(func() error {
		err := client.Close()
		h.winMu.Lock()
		winClient := h.winClient
		h.winClient = nil
		h.winUOTClient = nil
		h.winMu.Unlock()
		if winClient != nil {
			if winErr := winClient.Close(); winErr != nil && err == nil {
				err = winErr
			}
		}
		return err
	})
	h.uotClient = &uot.Client{
		Dialer:  anytlsDialer(client.DialContext),
		Version: uot.Version,
	}
	return nil
}

type anytlsDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func (d anytlsDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d anytlsDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) dialOut(ctx context.Context) (net.Conn, error) {
	return h.dialer.DialTLSContext(adapter.ContextForMultiplexSession(ctx), h.server)
}

func (h *Outbound) dialOutWindows(ctx context.Context) (net.Conn, error) {
	return h.dialer.DialTLSContext(dialer.WithInitialTTL(adapter.ContextForMultiplexSession(ctx), dialer.WindowsInitialTTL), h.server)
}

func (h *Outbound) selectClients(ctx context.Context) (*anytls.Client, *uot.Client, error) {
	if !dialer.IsWindowsTTLContext(ctx) {
		return h.client, h.uotClient, nil
	}
	h.winMu.Lock()
	defer h.winMu.Unlock()
	if h.winClient == nil {
		winOptions := h.clientOptions
		winOptions.DialOut = h.dialOutWindows
		c, err := anytls.NewClient(winOptions)
		if err != nil {
			return nil, nil, err
		}
		h.winClient = c
		h.winUOTClient = &uot.Client{
			Dialer:  anytlsDialer(c.DialContext),
			Version: uot.Version,
		}
	}
	return h.winClient, h.winUOTClient, nil
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.Reset()
	h.winMu.Lock()
	winClient := h.winClient
	h.winMu.Unlock()
	if winClient != nil {
		winClient.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	h.client.SetKeepIdleConnections(keep)
	h.winMu.Lock()
	winClient := h.winClient
	h.winMu.Unlock()
	if winClient != nil {
		winClient.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	h.client.CloseIdleConnections()
	h.winMu.Lock()
	winClient := h.winClient
	h.winMu.Unlock()
	if winClient != nil {
		winClient.CloseIdleConnections()
	}
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	client, uotClient, err := h.selectClients(ctx)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return uotClient.DialContext(ctx, network, destination)
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	_, uotClient, err := h.selectClients(ctx)
	if err != nil {
		return nil, err
	}
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return uotClient.ListenPacket(ctx, destination)
}
