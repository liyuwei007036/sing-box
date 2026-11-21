package hysteria

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HysteriaOutboundOptions](registry, C.TypeHysteria, NewOutbound)
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger       logger.ContextLogger
	client       *hysteria.Client
	winMu        sync.Mutex
	winClient    *hysteria.Client
	newWinClient func() (*hysteria.Client, error)
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HysteriaOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	networkList := options.Network.Build()
	var password string
	if options.AuthString != "" {
		password = options.AuthString
	} else {
		password = string(options.Auth)
	}
	var sendBps, receiveBps uint64
	if options.Up.Value() > 0 {
		sendBps = options.Up.Value()
	} else {
		sendBps = uint64(options.UpMbps) * hysteria.MbpsToBps
	}
	if options.Down.Value() > 0 {
		receiveBps = options.Down.Value()
	} else {
		receiveBps = uint64(options.DownMbps) * hysteria.MbpsToBps
	}
	clientOptions := hysteria.ClientOptions{
		Context:       ctx,
		Dialer:        outboundDialer,
		Logger:        logger,
		ServerAddress: options.ServerOptions.Build(),
		ServerPorts:   options.ServerPorts,
		HopInterval:   time.Duration(options.HopInterval),
		SendBPS:       sendBps,
		ReceiveBPS:    receiveBps,
		XPlusPassword: options.Obfs,
		Password:      password,
		TLSConfig:     tlsConfig,
		QUICOptions:   buildOutboundQUICOptions(options),
		UDPDisabled:   !common.Contains(networkList, N.NetworkUDP),
	}
	client, err := hysteria.NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHysteria, tag, networkList, options.DialerOptions),
		logger:  logger,
		client:  client,
		newWinClient: func() (*hysteria.Client, error) {
			winOptions := clientOptions
			winOptions.TLSConfig = tlsConfig.Clone()
			winOptions.Dialer = dialer.WrapWithInitialTTL(outboundDialer, dialer.WindowsInitialTTL)
			return hysteria.NewClient(winOptions)
		},
	}, nil
}

func (h *Outbound) selectClient(ctx context.Context) (*hysteria.Client, error) {
	if !dialer.IsWindowsTTLContext(ctx) || h.newWinClient == nil {
		return h.client, nil
	}
	h.winMu.Lock()
	defer h.winMu.Unlock()
	if h.winClient == nil {
		c, err := h.newWinClient()
		if err != nil {
			return nil, err
		}
		h.winClient = c
	}
	return h.winClient, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		client, err := h.selectClient(ctx)
		if err != nil {
			return nil, err
		}
		return client.DialConn(ctx, destination)
	case N.NetworkUDP:
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	client, err := h.selectClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.ListenPacket(ctx, destination)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.CloseWithError(E.New("network changed"))
	h.winMu.Lock()
	winClient := h.winClient
	h.winMu.Unlock()
	if winClient != nil {
		winClient.CloseWithError(E.New("network changed"))
	}
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
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

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		err := h.client.CloseWithError(os.ErrClosed)
		h.winMu.Lock()
		winClient := h.winClient
		h.winClient = nil
		h.winMu.Unlock()
		if winClient != nil {
			if winErr := winClient.CloseWithError(os.ErrClosed); winErr != nil && err == nil {
				err = winErr
			}
		}
		return err
	})
	return nil
}
