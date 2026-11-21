package mux

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Client wraps sing-mux.Client with a lazy companion client for Windows-TTL
// flows so multiplexed chained outbounds never mix TTL=128 and TTL=64 traffic
// onto the same outer TCP connection.
type Client struct {
	base         *mux.Client
	winMu        sync.Mutex
	win          *mux.Client
	newWinClient func() (*mux.Client, error)
}

func NewClientWithOptions(d N.Dialer, logger logger.Logger, options option.OutboundMultiplexOptions) (*Client, error) {
	if !options.Enabled {
		return nil, nil
	}
	var brutalOptions mux.BrutalOptions
	if options.Brutal != nil && options.Brutal.Enabled {
		brutalOptions = mux.BrutalOptions{
			Enabled:    true,
			SendBPS:    uint64(options.Brutal.UpMbps * C.MbpsToBps),
			ReceiveBPS: uint64(options.Brutal.DownMbps * C.MbpsToBps),
		}
		if brutalOptions.SendBPS < mux.BrutalMinSpeedBPS {
			return nil, E.New("brutal: invalid upload speed")
		}
		if brutalOptions.ReceiveBPS < mux.BrutalMinSpeedBPS {
			return nil, E.New("brutal: invalid download speed")
		}
	}
	baseOpts := mux.Options{
		Dialer:         &clientDialer{Dialer: d},
		Logger:         logger,
		Protocol:       options.Protocol,
		MaxConnections: options.MaxConnections,
		MinStreams:     options.MinStreams,
		MaxStreams:     options.MaxStreams,
		Padding:        options.Padding,
		Brutal:         brutalOptions,
	}
	base, err := mux.NewClient(baseOpts)
	if err != nil {
		return nil, err
	}
	return &Client{
		base: base,
		newWinClient: func() (*mux.Client, error) {
			winOpts := baseOpts
			winOpts.Dialer = &clientDialer{Dialer: d, initialTTL: dialer.WindowsInitialTTL}
			return mux.NewClient(winOpts)
		},
	}, nil
}

func (c *Client) selectClient(ctx context.Context) (*mux.Client, error) {
	if !dialer.IsWindowsTTLContext(ctx) || c.newWinClient == nil {
		return c.base, nil
	}
	c.winMu.Lock()
	defer c.winMu.Unlock()
	if c.win == nil {
		w, err := c.newWinClient()
		if err != nil {
			return nil, err
		}
		c.win = w
	}
	return c.win, nil
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client, err := c.selectClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.DialContext(ctx, network, destination)
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	client, err := c.selectClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.ListenPacket(ctx, destination)
}

func (c *Client) Reset() {
	c.base.Reset()
	c.winMu.Lock()
	win := c.win
	c.winMu.Unlock()
	if win != nil {
		win.Reset()
	}
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.base.SetKeepIdleConnections(keep)
	c.winMu.Lock()
	win := c.win
	c.winMu.Unlock()
	if win != nil {
		win.SetKeepIdleConnections(keep)
	}
}

func (c *Client) CloseIdleConnections() {
	c.base.CloseIdleConnections()
	c.winMu.Lock()
	win := c.win
	c.winMu.Unlock()
	if win != nil {
		win.CloseIdleConnections()
	}
}

func (c *Client) Close() error {
	err := c.base.Close()
	c.winMu.Lock()
	win := c.win
	c.win = nil
	c.winMu.Unlock()
	if win != nil {
		if winErr := win.Close(); winErr != nil && err == nil {
			err = winErr
		}
	}
	return err
}

type clientDialer struct {
	N.Dialer
	initialTTL int
}

func (d *clientDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	sessionCtx := adapter.ContextForMultiplexSession(ctx)
	if d.initialTTL > 0 {
		sessionCtx = dialer.WithInitialTTL(sessionCtx, d.initialTTL)
	}
	return d.Dialer.DialContext(sessionCtx, network, destination)
}

func (d *clientDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	sessionCtx := adapter.ContextForMultiplexSession(ctx)
	if d.initialTTL > 0 {
		sessionCtx = dialer.WithInitialTTL(sessionCtx, d.initialTTL)
	}
	return d.Dialer.ListenPacket(sessionCtx, destination)
}
