package mux

import (
	"context"
	"net"

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

// Client wraps sing-mux.Client with lazy companion clients keyed by non-zero
// initial TTL (e.g., 128 for Windows, 192 for Linux, 255 for Apple) so
// multiplexed chained outbounds never mix OS fingerprints on the same outer TCP.
type Client struct {
	base    *mux.Client
	ttlPool dialer.TTLClientPool[*mux.Client]
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
	c := &Client{base: base}
	c.ttlPool.Init(func(ttl int) (*mux.Client, error) {
		ttlOpts := baseOpts
		ttlOpts.Dialer = &clientDialer{Dialer: d, initialTTL: ttl}
		return mux.NewClient(ttlOpts)
	})
	return c, nil
}

func (c *Client) selectClient(ctx context.Context) (*mux.Client, error) {
	return c.ttlPool.Get(ctx, c.base)
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
	c.ttlPool.ForEach(func(cl *mux.Client) {
		cl.Reset()
	})
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.base.SetKeepIdleConnections(keep)
	c.ttlPool.ForEach(func(cl *mux.Client) {
		cl.SetKeepIdleConnections(keep)
	})
}

func (c *Client) CloseIdleConnections() {
	c.base.CloseIdleConnections()
	c.ttlPool.ForEach(func(cl *mux.Client) {
		cl.CloseIdleConnections()
	})
}

func (c *Client) Close() error {
	err := c.base.Close()
	for _, cl := range c.ttlPool.TakeAll() {
		if cl != nil {
			if clErr := cl.Close(); clErr != nil && err == nil {
				err = clErr
			}
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
