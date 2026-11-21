//go:build linux

package route

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"golang.org/x/sys/unix"
)

const (
	nflogSubsysULog = 4

	nfulnlMsgPacket = 0
	nfulnlMsgConfig = 1

	nfulaPayload = 9

	nfulaCfgCmd     = 1
	nfulaCfgMode    = 2
	nfulaCfgTimeout = 4
	nfulaCfgQThresh = 5

	nfulnlCfgCmdBind   = 1
	nfulnlCfgCmdUnbind = 2

	nfulnlCopyPacket = 2

	inboundTTLGroupBase   = 128
	inboundTTLGroupMax    = 159
	inboundTTLSnaplen     = 64
	inboundTTLEntryIdle   = 30 * time.Minute
	inboundTTLMaxEntries  = 65536
	inboundTTLMissWait    = 10 * time.Millisecond
	inboundTTLNftPriority = nftables.ChainPriority(10) // after host firewall filter input (priority 0)
	windowsMinObservedTTL = 65
	windowsMaxObservedTTL = 128
)

type inboundTTLKey struct {
	proto   uint8
	srcIP   netip.Addr
	srcPort uint16
}

type inboundTTLEntry struct {
	ttl      uint8
	lastSeen atomic.Int64
}

type inboundTTLObserver struct {
	logger    log.ContextLogger
	nlConn    *netlink.Conn
	nftMu     sync.Mutex
	nftConn   *nftables.Conn
	tableName string
	group     uint16

	mu       sync.RWMutex
	entries  map[inboundTTLKey]*inboundTTLEntry
	notifyCh chan struct{}
	waiters  atomic.Int32

	closeOnce sync.Once
	done      chan struct{}
}

func newInboundTTLObserver(logger log.ContextLogger) (*inboundTTLObserver, error) {
	nlConn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("dial netfilter netlink: %w", err)
	}
	_ = nlConn.SetReadBuffer(1 << 20)

	var boundGroup uint16
	var bindErr error
	for g := uint16(inboundTTLGroupBase); g <= inboundTTLGroupMax; g++ {
		if err := nflogBindGroup(nlConn, g); err == nil {
			boundGroup = g
			bindErr = nil
			break
		} else {
			bindErr = err
		}
	}
	if bindErr != nil {
		_ = nlConn.Close()
		return nil, fmt.Errorf("bind nflog group: %w", bindErr)
	}

	nftConn, err := nftables.New()
	if err != nil {
		_ = nflogUnbindGroup(nlConn, boundGroup)
		_ = nlConn.Close()
		return nil, fmt.Errorf("open nftables netlink: %w", err)
	}

	tableName := fmt.Sprintf("sing_box_ttl_%d", boundGroup)
	if err := installInboundTTLNftRules(nftConn, tableName, boundGroup); err != nil {
		_ = nflogUnbindGroup(nlConn, boundGroup)
		_ = nlConn.Close()
		return nil, fmt.Errorf("install nftables ttl rules: %w", err)
	}

	obs := &inboundTTLObserver{
		logger:    logger,
		nlConn:    nlConn,
		nftConn:   nftConn,
		tableName: tableName,
		group:     boundGroup,
		entries:   make(map[inboundTTLKey]*inboundTTLEntry, 256),
		notifyCh:  make(chan struct{}),
		done:      make(chan struct{}),
	}
	go obs.readLoop()
	go obs.cleanupLoop()
	return obs, nil
}

func nflogConfigMessage(group uint16, attrs []netlink.Attribute) (netlink.Message, error) {
	attrBytes, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	data := make([]byte, 4+len(attrBytes))
	data[0] = unix.AF_UNSPEC
	data[1] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(data[2:4], group)
	copy(data[4:], attrBytes)
	return netlink.Message{
		Header: netlink.Header{
			Type:  (nflogSubsysULog << 8) | nfulnlMsgConfig,
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}, nil
}

func nflogBindGroup(conn *netlink.Conn, group uint16) error {
	bindMsg, err := nflogConfigMessage(group, []netlink.Attribute{
		{Type: nfulaCfgCmd, Data: []byte{nfulnlCfgCmdBind}},
	})
	if err != nil {
		return err
	}
	if _, err := conn.Execute(bindMsg); err != nil {
		return err
	}

	modeBuf := make([]byte, 6)
	binary.BigEndian.PutUint32(modeBuf[0:4], inboundTTLSnaplen)
	modeBuf[4] = nfulnlCopyPacket
	modeBuf[5] = 0

	qThreshBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(qThreshBuf, 1)

	timeoutBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(timeoutBuf, 1)

	cfgMsg, err := nflogConfigMessage(group, []netlink.Attribute{
		{Type: nfulaCfgMode, Data: modeBuf},
		{Type: nfulaCfgQThresh, Data: qThreshBuf},
		{Type: nfulaCfgTimeout, Data: timeoutBuf},
	})
	if err != nil {
		_ = nflogUnbindGroup(conn, group)
		return err
	}
	if _, err := conn.Execute(cfgMsg); err != nil {
		_ = nflogUnbindGroup(conn, group)
		return err
	}
	return nil
}

func nflogUnbindGroup(conn *netlink.Conn, group uint16) error {
	msg, err := nflogConfigMessage(group, []netlink.Attribute{
		{Type: nfulaCfgCmd, Data: []byte{nfulnlCfgCmdUnbind}},
	})
	if err != nil {
		return err
	}
	_, err = conn.Execute(msg)
	return err
}

func installInboundTTLNftRules(conn *nftables.Conn, tableName string, group uint16) error {
	// Best-effort cleanup of any stale table left behind by a prior SIGKILL/OOM
	// restart that previously owned this exact exclusive NFLOG group.
	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
	_ = conn.Flush()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
	// Hook on input at priority +10 (after host firewall filter input at priority 0)
	// so port scans, fail2ban drops, and non-local forwarded packets never reach NFLOG.
	priority := inboundTTLNftPriority
	chain := conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &priority,
		Policy:   common.Ptr(nftables.ChainPolicyAccept),
	})

	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{0, 0, 0, 0},
				},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{proto},
				},
				&expr.Log{
					Key:        (1 << unix.NFTA_LOG_GROUP) | (1 << unix.NFTA_LOG_SNAPLEN) | (1 << unix.NFTA_LOG_QTHRESHOLD),
					Group:      group,
					Snaplen:    inboundTTLSnaplen,
					QThreshold: 1,
				},
			},
		})
	}
	return conn.Flush()
}

func (o *inboundTTLObserver) readLoop() {
	for {
		msgs, err := o.nlConn.Receive()
		if err != nil {
			select {
			case <-o.done:
				return
			default:
			}
			if errors.Is(err, unix.ENOBUFS) {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		for _, msg := range msgs {
			if msg.Header.Type != ((nflogSubsysULog << 8) | nfulnlMsgPacket) {
				continue
			}
			if len(msg.Data) < 4 {
				continue
			}
			o.handlePacketAttributes(msg.Data[4:])
		}
	}
}

func (o *inboundTTLObserver) handlePacketAttributes(attrData []byte) {
	ad, err := netlink.NewAttributeDecoder(attrData)
	if err != nil {
		return
	}
	for ad.Next() {
		if ad.Type() == nfulaPayload {
			if key, ttl, ok := parseL3PacketSourceTTL(ad.Bytes()); ok {
				o.record(key, ttl)
			}
		}
	}
}

func parseL3PacketSourceTTL(pkt []byte) (inboundTTLKey, uint8, bool) {
	if len(pkt) < 20 {
		return inboundTTLKey{}, 0, false
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+2 {
			return inboundTTLKey{}, 0, false
		}
		proto := pkt[9]
		if proto != unix.IPPROTO_TCP && proto != unix.IPPROTO_UDP {
			return inboundTTLKey{}, 0, false
		}
		ttl := pkt[8]
		var ip4 [4]byte
		copy(ip4[:], pkt[12:16])
		srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		return inboundTTLKey{
			proto:   proto,
			srcIP:   netip.AddrFrom4(ip4),
			srcPort: srcPort,
		}, ttl, true
	case 6:
		if len(pkt) < 42 {
			return inboundTTLKey{}, 0, false
		}
		hopLimit := pkt[7]
		nextHdr := pkt[6]
		offset := 40
		// Walk common IPv6 extension headers when present within snaplen.
		for range 4 {
			if nextHdr == unix.IPPROTO_TCP || nextHdr == unix.IPPROTO_UDP {
				break
			}
			switch nextHdr {
			case unix.IPPROTO_HOPOPTS, unix.IPPROTO_ROUTING, unix.IPPROTO_DSTOPTS:
				if len(pkt) < offset+2 {
					return inboundTTLKey{}, 0, false
				}
				nextHdr = pkt[offset]
				offset += (int(pkt[offset+1]) + 1) * 8
			case unix.IPPROTO_FRAGMENT:
				if len(pkt) < offset+8 {
					return inboundTTLKey{}, 0, false
				}
				nextHdr = pkt[offset]
				offset += 8
			default:
				return inboundTTLKey{}, 0, false
			}
		}
		if (nextHdr != unix.IPPROTO_TCP && nextHdr != unix.IPPROTO_UDP) || len(pkt) < offset+2 {
			return inboundTTLKey{}, 0, false
		}
		var ip6 [16]byte
		copy(ip6[:], pkt[8:24])
		srcPort := binary.BigEndian.Uint16(pkt[offset : offset+2])
		return inboundTTLKey{
			proto:   nextHdr,
			srcIP:   netip.AddrFrom16(ip6).Unmap(),
			srcPort: srcPort,
		}, hopLimit, true
	default:
		return inboundTTLKey{}, 0, false
	}
}

func (o *inboundTTLObserver) record(key inboundTTLKey, ttl uint8) {
	now := time.Now().UnixNano()
	o.mu.RLock()
	entry, ok := o.entries[key]
	if ok && entry.ttl == ttl {
		entry.lastSeen.Store(now)
		o.mu.RUnlock()
		return
	}
	o.mu.RUnlock()

	o.mu.Lock()
	if existing, ok := o.entries[key]; ok {
		existing.ttl = ttl
		existing.lastSeen.Store(now)
	} else {
		if len(o.entries) >= inboundTTLMaxEntries {
			o.evictLocked(now)
		}
		e := &inboundTTLEntry{ttl: ttl}
		e.lastSeen.Store(now)
		o.entries[key] = e
	}
	if o.waiters.Load() > 0 {
		close(o.notifyCh)
		o.notifyCh = make(chan struct{})
	}
	o.mu.Unlock()
}

func (o *inboundTTLObserver) lookupOnce(proto uint8, srcIP netip.Addr, srcPort uint16) (uint8, bool, <-chan struct{}) {
	key := inboundTTLKey{proto: proto, srcIP: srcIP, srcPort: srcPort}
	o.mu.RLock()
	entry, ok := o.entries[key]
	notify := o.notifyCh
	if ok {
		ttl := entry.ttl
		entry.lastSeen.Store(time.Now().UnixNano())
		o.mu.RUnlock()
		return ttl, true, nil
	}
	o.mu.RUnlock()
	return 0, false, notify
}

// IsWindowsSource reports whether the outer transport flow for (srcIP, srcPort)
// arrived with a Windows-range IP TTL / Hop Limit (65..128).
func (o *inboundTTLObserver) IsWindowsSource(inboundType string, srcIP netip.Addr, srcPort uint16) bool {
	if o == nil || !srcIP.IsValid() || srcPort == 0 {
		return false
	}
	srcIP = srcIP.Unmap()

	firstProto, secondProto := uint8(unix.IPPROTO_TCP), uint8(unix.IPPROTO_UDP)
	switch inboundType {
	case C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC, C.TypeWireGuard:
		firstProto, secondProto = unix.IPPROTO_UDP, unix.IPPROTO_TCP
	}

	if ttl, ok, _ := o.lookupOnce(firstProto, srcIP, srcPort); ok {
		return isWindowsObservedTTL(ttl)
	}
	if ttl, ok, notify := o.lookupOnce(secondProto, srcIP, srcPort); ok {
		return isWindowsObservedTTL(ttl)
	} else if notify != nil {
		// On ultra-low-latency links (e.g. loopback / LAN), the userspace accept
		// can briefly outrun the NFLOG goroutine. Wait briefly for arrival.
		o.waiters.Add(1)
		defer o.waiters.Add(-1)
		// Re-check after registering waiter to avoid missing a concurrent record().
		if ttl, ok, _ := o.lookupOnce(firstProto, srcIP, srcPort); ok {
			return isWindowsObservedTTL(ttl)
		}
		if ttl, ok, nextNotify := o.lookupOnce(secondProto, srcIP, srcPort); ok {
			return isWindowsObservedTTL(ttl)
		} else {
			notify = nextNotify
		}
		deadline := time.NewTimer(inboundTTLMissWait)
		defer deadline.Stop()
		for {
			select {
			case <-notify:
				if ttl, ok, _ := o.lookupOnce(firstProto, srcIP, srcPort); ok {
					return isWindowsObservedTTL(ttl)
				}
				if ttl, ok, nextNotify := o.lookupOnce(secondProto, srcIP, srcPort); ok {
					return isWindowsObservedTTL(ttl)
				} else {
					notify = nextNotify
				}
			case <-deadline.C:
				return false
			case <-o.done:
				return false
			}
		}
	}
	return false
}

func isWindowsObservedTTL(ttl uint8) bool {
	return ttl >= windowsMinObservedTTL && ttl <= windowsMaxObservedTTL
}

func (o *inboundTTLObserver) ensureNftTable() {
	o.nftMu.Lock()
	defer o.nftMu.Unlock()
	select {
	case <-o.done:
		return
	default:
	}
	if o.nftConn == nil || o.tableName == "" {
		return
	}
	tables, err := o.nftConn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return
	}
	for _, t := range tables {
		if t.Name == o.tableName {
			return
		}
	}
	if err := installInboundTTLNftRules(o.nftConn, o.tableName, o.group); err != nil {
		if o.logger != nil {
			o.logger.Warn("reinstall inbound TTL nftables table: ", err)
		}
	} else if o.logger != nil {
		o.logger.Info("reinstalled inbound TTL nftables table ", o.tableName)
	}
}

func (o *inboundTTLObserver) Group() uint16 {
	if o == nil {
		return 0
	}
	return o.group
}

func (o *inboundTTLObserver) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			o.mu.Lock()
			o.evictLocked(now)
			o.mu.Unlock()
			o.ensureNftTable()
		case <-o.done:
			return
		}
	}
}

func (o *inboundTTLObserver) evictLocked(now int64) {
	// Tiered idle eviction preserves active long-lived multiplexed sessions (e.g.
	// Hysteria2) while shedding stale entries and single-packet flood noise first.
	for _, idle := range []time.Duration{
		inboundTTLEntryIdle,
		5 * time.Minute,
		30 * time.Second,
		5 * time.Second,
	} {
		cutoff := now - idle.Nanoseconds()
		for k, e := range o.entries {
			if e.lastSeen.Load() < cutoff {
				delete(o.entries, k)
			}
		}
		if len(o.entries) < inboundTTLMaxEntries*3/4 {
			return
		}
	}
	// Hard cap safety under sustained open-port flood.
	if len(o.entries) >= inboundTTLMaxEntries {
		drop := len(o.entries) - inboundTTLMaxEntries*3/4
		for k := range o.entries {
			delete(o.entries, k)
			drop--
			if drop <= 0 {
				break
			}
		}
	}
}

func (o *inboundTTLObserver) Close() error {
	var firstErr error
	o.closeOnce.Do(func() {
		close(o.done)
		o.nftMu.Lock()
		if o.nftConn != nil && o.tableName != "" {
			o.nftConn.DelTable(&nftables.Table{
				Family: nftables.TableFamilyINet,
				Name:   o.tableName,
			})
			if err := o.nftConn.Flush(); err != nil {
				firstErr = err
			}
		}
		o.nftMu.Unlock()
		if o.nlConn != nil {
			// Closing the netfilter netlink socket releases all bound NFLOG groups
			// in the kernel automatically without racing with readLoop's Receive().
			if err := o.nlConn.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}
