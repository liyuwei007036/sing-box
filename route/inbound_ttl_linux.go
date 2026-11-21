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
	inboundTTLSnaplen     = 128 // fits IPv6 (40B) + Apple TCP SYN (44B) comfortably
	inboundTTLEntryIdle   = 30 * time.Minute
	inboundTTLMaxEntries  = 65536
	inboundTTLMissWait    = 10 * time.Millisecond
	inboundTTLNftPriority = nftables.ChainPriority(10) // after host firewall filter input (priority 0)
	windowsMinObservedTTL = 65
	windowsMaxObservedTTL = 128
	linuxMinObservedTTL   = 129
	linuxMaxObservedTTL   = 192
	appleMinObservedTTL   = 193
)

type inboundTTLKey struct {
	proto   uint8
	srcIP   netip.Addr
	srcPort uint16
}

type inboundTTLEntry struct {
	profile  inboundOSProfile
	lastSeen atomic.Int64
}

type inboundTTLObserver struct {
	logger    log.ContextLogger
	nlConn    *netlink.Conn
	synRW     *outboundSYNRewriter
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

	synRW, synErr := newOutboundSYNRewriter(logger, boundGroup)
	if synErr != nil && logger != nil {
		logger.Warn("outbound SYN option rewriter unavailable (falling back to TTL-only): ", synErr)
	}

	tableName := fmt.Sprintf("sing_box_ttl_%d", boundGroup)
	if err := installInboundTTLNftRules(nftConn, tableName, boundGroup, synRW != nil); err != nil {
		if synRW != nil {
			_ = synRW.Close()
		}
		_ = nflogUnbindGroup(nlConn, boundGroup)
		_ = nlConn.Close()
		return nil, fmt.Errorf("install nftables ttl rules: %w", err)
	}

	obs := &inboundTTLObserver{
		logger:    logger,
		nlConn:    nlConn,
		synRW:     synRW,
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

func installInboundTTLNftRules(conn *nftables.Conn, tableName string, group uint16, withOutboundSYN bool) error {
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
	if withOutboundSYN {
		addOutboundSYNNftRules(conn, table, group)
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
			if key, profile, ok := parseL3PacketSourceProfile(ad.Bytes()); ok {
				o.record(key, profile)
			}
		}
	}
}

// isAppleTCPSYNOptions reports whether a TCP header carries the characteristic
// Apple XNU (macOS / iOS / iPadOS) SYN option prefix:
// MSS(2), NOP(1), WS(3), NOP(1), NOP(1), TS(8) [, SACK_PERM(4), EOL(0), EOL(0)].
func isAppleTCPSYNOptions(tcpHeader []byte) bool {
	if len(tcpHeader) < 20 {
		return false
	}
	// Require pure SYN (SYN=1, ACK=0).
	if (tcpHeader[13] & 0x12) != 0x02 {
		return false
	}
	dataOffset := int(tcpHeader[12]>>4) * 4
	if dataOffset <= 20 {
		return false
	}
	if dataOffset > len(tcpHeader) {
		dataOffset = len(tcpHeader)
	}
	opts := tcpHeader[20:dataOffset]
	want := [6]byte{2, 1, 3, 1, 1, 8}
	matched := 0
	for i := 0; i < len(opts) && matched < len(want); {
		kind := opts[i]
		if kind == 0 || kind != want[matched] {
			return false
		}
		matched++
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			return false
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return false
		}
		i += optLen
	}
	return matched == len(want)
}

func classifyInboundOSProfile(ttl uint8, proto uint8, l4 []byte) inboundOSProfile {
	switch {
	case ttl >= windowsMinObservedTTL && ttl <= windowsMaxObservedTTL:
		return inboundOSWindows
	case ttl >= appleMinObservedTTL:
		return inboundOSApple
	case ttl >= linuxMinObservedTTL && ttl <= linuxMaxObservedTTL:
		return inboundOSLinux
	case proto == unix.IPPROTO_TCP:
		if isAppleTCPSYNOptions(l4) {
			return inboundOSApple
		}
		return inboundOSLinux
	case proto == unix.IPPROTO_UDP:
		// Direct pure-UDP flows with TTL<=64 carry no TCP options and share TTL=64
		// between iOS/macOS and Android; fall back to Apple (macOS/iOS) as requested.
		return inboundOSApple
	default:
		return inboundOSLinux
	}
}

func parseL3PacketSourceProfile(pkt []byte) (inboundTTLKey, inboundOSProfile, bool) {
	if len(pkt) < 20 {
		return inboundTTLKey{}, inboundOSUnknown, false
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+2 {
			return inboundTTLKey{}, inboundOSUnknown, false
		}
		proto := pkt[9]
		if proto != unix.IPPROTO_TCP && proto != unix.IPPROTO_UDP {
			return inboundTTLKey{}, inboundOSUnknown, false
		}
		ttl := pkt[8]
		var ip4 [4]byte
		copy(ip4[:], pkt[12:16])
		srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		profile := classifyInboundOSProfile(ttl, proto, pkt[ihl:])
		return inboundTTLKey{
			proto:   proto,
			srcIP:   netip.AddrFrom4(ip4),
			srcPort: srcPort,
		}, profile, true
	case 6:
		if len(pkt) < 42 {
			return inboundTTLKey{}, inboundOSUnknown, false
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
					return inboundTTLKey{}, inboundOSUnknown, false
				}
				nextHdr = pkt[offset]
				offset += (int(pkt[offset+1]) + 1) * 8
			case unix.IPPROTO_FRAGMENT:
				if len(pkt) < offset+8 {
					return inboundTTLKey{}, inboundOSUnknown, false
				}
				nextHdr = pkt[offset]
				offset += 8
			default:
				return inboundTTLKey{}, inboundOSUnknown, false
			}
		}
		if (nextHdr != unix.IPPROTO_TCP && nextHdr != unix.IPPROTO_UDP) || len(pkt) < offset+2 {
			return inboundTTLKey{}, inboundOSUnknown, false
		}
		var ip6 [16]byte
		copy(ip6[:], pkt[8:24])
		srcPort := binary.BigEndian.Uint16(pkt[offset : offset+2])
		profile := classifyInboundOSProfile(hopLimit, nextHdr, pkt[offset:])
		return inboundTTLKey{
			proto:   nextHdr,
			srcIP:   netip.AddrFrom16(ip6).Unmap(),
			srcPort: srcPort,
		}, profile, true
	default:
		return inboundTTLKey{}, inboundOSUnknown, false
	}
}

func (o *inboundTTLObserver) record(key inboundTTLKey, profile inboundOSProfile) {
	now := time.Now().UnixNano()
	o.mu.RLock()
	entry, ok := o.entries[key]
	if ok && entry.profile == profile {
		entry.lastSeen.Store(now)
		o.mu.RUnlock()
		return
	}
	o.mu.RUnlock()

	o.mu.Lock()
	if existing, ok := o.entries[key]; ok {
		existing.profile = profile
		existing.lastSeen.Store(now)
	} else {
		if len(o.entries) >= inboundTTLMaxEntries {
			o.evictLocked(now)
		}
		e := &inboundTTLEntry{profile: profile}
		e.lastSeen.Store(now)
		o.entries[key] = e
	}
	if o.waiters.Load() > 0 {
		close(o.notifyCh)
		o.notifyCh = make(chan struct{})
	}
	o.mu.Unlock()
}

func (o *inboundTTLObserver) lookupOnce(proto uint8, srcIP netip.Addr, srcPort uint16) (inboundOSProfile, bool, <-chan struct{}) {
	key := inboundTTLKey{proto: proto, srcIP: srcIP, srcPort: srcPort}
	o.mu.RLock()
	entry, ok := o.entries[key]
	notify := o.notifyCh
	if ok {
		profile := entry.profile
		entry.lastSeen.Store(time.Now().UnixNano())
		o.mu.RUnlock()
		return profile, true, nil
	}
	o.mu.RUnlock()
	return inboundOSUnknown, false, notify
}

// LookupOSProfile returns the inferred originating OS profile for the outer
// transport flow (srcIP, srcPort).
func (o *inboundTTLObserver) LookupOSProfile(inboundType string, srcIP netip.Addr, srcPort uint16) inboundOSProfile {
	if o == nil || !srcIP.IsValid() || srcPort == 0 {
		return inboundOSUnknown
	}
	srcIP = srcIP.Unmap()

	firstProto, secondProto := uint8(unix.IPPROTO_TCP), uint8(unix.IPPROTO_UDP)
	switch inboundType {
	case C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC, C.TypeWireGuard:
		firstProto, secondProto = unix.IPPROTO_UDP, unix.IPPROTO_TCP
	}

	if profile, ok, _ := o.lookupOnce(firstProto, srcIP, srcPort); ok {
		return profile
	}
	if profile, ok, notify := o.lookupOnce(secondProto, srcIP, srcPort); ok {
		return profile
	} else if notify != nil {
		// On ultra-low-latency links (e.g. loopback / LAN), the userspace accept
		// can briefly outrun the NFLOG goroutine. Wait briefly for arrival.
		o.waiters.Add(1)
		defer o.waiters.Add(-1)
		// Re-check after registering waiter to avoid missing a concurrent record().
		if profile, ok, _ := o.lookupOnce(firstProto, srcIP, srcPort); ok {
			return profile
		}
		if profile, ok, nextNotify := o.lookupOnce(secondProto, srcIP, srcPort); ok {
			return profile
		} else {
			notify = nextNotify
		}
		deadline := time.NewTimer(inboundTTLMissWait)
		defer deadline.Stop()
		for {
			select {
			case <-notify:
				if profile, ok, _ := o.lookupOnce(firstProto, srcIP, srcPort); ok {
					return profile
				}
				if profile, ok, nextNotify := o.lookupOnce(secondProto, srcIP, srcPort); ok {
					return profile
				} else {
					notify = nextNotify
				}
			case <-deadline.C:
				return inboundOSUnknown
			case <-o.done:
				return inboundOSUnknown
			}
		}
	}
	return inboundOSUnknown
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
	if err := installInboundTTLNftRules(o.nftConn, o.tableName, o.group, o.synRW != nil); err != nil {
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
		if o.synRW != nil {
			if err := o.synRW.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
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
