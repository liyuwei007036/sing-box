//go:build linux

package route

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"golang.org/x/sys/unix"
)

const (
	nfqSubsysQueue = 3

	nfqnlMsgPacket  = 0
	nfqnlMsgVerdict = 1
	nfqnlMsgConfig  = 2

	nfqaPacketHdr  = 1
	nfqaVerdictHdr = 2
	nfqaPayload    = 10

	nfqaCfgCmd    = 1
	nfqaCfgParams = 2
	nfqaCfgFlags  = 4
	nfqaCfgMask   = 5

	nfqnlCfgCmdBind   = 1
	nfqnlCfgCmdUnbind = 2

	nfqnlCopyPacket = 2
	nfqaCfgFailOpen = 1 << 0

	nfAccept = 1

	nfqCopyRange = 256
)

// outboundSYNRewriter intercepts ONLY outbound pure TCP SYN packets whose
// IPv4 TTL / IPv6 Hop Limit == 128 via NFQUEUE (with kernel bypass + fail-open)
// and reorders their TCP options to match native Windows 10/11:
//
//	MSS(orig), NOP, WSCALE(orig), NOP, NOP, SACK_PERM
//
// Removing TCP Timestamp from the SYN is 100% RFC 7323 compliant (the remote
// server omits TS in SYN-ACK and the Linux kernel sets tstamp_ok=0), while
// keeping MSS and WSCALE identical to what the Linux kernel natively selected
// (WSCALE=8 via SO_RCVBUFFORCE) so TCP state never desyncs.
type outboundSYNRewriter struct {
	logger    log.ContextLogger
	nlConn    *netlink.Conn
	queueNum  uint16
	closeOnce sync.Once
	done      chan struct{}
}

func newOutboundSYNRewriter(logger log.ContextLogger, queueNum uint16) (*outboundSYNRewriter, error) {
	nlConn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("dial nfqueue netlink: %w", err)
	}
	_ = nlConn.SetReadBuffer(1 << 20)

	if err := nfqBindQueue(nlConn, queueNum); err != nil {
		_ = nlConn.Close()
		return nil, fmt.Errorf("bind nfqueue %d: %w", queueNum, err)
	}

	r := &outboundSYNRewriter{
		logger:   logger,
		nlConn:   nlConn,
		queueNum: queueNum,
		done:     make(chan struct{}),
	}
	go r.readLoop()
	return r, nil
}

func nfqConfigMessage(queueNum uint16, attrs []netlink.Attribute) (netlink.Message, error) {
	attrBytes, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	data := make([]byte, 4+len(attrBytes))
	data[0] = unix.AF_UNSPEC
	data[1] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(data[2:4], queueNum)
	copy(data[4:], attrBytes)
	return netlink.Message{
		Header: netlink.Header{
			Type:  (nfqSubsysQueue << 8) | nfqnlMsgConfig,
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}, nil
}

func nfqBindQueue(conn *netlink.Conn, queueNum uint16) error {
	// struct nfqnl_msg_config_cmd { __u8 command; __u8 _pad; __be16 pf; }
	cmdBuf := []byte{nfqnlCfgCmdBind, 0, 0, 0}
	bindMsg, err := nfqConfigMessage(queueNum, []netlink.Attribute{
		{Type: nfqaCfgCmd, Data: cmdBuf},
	})
	if err != nil {
		return err
	}
	if _, err := conn.Execute(bindMsg); err != nil {
		return err
	}

	// struct nfqnl_msg_config_params { __be32 copy_range; __u8 copy_mode; }
	paramsBuf := make([]byte, 5)
	binary.BigEndian.PutUint32(paramsBuf[0:4], nfqCopyRange)
	paramsBuf[4] = nfqnlCopyPacket

	failOpenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(failOpenBuf, nfqaCfgFailOpen)

	cfgMsg, err := nfqConfigMessage(queueNum, []netlink.Attribute{
		{Type: nfqaCfgParams, Data: paramsBuf},
		{Type: nfqaCfgFlags, Data: failOpenBuf},
		{Type: nfqaCfgMask, Data: failOpenBuf},
	})
	if err != nil {
		return err
	}
	if _, err := conn.Execute(cfgMsg); err != nil {
		return err
	}
	return nil
}

func addOutboundSYNNftRules(conn *nftables.Conn, table *nftables.Table, queueNum uint16) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   common.Ptr(nftables.ChainPolicyAccept),
	})

	// Rule 1: IPv4 TTL == 128 && pure TCP SYN (FIN=0,SYN=1,RST=0,ACK=0)
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{128}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x17}, Xor: []byte{0x00}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
			&expr.Queue{Num: queueNum, Total: 1, Flag: expr.QueueFlagBypass},
		},
	})

	// Rule 2: IPv6 HopLimit == 128 && pure TCP SYN
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{128}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x17}, Xor: []byte{0x00}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
			&expr.Queue{Num: queueNum, Total: 1, Flag: expr.QueueFlagBypass},
		},
	})
}

func (r *outboundSYNRewriter) readLoop() {
	for {
		msgs, err := r.nlConn.Receive()
		if err != nil {
			select {
			case <-r.done:
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
			if msg.Header.Type != ((nfqSubsysQueue << 8) | nfqnlMsgPacket) {
				continue
			}
			if len(msg.Data) < 4 {
				continue
			}
			r.handlePacket(msg.Data[0], msg.Data[4:])
		}
	}
}

func (r *outboundSYNRewriter) handlePacket(family uint8, attrData []byte) {
	ad, err := netlink.NewAttributeDecoder(attrData)
	if err != nil {
		return
	}
	var (
		hasID   bool
		pktID   uint32
		payload []byte
	)
	for ad.Next() {
		switch ad.Type() {
		case nfqaPacketHdr:
			b := ad.Bytes()
			if len(b) >= 4 {
				pktID = binary.BigEndian.Uint32(b[0:4])
				hasID = true
			}
		case nfqaPayload:
			payload = ad.Bytes()
		}
	}
	if !hasID {
		return
	}
	modified, ok := rewriteTCPSYNToWindows(payload)
	if ok {
		r.sendVerdict(family, pktID, modified)
	} else {
		r.sendVerdict(family, pktID, nil)
	}
}

func (r *outboundSYNRewriter) sendVerdict(family uint8, pktID uint32, modifiedPayload []byte) {
	// struct nfqnl_msg_verdict_hdr { __be32 verdict; __be32 id; }
	verdictBuf := make([]byte, 8)
	binary.BigEndian.PutUint32(verdictBuf[0:4], nfAccept)
	binary.BigEndian.PutUint32(verdictBuf[4:8], pktID)

	attrs := make([]netlink.Attribute, 0, 2)
	attrs = append(attrs, netlink.Attribute{Type: nfqaVerdictHdr, Data: verdictBuf})
	if len(modifiedPayload) > 0 {
		attrs = append(attrs, netlink.Attribute{Type: nfqaPayload, Data: modifiedPayload})
	}
	attrBytes, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return
	}
	data := make([]byte, 4+len(attrBytes))
	data[0] = family
	data[1] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(data[2:4], r.queueNum)
	copy(data[4:], attrBytes)

	_, _ = r.nlConn.Send(netlink.Message{
		Header: netlink.Header{
			Type:  (nfqSubsysQueue << 8) | nfqnlMsgVerdict,
			Flags: netlink.Request,
		},
		Data: data,
	})
}

func (r *outboundSYNRewriter) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.done)
		if r.nlConn != nil {
			err = r.nlConn.Close()
		}
	})
	return err
}

// rewriteTCPSYNToWindows rewrites a Linux IPv4/IPv6 TCP SYN packet's TCP options
// to native Windows 10/11 layout: MSS, NOP, WSCALE, NOP, NOP, SACK_PERM (12 bytes),
// keeping the kernel-chosen MSS and WSCALE intact and recomputing IP + TCP checksums.
func rewriteTCPSYNToWindows(pkt []byte) ([]byte, bool) {
	if len(pkt) < 40 {
		return nil, false
	}
	version := pkt[0] >> 4
	var (
		l4Offset int
		isIPv6   bool
	)
	switch version {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+20 || pkt[9] != unix.IPPROTO_TCP {
			return nil, false
		}
		l4Offset = ihl
	case 6:
		if len(pkt) < 60 || pkt[6] != unix.IPPROTO_TCP {
			return nil, false
		}
		l4Offset = 40
		isIPv6 = true
	default:
		return nil, false
	}

	tcpHdr := pkt[l4Offset:]
	doff := int(tcpHdr[12]>>4) * 4
	if doff < 20 || len(tcpHdr) < doff {
		return nil, false
	}
	// Verify pure SYN (FIN=0, SYN=1, RST=0, ACK=0).
	if (tcpHdr[13] & 0x17) != 0x02 {
		return nil, false
	}

	origOpts := tcpHdr[20:doff]
	var (
		hasMSS    bool
		mss       uint16
		hasWScale bool
		wscale    uint8
		hasSACK   bool
	)
	for i := 0; i < len(origOpts); {
		kind := origOpts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(origOpts) {
			break
		}
		optLen := int(origOpts[i+1])
		if optLen < 2 || i+optLen > len(origOpts) {
			break
		}
		switch kind {
		case 2: // MSS
			if optLen == 4 {
				mss = binary.BigEndian.Uint16(origOpts[i+2 : i+4])
				hasMSS = true
			}
		case 3: // Window Scale
			if optLen == 3 {
				wscale = origOpts[i+2]
				hasWScale = true
			}
		case 4: // SACK Permitted
			if optLen == 2 {
				hasSACK = true
			}
		}
		i += optLen
	}
	if !hasMSS || !hasWScale {
		return nil, false
	}

	// Native Windows 10/11 12-byte TCP SYN option layout:
	//   [0..3]  MSS (kind=2, len=4, mss)
	//   [4]     NOP (kind=1)
	//   [5..7]  Window Scale (kind=3, len=3, wscale)
	//   [8..9]  NOP, NOP (kind=1, kind=1)
	//   [10..11] SACK Permitted (kind=4, len=2) or NOP, NOP
	winOpts := [12]byte{
		0x02, 0x04, byte(mss >> 8), byte(mss),
		0x01,
		0x03, 0x03, wscale,
		0x01, 0x01,
		0x01, 0x01,
	}
	if hasSACK {
		winOpts[10] = 0x04
		winOpts[11] = 0x02
	}

	tcpPayload := tcpHdr[doff:]
	newTCPLen := 20 + len(winOpts) + len(tcpPayload)
	out := make([]byte, l4Offset+newTCPLen)
	copy(out[:l4Offset], pkt[:l4Offset])
	copy(out[l4Offset:l4Offset+20], tcpHdr[:20])
	copy(out[l4Offset+20:l4Offset+32], winOpts[:])
	if len(tcpPayload) > 0 {
		copy(out[l4Offset+32:], tcpPayload)
	}

	// Set new TCP data offset = 8 (32 bytes), preserving reserved bits.
	out[l4Offset+12] = (8 << 4) | (out[l4Offset+12] & 0x0f)
	// Zero TCP checksum before recomputing.
	out[l4Offset+16] = 0
	out[l4Offset+17] = 0

	if !isIPv6 {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10] = 0
		out[11] = 0
		ipSum := internetChecksum(out[:l4Offset])
		binary.BigEndian.PutUint16(out[10:12], ipSum)

		tcpSum := tcpChecksumIPv4(out[12:16], out[16:20], out[l4Offset:])
		binary.BigEndian.PutUint16(out[l4Offset+16:l4Offset+18], tcpSum)
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(newTCPLen))
		tcpSum := tcpChecksumIPv6(out[8:24], out[24:40], out[l4Offset:])
		binary.BigEndian.PutUint16(out[l4Offset+16:l4Offset+18], tcpSum)
	}
	return out, true
}

func checksumAdd(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func checksumFinish(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func internetChecksum(b []byte) uint16 {
	return checksumFinish(checksumAdd(0, b))
}

func tcpChecksumIPv4(src, dst, tcpSeg []byte) uint16 {
	var pseudo [12]byte
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpSeg)))
	sum := checksumAdd(0, pseudo[:])
	sum = checksumAdd(sum, tcpSeg)
	return checksumFinish(sum)
}

func tcpChecksumIPv6(src, dst, tcpSeg []byte) uint16 {
	var pseudo [40]byte
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcpSeg)))
	pseudo[39] = unix.IPPROTO_TCP
	sum := checksumAdd(0, pseudo[:])
	sum = checksumAdd(sum, tcpSeg)
	return checksumFinish(sum)
}
