//go:build with_gvisor

package atrust

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-wireguard"
	D "github.com/miekg/dns"
)

const (
	l3Version          = 0x05
	l3CmdAuth          = 0x13
	l3CmdAuthResp      = 0x93
	l3CmdData          = 0x14
	l3CmdDataResp      = 0x94
	l3CmdHeartbeat     = 0x15
	l3CmdHeartbeatResp = 0x95
	l3CmdSecondVIP     = 0x96

	l3HeartbeatInterval = 5 * time.Second
	l3HeartbeatMisses   = 3
	l3AuthTimeout       = 5 * time.Second
	l3PendingLimit      = 1024
	l3MTU               = 1500
)

type l3Tunnel struct {
	client    *Client
	options   Options
	resources *resourceIndex
	tcp       *tcpTunnel

	mu       sync.Mutex
	stack    *wireguard.StackDevice
	vip      netip.Addr
	conns    map[string]*l3Conn
	closed   bool
	closeCh  chan struct{}
	dnsCache map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	ips     []netip.Addr
	expires time.Time
}

func newL3Tunnel(client *Client, options Options, resources *resourceIndex) (*l3Tunnel, error) {
	tunnel := &l3Tunnel{
		client:    client,
		options:   options,
		resources: resources,
		tcp:       newTCPTunnel(client, options, resources),
		conns:     map[string]*l3Conn{},
		closeCh:   make(chan struct{}),
		dnsCache:  map[string]dnsCacheEntry{},
	}
	if err := tunnel.ensureStack(context.Background()); err != nil {
		return nil, err
	}
	return tunnel, nil
}

func (t *l3Tunnel) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	close(t.closeCh)
	conns := t.conns
	t.conns = map[string]*l3Conn{}
	stack := t.stack
	t.stack = nil
	t.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	if stack != nil {
		_ = stack.Close()
	}
	return nil
}

func (t *l3Tunnel) ensureStack(ctx context.Context) error {
	t.mu.Lock()
	if t.stack != nil {
		t.mu.Unlock()
		return nil
	}
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.mu.Unlock()

	conn, err := t.dialConn(ctx, t.resources.majorGroup)
	if err != nil {
		return err
	}
	if !conn.vip.IsValid() {
		_ = conn.Close()
		return errors.New("aTrust L3 tunnel did not return a virtual IP")
	}
	stack, err := wireguard.NewStackDevice([]netip.Prefix{netip.PrefixFrom(conn.vip, 32)}, l3MTU)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("create aTrust netstack: %w", err)
	}
	if err := stack.Start(); err != nil {
		_ = conn.Close()
		_ = stack.Close()
		return err
	}

	t.mu.Lock()
	if t.stack != nil {
		t.mu.Unlock()
		_ = conn.Close()
		_ = stack.Close()
		return nil
	}
	t.stack = stack
	t.vip = conn.vip
	t.conns[conn.group] = conn
	t.mu.Unlock()

	conn.attach(t, stack)
	go t.stackLoop(stack)
	go conn.readLoop()
	go conn.heartbeatLoop()
	return nil
}

func (t *l3Tunnel) stackLoop(stack *wireguard.StackDevice) {
	buf := make([]byte, 65535)
	for {
		sizes := []int{0}
		count, err := stack.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			select {
			case <-t.closeCh:
				return
			default:
			}
			continue
		}
		if count == 0 || sizes[0] == 0 {
			continue
		}
		packet := append([]byte(nil), buf[:sizes[0]]...)
		meta, err := parsePacketMeta(packet)
		if err != nil {
			continue
		}
		appID, group, ok := t.matchPacket(meta)
		if !ok {
			log.Debugln("[Atrust] L3 packet denied: %s", meta.String())
			continue
		}
		log.Debugln("[Atrust] L3 send meta=%s appID=%s group=%s", meta.String(), appID, group)
		conn, err := t.connForGroup(group)
		if err != nil {
			log.Debugln("[Atrust] L3 packet dropped: %v", err)
			continue
		}
		if err := conn.sendPacket(packet, meta, appID, group); err != nil {
			log.Debugln("[Atrust] L3 packet send failed: %v", err)
		}
	}
}

func (t *l3Tunnel) matchPacket(meta packetMeta) (appID, group string, ok bool) {
	if resource, found := t.resources.matchIP(meta.dstIP, int(meta.dstPort), meta.protocol()); found {
		return resource.AppID, resource.NodeGroupID, true
	}
	// DNS servers are not always present in the resource list; allow the
	// configured server so the atrust:// resolver can work.
	if meta.dstPort == 53 {
		for _, server := range t.resources.dnsServers {
			if ip := net.ParseIP(server); ip != nil && ip.Equal(net.IP(meta.dstIP.AsSlice())) {
				group = t.resources.majorGroup
				for _, resource := range t.resources.ipResources {
					if resource.Protocol == "udp" || resource.Protocol == "all" {
						return resource.AppID, group, true
					}
				}
				return "", group, true
			}
		}
	}
	return "", "", false
}

func (t *l3Tunnel) connForGroup(group string) (*l3Conn, error) {
	t.mu.Lock()
	conn := t.conns[group]
	t.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	newConn, err := t.dialConn(context.Background(), group)
	if err != nil {
		return nil, err
	}
	newConn.attach(t, t.stack)
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = newConn.Close()
		return nil, ErrClosed
	}
	if existing := t.conns[group]; existing != nil {
		t.mu.Unlock()
		_ = newConn.Close()
		return existing, nil
	}
	t.conns[group] = newConn
	t.mu.Unlock()
	go newConn.readLoop()
	go newConn.heartbeatLoop()
	return newConn, nil
}

func (t *l3Tunnel) dialConn(ctx context.Context, group string) (*l3Conn, error) {
	addr, err := t.tcp.nodeAddress(group)
	if err != nil {
		return nil, err
	}
	tlsConn, err := dialTunnelTLS(ctx, t.options, addr)
	if err != nil {
		return nil, fmt.Errorf("connect aTrust L3 node %s: %w", addr, err)
	}
	conn := &l3Conn{
		tunnel:  t,
		group:   group,
		addr:    addr,
		tls:     tlsConn,
		reader:  bufio.NewReader(tlsConn),
		flows:   map[string]*l3Flow{},
		closeCh: make(chan struct{}),
	}
	if err := conn.handshake(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return conn, nil
}

func (t *l3Tunnel) DialTCP(ctx context.Context, target Target) (net.Conn, error) {
	if !target.PreferL3 {
		conn, err := t.tcp.DialTCP(ctx, target)
		if err == nil {
			return conn, nil
		}
		log.Debugln("[Atrust] TCP tunnel failed for %s:%d, falling back to L3: %v", target.Host, target.Port, err)
	}
	if err := t.ensureStack(ctx); err != nil {
		return nil, err
	}
	t.mu.Lock()
	stack := t.stack
	t.mu.Unlock()
	if stack == nil {
		return nil, ErrNotReady
	}
	dst := netip.AddrPortFrom(target.IP, uint16(target.Port))
	conn, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, dst)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (t *l3Tunnel) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := t.ensureStack(ctx); err != nil {
		return nil, err
	}
	t.mu.Lock()
	stack := t.stack
	vip := t.vip
	t.mu.Unlock()
	if stack == nil {
		return nil, ErrNotReady
	}
	return stack.ListenUDP(ctx, "udp", netip.AddrPortFrom(vip, 0))
}

func (t *l3Tunnel) ResolveDNS(ctx context.Context, host string, servers []string) ([]netip.Addr, error) {
	t.mu.Lock()
	if entry, ok := t.dnsCache[host]; ok && time.Now().Before(entry.expires) {
		t.mu.Unlock()
		return append([]netip.Addr(nil), entry.ips...), nil
	}
	t.mu.Unlock()
	if len(servers) == 0 {
		return nil, errors.New("aTrust server did not provide a DNS server")
	}
	var lastErr error
	for _, server := range servers {
		ips, err := t.queryDNS(ctx, host, server)
		if err == nil && len(ips) > 0 {
			t.mu.Lock()
			t.dnsCache[host] = dnsCacheEntry{ips: ips, expires: time.Now().Add(time.Hour)}
			t.mu.Unlock()
			return ips, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("aTrust DNS returned no addresses")
	}
	return nil, lastErr
}

func (t *l3Tunnel) queryDNS(ctx context.Context, host, server string) ([]netip.Addr, error) {
	serverIP := net.ParseIP(server)
	if serverIP == nil {
		return nil, fmt.Errorf("invalid aTrust DNS server %q", server)
	}
	query := new(D.Msg)
	query.SetQuestion(D.Fqdn(host), D.TypeA)
	query.RecursionDesired = true
	payload, err := query.Pack()
	if err != nil {
		return nil, err
	}
	serverAddr, ok := netip.AddrFromSlice(serverIP.To4())
	if !ok {
		return nil, fmt.Errorf("invalid aTrust DNS server %q", server)
	}
	serverAddr = serverAddr.Unmap()
	if ips, err := t.queryDNSUDP(ctx, payload, serverAddr); err == nil && len(ips) > 0 {
		return ips, nil
	}
	return t.queryDNSTCP(ctx, payload, serverAddr)
}

func (t *l3Tunnel) queryDNSUDP(ctx context.Context, payload []byte, server netip.Addr) ([]netip.Addr, error) {
	t.mu.Lock()
	stack := t.stack
	t.mu.Unlock()
	if stack == nil {
		return nil, ErrNotReady
	}
	conn, err := stack.DialUDP(ctx, "udp", netip.AddrPort{}, netip.AddrPortFrom(server, 53))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseDNSAnswer(buf[:n])
}

func (t *l3Tunnel) queryDNSTCP(ctx context.Context, payload []byte, server netip.Addr) ([]netip.Addr, error) {
	t.mu.Lock()
	stack := t.stack
	t.mu.Unlock()
	if stack == nil {
		return nil, ErrNotReady
	}
	conn, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(server, 53))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return parseDNSAnswer(response)
}

func parseDNSAnswer(payload []byte) ([]netip.Addr, error) {
	var msg D.Msg
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for _, answer := range msg.Answer {
		switch record := answer.(type) {
		case *D.A:
			if ip, ok := netip.AddrFromSlice(record.A); ok {
				ips = append(ips, ip.Unmap())
			}
		case *D.AAAA:
			if ip, ok := netip.AddrFromSlice(record.AAAA); ok {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

type l3Conn struct {
	tunnel           *l3Tunnel
	group            string
	addr             string
	tls              *tls.Conn
	reader           *bufio.Reader
	writeMu          sync.Mutex
	mu               sync.Mutex
	flows            map[string]*l3Flow
	nextID           uint64
	stack            *wireguard.StackDevice
	vip              netip.Addr
	closeCh          chan struct{}
	closeOnce        sync.Once
	heartbeatMisses  int32
	heartbeatWritten uint32
}

type l3Flow struct {
	id           uint64
	appID        string
	group        string
	token        string
	pending      [][]byte
	authPending  bool
	authDeadline time.Time
	authMeta     packetMeta
}

func (c *l3Conn) attach(tunnel *l3Tunnel, stack *wireguard.StackDevice) {
	c.tunnel = tunnel
	c.stack = stack
	c.vip = tunnel.vip
}

func (c *l3Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		err = c.tls.Close()
	})
	return err
}

func (c *l3Conn) handshake(ctx context.Context) error {
	state := c.tunnel.client.sessionSnapshot()
	if state.SID == "" {
		return ErrAuthRequired
	}
	payload, _ := json.Marshal(map[string]string{"sid": state.SID})
	header := make([]byte, 4+len(payload))
	header[0] = 0x53
	header[1] = 0x00
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
	copy(header[4:], payload)
	packet := make([]byte, 0, 3+len(header)+10)
	packet = append(packet, l3Version, 0x01, 0xD0)
	packet = append(packet, header...)
	packet = append(packet, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if _, err := c.tls.Write(packet); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.tls.SetReadDeadline(deadline)
		defer c.tls.SetReadDeadline(time.Time{})
	} else {
		_ = c.tls.SetReadDeadline(time.Now().Add(10 * time.Second))
		defer c.tls.SetReadDeadline(time.Time{})
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, method); err != nil {
		return err
	}
	if method[0] != l3Version || method[1] != 0xD0 {
		return fmt.Errorf("unexpected aTrust L3 auth method %x", method)
	}
	authHeader := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, authHeader); err != nil {
		return err
	}
	if authHeader[0] != 0x53 {
		return fmt.Errorf("unexpected aTrust L3 auth version 0x%02x", authHeader[0])
	}
	status := authHeader[1]
	length := int(binary.BigEndian.Uint16(authHeader[2:4]))
	body := make([]byte, length)
	if _, err := io.ReadFull(c.reader, body); err != nil {
		return err
	}
	if length > 0 {
		var response struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return err
		}
		if response.Code == 10000004 || response.Code == 75500002 {
			return ErrSessionInvalid
		}
		if response.Code != 0 {
			return fmt.Errorf("aTrust L3 auth failed with code %d: %s", response.Code, response.Message)
		}
	}
	if status != 0 {
		return fmt.Errorf("aTrust L3 auth status %d", status)
	}
	vipHeader := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, vipHeader); err != nil {
		return err
	}
	vipLen, err := vipDataLength(vipHeader)
	if err != nil {
		return err
	}
	vipData := make([]byte, vipLen)
	if _, err := io.ReadFull(c.reader, vipData); err != nil {
		return err
	}
	ips := parseVIPData(vipData)
	for _, ip := range ips {
		if ip.Is4() {
			c.vip = ip
			break
		}
	}
	return nil
}

func vipDataLength(header []byte) (int, error) {
	if len(header) != 4 || header[0] != l3Version {
		return 0, errors.New("invalid aTrust L3 VIP header")
	}
	if header[1] != 0 {
		return 0, fmt.Errorf("aTrust L3 VIP status %d", header[1])
	}
	switch header[3] {
	case 1:
		return 6, nil
	case 4:
		return 18, nil
	case 5:
		return 22, nil
	default:
		return 0, fmt.Errorf("unsupported aTrust L3 VIP type %d", header[3])
	}
}

func parseVIPData(data []byte) []netip.Addr {
	var ips []netip.Addr
	switch len(data) {
	case 6:
		ips = append(ips, netip.AddrFrom4([4]byte{data[0], data[1], data[2], data[3]}))
	case 18:
		if ip, ok := netip.AddrFromSlice(data[:16]); ok {
			ips = append(ips, ip)
		}
	case 22:
		ips = append(ips, netip.AddrFrom4([4]byte{data[0], data[1], data[2], data[3]}))
		if ip, ok := netip.AddrFromSlice(data[4:20]); ok {
			ips = append(ips, ip)
		}
	}
	return ips
}

func (c *l3Conn) readLoop() {
	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, header); err != nil {
			c.fail()
			return
		}
		if header[0] != l3Version {
			c.fail()
			return
		}
		switch header[1] {
		case l3CmdDataResp:
			payload, err := readLengthPrefixed(c.reader)
			if err != nil {
				c.fail()
				return
			}
			packets := splitIPPackets(payload)
			log.Debugln("[Atrust] L3 data response payload=%d packets=%d", len(payload), len(packets))
			for _, packet := range packets {
				if meta, err := parsePacketMeta(packet); err == nil {
					log.Debugln("[Atrust] L3 inbound meta=%s len=%d", meta.String(), len(packet))
				}
				if _, err := c.stack.Write([][]byte{packet}, 0); err != nil {
					log.Debugln("[Atrust] L3 inbound write failed: %v", err)
				}
			}
		case l3CmdAuthResp, l3CmdSecondVIP:
			statusLen := make([]byte, 3)
			if _, err := io.ReadFull(c.reader, statusLen); err != nil {
				c.fail()
				return
			}
			status := statusLen[0]
			payload := make([]byte, binary.BigEndian.Uint16(statusLen[1:]))
			if _, err := io.ReadFull(c.reader, payload); err != nil {
				c.fail()
				return
			}
			if header[1] == l3CmdAuthResp {
				c.handleAuthResponse(status, payload)
			}
		case l3CmdHeartbeatResp:
			if _, err := readLengthPrefixed(c.reader); err != nil {
				c.fail()
				return
			}
			atomic.StoreInt32(&c.heartbeatMisses, 0)
			atomic.StoreUint32(&c.heartbeatWritten, 0)
		default:
			c.fail()
			return
		}
	}
}

func (c *l3Conn) fail() {
	_ = c.Close()
	c.tunnel.removeConn(c.group, c)
}

func (c *l3Conn) heartbeatLoop() {
	ticker := time.NewTicker(l3HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if atomic.SwapUint32(&c.heartbeatWritten, 0) != 0 {
				continue
			}
			if atomic.LoadInt32(&c.heartbeatMisses) >= l3HeartbeatMisses {
				c.fail()
				return
			}
			atomic.AddInt32(&c.heartbeatMisses, 1)
			if err := c.writeFrame([]byte{l3Version, l3CmdHeartbeat, 0x00, 0x00}); err != nil {
				c.fail()
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *l3Conn) writeFrame(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.tls.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	atomic.StoreUint32(&c.heartbeatWritten, 1)
	return nil
}

func (c *l3Conn) sendPacket(packet []byte, meta packetMeta, appID, group string) error {
	key := meta.key()
	c.mu.Lock()
	flow := c.flows[key]
	if flow == nil {
		c.nextID++
		flow = &l3Flow{id: c.nextID, appID: appID, group: group}
		c.flows[key] = flow
	}
	flow.authMeta = meta
	token := flow.token
	if token != "" {
		c.mu.Unlock()
		return c.writeData(token, packet)
	}
	if len(flow.pending) < l3PendingLimit {
		flow.pending = append(flow.pending, packet)
	}
	sendAuth := !flow.authPending
	if sendAuth {
		flow.authPending = true
		flow.authDeadline = time.Now().Add(l3AuthTimeout)
	}
	c.mu.Unlock()
	if sendAuth {
		return c.sendAuth(flow, meta)
	}
	return nil
}

func (c *l3Conn) sendAuth(flow *l3Flow, meta packetMeta) error {
	log.Debugln("[Atrust] L3 auth request flow=%d meta=%s appID=%s", flow.id, meta.String(), flow.appID)
	state := c.tunnel.client.sessionSnapshot()
	if state.SID == "" {
		return ErrAuthRequired
	}
	signKey, err := hex.DecodeString(state.SignKey)
	if err != nil {
		return err
	}
	procPath := "/usr/bin/atrust"
	fingerprint := strings.ToUpper(fmt.Sprintf("%X", sha256.Sum256([]byte(procPath))))
	url := fmt.Sprintf("%s:%s:%d", meta.protocol(), meta.dstIP, meta.dstPort)
	request := l3AuthRequest{
		SID:           state.SID,
		AppID:         flow.appID,
		URL:           url,
		DeviceID:      state.DeviceID,
		ConnectionID:  state.ConnectionID,
		RCAppliedInfo: 0,
		Lang:          "en-US",
		ConntrackHash: flow.id,
		IP: l3AuthIP{
			Atype:    meta.aType(),
			Protocol: meta.proto,
			DestAddr: meta.dstIP.String(),
			DestPort: meta.dstPort,
			SrcAddr:  meta.srcIP.String(),
			SrcPort:  meta.srcPort,
		},
		XRequestSig: "",
	}
	request.ProcHash = fingerprint
	request.Env.Application.Runtime.Process = l3Process{
		Name:             "atrust",
		DigitalSignature: "TrustAppClosed",
		Platform:         "Linux",
		Fingerprint:      fingerprint,
		Description:      "TrustAppClosed",
		Path:             procPath,
		Version:          "TrustAppClosed",
		SecurityEnv:      "normal",
	}
	request.Env.Application.Runtime.ProcessTrusted = "TRUSTED"
	unsigned, err := json.Marshal(request)
	if err != nil {
		return err
	}
	request.XRequestSig = hmacSignature(signKey, unsigned)
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(body) > 0xFFFF {
		return errors.New("aTrust L3 auth request is too large")
	}
	frame := make([]byte, 0, 4+len(body))
	frame = append(frame, l3Version, l3CmdAuth)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(body)))
	frame = append(frame, body...)
	return c.writeFrame(frame)
}

type l3AuthRequest struct {
	SID           string     `json:"sid"`
	AppID         string     `json:"appId"`
	ProcHash      string     `json:"procHash,omitempty"`
	URL           string     `json:"url"`
	DeviceID      string     `json:"deviceId"`
	ConnectionID  string     `json:"connectionId"`
	RCAppliedInfo int        `json:"rcAppliedInfo"`
	Lang          string     `json:"lang"`
	Env           l3TrustEnv `json:"env"`
	ConntrackHash uint64     `json:"conntrackHash"`
	IP            l3AuthIP   `json:"ip"`
	XRequestSig   string     `json:"xRequestSig"`
}

type l3AuthIP struct {
	Atype    int    `json:"atype"`
	Protocol int    `json:"protocol"`
	DestAddr string `json:"destAddr"`
	DestPort uint16 `json:"destPort"`
	SrcAddr  string `json:"srcAddr"`
	SrcPort  uint16 `json:"srcPort"`
}

type l3TrustEnv struct {
	Application struct {
		Runtime struct {
			Process        l3Process `json:"process"`
			ProcessTrusted string    `json:"process_trusted"`
		} `json:"runtime"`
	} `json:"application"`
}

type l3Process struct {
	Name             string `json:"name"`
	DigitalSignature string `json:"digital_signature"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	Description      string `json:"description"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	SecurityEnv      string `json:"security_env"`
}

func (c *l3Conn) handleAuthResponse(status byte, payload []byte) {
	var response struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
		Data    struct {
			ConntrackHash uint64   `json:"conntrackHash"`
			ConnectToken  string   `json:"connectToken"`
			IP            l3AuthIP `json:"ip"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return
	}
	id := response.Data.ConntrackHash
	log.Debugln("[Atrust] L3 auth response status=0x%02x code=%d conntrack=%d tokenLen=%d msg=%s", status, response.Code, id, len(response.Data.ConnectToken), response.Message)
	c.mu.Lock()
	var flow *l3Flow
	for _, candidate := range c.flows {
		if candidate.id == id {
			flow = candidate
			break
		}
	}
	if flow == nil {
		c.mu.Unlock()
		return
	}
	if status != 0 {
		if status == 0x84 {
			flow.authPending = false
			meta := flow.authMeta
			c.mu.Unlock()
			_ = c.sendAuth(flow, meta)
			return
		}
		if status >= 0x85 && status <= 0x87 {
			flow.authPending = false
			meta := flow.authMeta
			c.mu.Unlock()
			time.AfterFunc(10*time.Second, func() {
				_ = c.sendAuth(flow, meta)
			})
			return
		}
		flow.pending = nil
		flow.authPending = false
		c.mu.Unlock()
		return
	}
	token := response.Data.ConnectToken
	flow.token = token
	flow.authPending = false
	pending := flow.pending
	flow.pending = nil
	c.mu.Unlock()
	for _, packet := range pending {
		_ = c.writeData(token, packet)
	}
}

func (c *l3Conn) writeData(token string, packet []byte) error {
	if len(token) > 0xFF {
		return errors.New("aTrust L3 connect token is too long")
	}
	frame := make([]byte, 0, 8+len(token)+len(packet))
	frame = append(frame, l3Version, l3CmdData, byte(len(token)))
	frame = append(frame, token...)
	frame = append(frame, 0x00, 0x00, 0x01, 0x00, 0x00)
	binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(len(packet)))
	frame = append(frame, packet...)
	return c.writeFrame(frame)
}

func (t *l3Tunnel) removeConn(group string, conn *l3Conn) {
	t.mu.Lock()
	if t.conns[group] == conn {
		delete(t.conns, group)
	}
	t.mu.Unlock()
}

type packetMeta struct {
	atype   int
	proto   int
	srcIP   netip.Addr
	dstIP   netip.Addr
	srcPort uint16
	dstPort uint16
}

func (m packetMeta) protocol() string {
	switch m.proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	default:
		return "ip"
	}
}

func (m packetMeta) aType() int {
	if m.atype == 6 {
		return 0x86DD
	}
	return 0x0800
}

func (m packetMeta) key() string {
	return fmt.Sprintf("%d:%d:%s:%d-%s:%d", m.atype, m.proto, m.srcIP, m.srcPort, m.dstIP, m.dstPort)
}

func (m packetMeta) String() string {
	return fmt.Sprintf("%s %s:%d -> %s:%d", m.protocol(), m.srcIP, m.srcPort, m.dstIP, m.dstPort)
}

func parsePacketMeta(packet []byte) (packetMeta, error) {
	if len(packet) == 0 {
		return packetMeta{}, errors.New("empty packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return packetMeta{}, errors.New("short IPv4 packet")
		}
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen < 20 || len(packet) < headerLen {
			return packetMeta{}, errors.New("invalid IPv4 header")
		}
		src, ok1 := netip.AddrFromSlice(packet[12:16])
		dst, ok2 := netip.AddrFromSlice(packet[16:20])
		if !ok1 || !ok2 {
			return packetMeta{}, errors.New("invalid IPv4 address")
		}
		meta := packetMeta{atype: 4, proto: int(packet[9]), srcIP: src, dstIP: dst}
		payload := packet[headerLen:]
		return withPorts(meta, payload)
	case 6:
		if len(packet) < 40 {
			return packetMeta{}, errors.New("short IPv6 packet")
		}
		src, ok1 := netip.AddrFromSlice(packet[8:24])
		dst, ok2 := netip.AddrFromSlice(packet[24:40])
		if !ok1 || !ok2 {
			return packetMeta{}, errors.New("invalid IPv6 address")
		}
		meta := packetMeta{atype: 6, proto: int(packet[6]), srcIP: src, dstIP: dst}
		return withPorts(meta, packet[40:])
	default:
		return packetMeta{}, errors.New("unsupported IP version")
	}
}

func withPorts(meta packetMeta, payload []byte) (packetMeta, error) {
	switch meta.proto {
	case 6:
		if len(payload) < 20 {
			return packetMeta{}, errors.New("short TCP header")
		}
		meta.srcPort = binary.BigEndian.Uint16(payload[0:2])
		meta.dstPort = binary.BigEndian.Uint16(payload[2:4])
	case 17:
		if len(payload) < 8 {
			return packetMeta{}, errors.New("short UDP header")
		}
		meta.srcPort = binary.BigEndian.Uint16(payload[0:2])
		meta.dstPort = binary.BigEndian.Uint16(payload[2:4])
	}
	return meta, nil
}

func splitIPPackets(stream []byte) [][]byte {
	var packets [][]byte
	for len(stream) > 0 {
		var size int
		switch stream[0] >> 4 {
		case 4:
			if len(stream) < 4 {
				return packets
			}
			headerLen := int(stream[0]&0x0f) * 4
			size = int(binary.BigEndian.Uint16(stream[2:4]))
			if headerLen < 20 || size < headerLen {
				return packets
			}
		case 6:
			if len(stream) < 6 {
				return packets
			}
			size = 40 + int(binary.BigEndian.Uint16(stream[4:6]))
		default:
			return packets
		}
		if len(stream) < size {
			return packets
		}
		packets = append(packets, append([]byte(nil), stream[:size]...))
		stream = stream[size:]
	}
	return packets
}
