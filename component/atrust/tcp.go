package atrust

import (
	"bufio"
	"context"
	"crypto/hmac"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

type tcpTunnel struct {
	client    *Client
	options   Options
	resources *resourceIndex
	zeroRTT   bool
}

func newTCPTunnel(client *Client, options Options, resources *resourceIndex) *tcpTunnel {
	return &tcpTunnel{client: client, options: options, resources: resources, zeroRTT: client.zeroRTT()}
}

func (t *tcpTunnel) ListenPacket(context.Context) (net.PacketConn, error) {
	return nil, errors.New("aTrust TCP tunnel does not support UDP")
}

func (t *tcpTunnel) ResolveDNS(context.Context, string, []string) ([]netip.Addr, error) {
	return nil, errors.New("aTrust TCP tunnel does not provide DNS")
}

func (t *tcpTunnel) Close() error { return nil }

func (t *tcpTunnel) DialTCP(ctx context.Context, target Target) (net.Conn, error) {
	addr, err := t.nodeAddress(target.NodeGroupID)
	if err != nil {
		return nil, err
	}
	conn, err := dialTunnelTLS(ctx, t.options, addr)
	if err != nil {
		return nil, fmt.Errorf("connect aTrust node %s: %w", addr, err)
	}
	reader, err := t.handshake(ctx, conn, target)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &tcpTunnelConn{Conn: conn, reader: reader, raw: !t.zeroRTT}, nil
}

func (t *tcpTunnel) nodeAddress(group string) (string, error) {
	if group == "" {
		group = t.resources.majorGroup
	}
	nodes := t.resources.nodeGroups[group]
	for _, candidate := range append(append([]string(nil), nodes.WAN...), nodes.LAN...) {
		if candidate != "" {
			return candidate, nil
		}
	}
	if group != t.resources.majorGroup {
		return t.nodeAddress(t.resources.majorGroup)
	}
	return "", fmt.Errorf("no aTrust node available for group %q", group)
}

func dialTunnelTLS(ctx context.Context, options Options, address string) (*tls.Conn, error) {
	dial := options.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		dial = dialer.DialContext
	}
	raw, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify:     options.SkipCertVerify,
		ServerName:             host,
		SessionTicketsDisabled: true,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

type tcpAuthRequest struct {
	SID           string       `json:"sid"`
	AppID         string       `json:"appId"`
	URL           string       `json:"url"`
	DeviceID      string       `json:"deviceId"`
	ConnectionID  string       `json:"connectionId"`
	ProcHash      string       `json:"procHash"`
	UserName      string       `json:"userName"`
	RCAppliedInfo int          `json:"rcAppliedInfo"`
	Lang          string       `json:"lang"`
	DestAddr      string       `json:"destAddr"`
	DestIP        string       `json:"destIP,omitempty"`
	Env           tcpTunnelEnv `json:"env"`
	XRequestSig   string       `json:"xRequestSig"`
}

type tcpTunnelEnv struct {
	Application struct {
		Runtime struct {
			Process        tcpProcess `json:"process"`
			ProcessTrusted string     `json:"process_trusted"`
		} `json:"runtime"`
	} `json:"application"`
}

type tcpProcess struct {
	Name             string `json:"name"`
	DigitalSignature string `json:"digital_signature"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	Description      string `json:"description"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	SecurityEnv      string `json:"security_env"`
}

func (t *tcpTunnel) handshake(ctx context.Context, conn *tls.Conn, target Target) (*bufio.Reader, error) {
	state := t.client.sessionSnapshot()
	if state.SID == "" {
		return nil, ErrAuthRequired
	}
	signKey, err := hex.DecodeString(state.SignKey)
	if err != nil {
		return nil, fmt.Errorf("invalid aTrust sign key: %w", err)
	}
	realHost := target.IP.String()
	destAddr := net.JoinHostPort(realHost, strconv.Itoa(target.Port))
	destIP := ""
	if target.Host != "" {
		destAddr = net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
		if !target.AddrPretend {
			destIP = realHost
		}
	}
	procName := "google-chrome-stable"
	procPath := "/usr/bin/google-chrome-stable"
	if target.Port == 22 {
		procName = "ssh"
		procPath = "/usr/bin/ssh"
	}
	fingerprint := strings.ToUpper(fmt.Sprintf("%X", sha256.Sum256([]byte(procPath))))
	request := tcpAuthRequest{
		SID:          state.SID,
		AppID:        target.AppID,
		URL:          "tcp://" + destAddr,
		DeviceID:     state.DeviceID,
		ConnectionID: state.ConnectionID,
		ProcHash:     fingerprint,
		UserName:     state.Username,
		Lang:         "en-US",
		DestAddr:     destAddr,
		DestIP:       destIP,
	}
	request.Env.Application.Runtime.Process = tcpProcess{
		Name:             procName,
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
		return nil, err
	}
	request.XRequestSig = hmacSignature(signKey, unsigned)
	signed, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(signed) > 0xFFFF {
		return nil, errors.New("aTrust TCP tunnel auth request is too large")
	}
	initMessage := make([]byte, 0, 7+len(signed))
	initMessage = append(initMessage, 0x05, 0x01, 0x81, 0x53, 0x03)
	initMessage = binary.BigEndian.AppendUint16(initMessage, uint16(len(signed)))
	initMessage = append(initMessage, signed...)
	destMessage, err := encodeTCPDestination(realHost, target.Port, t.zeroRTT)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(initMessage, destMessage...)); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
		defer conn.SetReadDeadline(time.Time{})
	}
	reader := bufio.NewReader(conn)
	hello := make([]byte, 2)
	if _, err := io.ReadFull(reader, hello); err != nil {
		return nil, err
	}
	if hello[0] != 0x05 || hello[1] != 0x81 {
		return nil, fmt.Errorf("unexpected aTrust TCP tunnel hello %x", hello)
	}
	authHeader := make([]byte, 2)
	if _, err := io.ReadFull(reader, authHeader); err != nil {
		return nil, err
	}
	if authHeader[0] != 0x53 || authHeader[1] != 0x00 {
		return nil, fmt.Errorf("unexpected aTrust TCP tunnel auth header %x", authHeader)
	}
	response, err := readLengthPrefixed(reader)
	if err != nil {
		return nil, err
	}
	var authResponse struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response, &authResponse); err != nil {
		return nil, fmt.Errorf("parse aTrust TCP tunnel auth: %w", err)
	}
	if authResponse.Code != 0 {
		if authResponse.Code == 10000004 || authResponse.Code == 75500002 {
			return nil, ErrSessionInvalid
		}
		return nil, fmt.Errorf("aTrust TCP tunnel auth failed with code %d: %s", authResponse.Code, authResponse.Message)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		return nil, err
	}
	if reply[0] != 0x05 {
		return nil, fmt.Errorf("unexpected aTrust TCP tunnel reply version 0x%02x", reply[0])
	}
	if reply[1] != 0x00 {
		return nil, fmt.Errorf("aTrust TCP tunnel refused the connection with status 0x%02x", reply[1])
	}
	addressLen := 0
	switch reply[3] {
	case 0x01:
		addressLen = net.IPv4len
	case 0x04:
		addressLen = net.IPv6len
	default:
		return nil, fmt.Errorf("unexpected aTrust TCP tunnel bind address type 0x%02x", reply[3])
	}
	if _, err := io.CopyN(io.Discard, reader, int64(addressLen+2)); err != nil {
		return nil, err
	}
	return reader, nil
}

func encodeTCPDestination(host string, port int, zeroRTT bool) ([]byte, error) {
	rsv := byte(0)
	if zeroRTT {
		rsv = 1
	}
	message := []byte{0x05, 0x01, rsv}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			message = append(message, 0x01)
			message = append(message, ip4...)
		} else {
			message = append(message, 0x04)
			message = append(message, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("destination host is too long")
		}
		message = append(message, 0x03, byte(len(host)))
		message = append(message, host...)
	}
	return binary.BigEndian.AppendUint16(message, uint16(port)), nil
}

func readLengthPrefixed(reader *bufio.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return nil, err
	}
	data := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	return data, nil
}

func hmacSignature(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

type tcpTunnelConn struct {
	net.Conn
	reader *bufio.Reader
	raw    bool
	mu     sync.Mutex
}

func (c *tcpTunnelConn) Read(b []byte) (int, error) {
	if c.raw {
		return c.reader.Read(b)
	}
	for {
		header := make([]byte, 4)
		if _, err := io.ReadFull(c.reader, header); err != nil {
			return 0, err
		}
		if header[0] != 0x01 {
			return 0, fmt.Errorf("unexpected aTrust TCP tunnel frame header %x", header)
		}
		switch header[1] {
		case 0x00:
			length := int(binary.BigEndian.Uint16(header[2:]))
			if length == 0 {
				continue
			}
			if length > len(b) {
				data := make([]byte, length)
				if _, err := io.ReadFull(c.reader, data); err != nil {
					return 0, err
				}
				n := copy(b, data)
				return n, nil
			}
			return io.ReadFull(c.reader, b[:length])
		case 0x01:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unexpected aTrust TCP tunnel frame type 0x%02x", header[1])
		}
	}
}

func (c *tcpTunnelConn) Write(b []byte) (int, error) {
	if c.raw {
		return c.Conn.Write(b)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for written < len(b) {
		size := len(b) - written
		if size > 0xFFFF {
			size = 0xFFFF
		}
		frame := make([]byte, 4+size)
		frame[0] = 0x01
		frame[1] = 0x00
		binary.BigEndian.PutUint16(frame[2:4], uint16(size))
		copy(frame[4:], b[written:written+size])
		if _, err := c.Conn.Write(frame); err != nil {
			return written, err
		}
		written += size
	}
	return written, nil
}
