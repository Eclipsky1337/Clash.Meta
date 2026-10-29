//go:build !no_atrust

package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/metacubex/mihomo/component/atrust"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
)

// Atrust is a mihomo outbound backed by a Sangfor aTrust session.
type Atrust struct {
	*Base
	option AtrustOption
	client *atrust.Client

	unregisterDNS      func()
	unregisterProvider func()
}

type AtrustOption struct {
	BasicOption
	Name            string `proxy:"name"`
	Server          string `proxy:"server"`
	Port            int    `proxy:"port,omitempty"`
	LoginDomain     string `proxy:"login-domain,omitempty"`
	AuthType        string `proxy:"auth-type,omitempty"`
	Username        string `proxy:"username,omitempty"`
	Password        string `proxy:"password,omitempty"`
	TOTPSecret      string `proxy:"totp-secret,omitempty"`
	Tunnel          string `proxy:"tunnel,omitempty"`
	StateDir        string `proxy:"state-dir,omitempty"`
	RefreshInterval int    `proxy:"refresh-interval,omitempty"`
	SkipCertVerify  *bool  `proxy:"skip-cert-verify,omitempty"`
	UDP             *bool  `proxy:"udp,omitempty"`
}

func NewAtrust(option AtrustOption) (*Atrust, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("aTrust proxy %q requires server", option.Name)
	}
	if option.Port == 0 {
		option.Port = 443
	}
	if option.Tunnel == "" {
		option.Tunnel = "l3"
	}
	if option.StateDir == "" {
		option.StateDir = filepath.Join("atrust", option.Name)
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}
	udp := true
	if option.UDP != nil {
		udp = *option.UDP
	}
	if option.Tunnel == "tcp" {
		udp = false
	}
	skipCertVerify := true
	if option.SkipCertVerify != nil {
		skipCertVerify = *option.SkipCertVerify
	}
	outbound := &Atrust{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, fmt.Sprint(option.Port)),
			Type:         C.Atrust,
			ProviderName: option.ProviderName,
			UDP:          udp,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option,
	}
	dialOptions := append(outbound.DialOptions(), dialer.WithResolver(resolver.ProxyServerHostResolver))
	outbound.dialer = option.NewDialer(dialOptions)

	client, err := atrust.NewClient(atrust.Options{
		Name:            option.Name,
		Server:          option.Server,
		Port:            option.Port,
		LoginDomain:     option.LoginDomain,
		AuthType:        option.AuthType,
		Username:        option.Username,
		Password:        option.Password,
		TOTPSecret:      option.TOTPSecret,
		Tunnel:          option.Tunnel,
		StateDir:        option.StateDir,
		RefreshInterval: time.Duration(option.RefreshInterval) * time.Second,
		SkipCertVerify:  skipCertVerify,
		DialContext:     outbound.dialer.DialContext,
		ResolveHost: func(ctx context.Context, host string) (netip.Addr, error) {
			return resolver.ResolveIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
		},
	})
	if err != nil {
		return nil, err
	}
	client.SetSnapshotHandler(func(snapshot atrust.Snapshot) {
		atrust.PublishSnapshot(option.Name, snapshot)
	})
	outbound.client = client
	outbound.unregisterDNS = dns.RegisterAtrustDnsClient(option.Name, client)
	outbound.unregisterProvider = atrust.RegisterProvider(client)
	return outbound, nil
}

func (a *Atrust) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := a.client.DialContext(ctx, metadata.Host, metadata.DstIP, int(metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, a), nil
}

func (a *Atrust) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	packetConn, err := a.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(packetConn, a), nil
}

// IsL3Protocol stays false so mihomo keeps metadata.Host; aTrust matches
// domain resources before the tunnel resolves anything.
func (a *Atrust) IsL3Protocol(*C.Metadata) bool {
	return false
}

func (a *Atrust) MarshalJSON() ([]byte, error) {
	status := a.client.Status()
	return json.Marshal(map[string]any{
		"type": a.Type().String(),
		"id":   a.Id(),
		"auth": map[string]any{
			"state":   status.State,
			"account": status.Account,
			"error":   status.Error,
		},
	})
}

func (a *Atrust) Close() error {
	if a.unregisterDNS != nil {
		a.unregisterDNS()
	}
	if a.unregisterProvider != nil {
		a.unregisterProvider()
	}
	return a.client.Close()
}
