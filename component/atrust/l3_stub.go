//go:build !with_gvisor

package atrust

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// Without the gVisor build tag only the TCP tunnel is available.
type l3Tunnel struct {
	tcp *tcpTunnel
}

func newL3Tunnel(client *Client, options Options, resources *resourceIndex) (tunnel, error) {
	return newTCPTunnel(client, options, resources), nil
}

func (t *l3Tunnel) Close() error { return nil }

func (t *l3Tunnel) DialTCP(ctx context.Context, target Target) (net.Conn, error) {
	return t.tcp.DialTCP(ctx, target)
}

func (t *l3Tunnel) ListenPacket(context.Context) (net.PacketConn, error) {
	return nil, errors.New("aTrust L3 tunnel requires the with_gvisor build tag")
}

func (t *l3Tunnel) ResolveDNS(context.Context, string, []string) ([]netip.Addr, error) {
	return nil, errors.New("aTrust DNS requires the with_gvisor build tag")
}
