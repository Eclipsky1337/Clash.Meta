package atrust

import (
	"context"
	"net"
	"net/netip"
)

type tunnel interface {
	DialTCP(ctx context.Context, target Target) (net.Conn, error)
	ListenPacket(ctx context.Context) (net.PacketConn, error)
	ResolveDNS(ctx context.Context, host string, servers []string) ([]netip.Addr, error)
	Close() error
}

func newTunnel(client *Client, options Options, resources *resourceIndex) (tunnel, error) {
	if options.Tunnel == "tcp" {
		return newTCPTunnel(client, options, resources), nil
	}
	return newL3Tunnel(client, options, resources)
}
