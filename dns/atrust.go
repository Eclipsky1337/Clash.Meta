package dns

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	D "github.com/miekg/dns"
)

type atrustDNSClient struct {
	name string
}

type atrustResolverEntry struct {
	id     uint64
	client dnsClient
}

var (
	atrustResolverID atomic.Uint64
	atrustResolverMu sync.RWMutex
	atrustResolvers  = map[string]atrustResolverEntry{}
)

var _ dnsClient = (*atrustDNSClient)(nil)

// RegisterAtrustDnsClient binds an outbound to the atrust://<name> scheme.
func RegisterAtrustDnsClient(name string, client dnsClient) func() {
	id := atrustResolverID.Add(1)
	atrustResolverMu.Lock()
	atrustResolvers[name] = atrustResolverEntry{id: id, client: client}
	atrustResolverMu.Unlock()
	return func() {
		atrustResolverMu.Lock()
		if entry, ok := atrustResolvers[name]; ok && entry.id == id {
			delete(atrustResolvers, name)
		}
		atrustResolverMu.Unlock()
	}
}

func newAtrustClient(name string) *atrustDNSClient {
	return &atrustDNSClient{name: name}
}

func (c *atrustDNSClient) Address() string {
	return "atrust://" + c.name
}

func (c *atrustDNSClient) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	atrustResolverMu.RLock()
	entry, ok := atrustResolvers[c.name]
	atrustResolverMu.RUnlock()
	if !ok || entry.client == nil {
		return nil, fmt.Errorf("proxy %q does not provide aTrust DNS", c.name)
	}
	return entry.client.ExchangeContext(ctx, msg)
}

func (c *atrustDNSClient) ResetConnection() {}
