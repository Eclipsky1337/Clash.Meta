package atrust

import (
	"context"
	"sync"
	"time"
)

// Provider is the surface the loopback auth API needs from one outbound.
type Provider interface {
	Name() string
	Status() Status
	NewLoginSession(ttl time.Duration, maxAttempts int) *LoginSession
	Session(id string) *LoginSession
	Logout(ctx context.Context) error
}

var (
	providerMu sync.RWMutex
	providers  = map[string]Provider{}
)

func RegisterProvider(provider Provider) func() {
	providerMu.Lock()
	providers[provider.Name()] = provider
	providerMu.Unlock()
	return func() {
		providerMu.Lock()
		delete(providers, provider.Name())
		providerMu.Unlock()
	}
}

func Providers() []Provider {
	providerMu.RLock()
	defer providerMu.RUnlock()
	out := make([]Provider, 0, len(providers))
	for _, provider := range providers {
		out = append(out, provider)
	}
	return out
}

func ProviderByName(name string) (Provider, bool) {
	providerMu.RLock()
	defer providerMu.RUnlock()
	provider, ok := providers[name]
	return provider, ok
}

// Snapshot listeners let the internal rule providers track resource changes
// without the outbound importing rules/provider (which would cycle). One
// listener per proxy name is enough: a config reload replaces the providers.
var (
	snapshotMu        sync.RWMutex
	snapshotListeners = map[string]func(Snapshot){}
	snapshotLatest    = map[string]Snapshot{}
)

func SetSnapshotListener(name string, listener func(Snapshot)) {
	snapshotMu.Lock()
	snapshotListeners[name] = listener
	latest, hasLatest := snapshotLatest[name]
	snapshotMu.Unlock()
	if hasLatest {
		listener(latest)
	}
}

func PublishSnapshot(name string, snapshot Snapshot) {
	snapshotMu.Lock()
	snapshotLatest[name] = snapshot
	listener := snapshotListeners[name]
	snapshotMu.Unlock()
	if listener != nil {
		listener(snapshot)
	}
}
