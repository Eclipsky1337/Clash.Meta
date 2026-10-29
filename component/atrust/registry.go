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
// without the outbound importing rules/provider (which would cycle).
var (
	snapshotMu        sync.RWMutex
	snapshotListeners = map[string]map[uint64]func(Snapshot){}
	snapshotLatest    = map[string]Snapshot{}
	snapshotNextID    uint64
)

func SubscribeSnapshot(name string, listener func(Snapshot)) func() {
	snapshotMu.Lock()
	snapshotNextID++
	id := snapshotNextID
	if snapshotListeners[name] == nil {
		snapshotListeners[name] = map[uint64]func(Snapshot){}
	}
	snapshotListeners[name][id] = listener
	latest, hasLatest := snapshotLatest[name]
	snapshotMu.Unlock()
	if hasLatest {
		listener(latest)
	}
	return func() {
		snapshotMu.Lock()
		if listeners := snapshotListeners[name]; listeners != nil {
			delete(listeners, id)
			if len(listeners) == 0 {
				delete(snapshotListeners, name)
			}
		}
		snapshotMu.Unlock()
	}
}

func PublishSnapshot(name string, snapshot Snapshot) {
	snapshotMu.Lock()
	snapshotLatest[name] = snapshot
	listeners := make([]func(Snapshot), 0, len(snapshotListeners[name]))
	for _, listener := range snapshotListeners[name] {
		listeners = append(listeners, listener)
	}
	snapshotMu.Unlock()
	for _, listener := range listeners {
		listener(snapshot)
	}
}
