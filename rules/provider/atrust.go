package provider

import (
	"encoding/json"
	"sync"

	"github.com/metacubex/mihomo/component/atrust"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// AtrustRuleProvider is an in-memory rule provider whose payload is rebuilt
// from the logged-in aTrust resource table.
type AtrustRuleProvider struct {
	name     string
	behavior P.RuleBehavior
	mu       sync.RWMutex
	strategy ruleStrategy
}

func (p *AtrustRuleProvider) Name() string { return p.name }

func (p *AtrustRuleProvider) VehicleType() P.VehicleType { return P.Inline }

func (p *AtrustRuleProvider) Type() P.ProviderType { return P.Rule }

func (p *AtrustRuleProvider) Initial() error { return nil }

func (p *AtrustRuleProvider) Update() error { return nil }

func (p *AtrustRuleProvider) Behavior() P.RuleBehavior { return p.behavior }

func (p *AtrustRuleProvider) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.strategy == nil {
		return 0
	}
	return p.strategy.Count()
}

func (p *AtrustRuleProvider) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	p.mu.RLock()
	strategy := p.strategy
	p.mu.RUnlock()
	return strategy != nil && strategy.Match(metadata, helper)
}

func (p *AtrustRuleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"behavior":    p.behavior.String(),
		"format":      "TextRule",
		"name":        p.name,
		"ruleCount":   p.Count(),
		"type":        p.Type().String(),
		"vehicleType": p.VehicleType().String(),
	})
}

func (p *AtrustRuleProvider) Strategy() any {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.strategy
}

func (p *AtrustRuleProvider) SetPayload(payload []string) {
	strategy := newStrategy(p.behavior, nil)
	strategy.Reset()
	for _, item := range payload {
		strategy.Insert(item)
	}
	strategy.FinishInsert()
	p.mu.Lock()
	p.strategy = strategy
	p.mu.Unlock()
	if tunnel != nil {
		tunnel.RuleUpdateCallback().Emit(p)
	}
}

// AtrustRuleProviders bundles the two internal providers.
type AtrustRuleProviders struct {
	Domain *AtrustRuleProvider
	IP     *AtrustRuleProvider
}

func NewAtrustRuleProviders(name string) (*AtrustRuleProviders, func()) {
	domainStrategy := newStrategy(P.Domain, nil)
	domainStrategy.Reset()
	ipStrategy := newStrategy(P.IPCIDR, nil)
	ipStrategy.Reset()
	domain := &AtrustRuleProvider{name: "atrust-domain", behavior: P.Domain, strategy: domainStrategy}
	ip := &AtrustRuleProvider{name: "atrust-ip", behavior: P.IPCIDR, strategy: ipStrategy}
	providers := &AtrustRuleProviders{Domain: domain, IP: ip}
	unsubscribe := atrust.SubscribeSnapshot(name, func(snapshot atrust.Snapshot) {
		domain.SetPayload(snapshot.Domains)
		ip.SetPayload(snapshot.CIDRs)
	})
	return providers, unsubscribe
}
