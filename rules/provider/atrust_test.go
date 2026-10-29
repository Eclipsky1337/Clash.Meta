package provider

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/atrust"
	C "github.com/metacubex/mihomo/constant"
)

func TestAtrustRuleProvidersReplayLatestSnapshot(t *testing.T) {
	atrust.PublishSnapshot("late-atrust", atrust.Snapshot{Domains: []string{"+.late.example"}, CIDRs: []string{"10.9.0.0/16"}})
	providers, unsubscribe := NewAtrustRuleProviders("late-atrust")
	defer unsubscribe()
	if providers.Domain.Count() != 1 || providers.IP.Count() != 1 {
		t.Fatalf("late subscription counts: domain=%d ip=%d", providers.Domain.Count(), providers.IP.Count())
	}
}

func TestAtrustRuleProviders(t *testing.T) {
	providers, unsubscribe := NewAtrustRuleProviders("test-atrust")
	defer unsubscribe()
	if providers.Domain.Count() != 0 || providers.IP.Count() != 0 {
		t.Fatal("new providers should start empty")
	}
	atrust.PublishSnapshot("test-atrust", atrust.Snapshot{
		Domains: []string{"+.example.com", "lib.example.org"},
		CIDRs:   []string{"10.0.0.0/8", "192.168.1.1/32"},
	})
	if providers.Domain.Count() != 2 || providers.IP.Count() != 2 {
		t.Fatalf("counts: domain=%d ip=%d", providers.Domain.Count(), providers.IP.Count())
	}
	if !providers.Domain.Match(&C.Metadata{Host: "a.example.com"}, C.RuleMatchHelper{}) {
		t.Fatal("suffix domain should match")
	}
	if !providers.Domain.Match(&C.Metadata{Host: "lib.example.org"}, C.RuleMatchHelper{}) {
		t.Fatal("exact domain should match")
	}
	if providers.Domain.Match(&C.Metadata{Host: "example.net"}, C.RuleMatchHelper{}) {
		t.Fatal("unrelated domain should not match")
	}
	if !providers.IP.Match(&C.Metadata{DstIP: netip.MustParseAddr("10.1.2.3")}, C.RuleMatchHelper{}) {
		t.Fatal("CIDR should match")
	}
	if !providers.IP.Match(&C.Metadata{DstIP: netip.MustParseAddr("192.168.1.1")}, C.RuleMatchHelper{}) {
		t.Fatal("host CIDR should match")
	}
	if providers.IP.Match(&C.Metadata{DstIP: netip.MustParseAddr("192.168.1.2")}, C.RuleMatchHelper{}) {
		t.Fatal("unrelated IP should not match")
	}
}
