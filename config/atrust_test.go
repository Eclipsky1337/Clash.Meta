package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor"
)

const atrustBaseConfig = `
mixed-port: 7890
mode: rule
proxies:
  - name: atrust
    type: atrust
    server: vpn.example.com
    port: 443
    login-domain: Radius
    username: user
    state-dir: atrust
rules:
  - RULE-SET,atrust-domain,atrust
  - RULE-SET,atrust-ip,atrust,no-resolve
  - MATCH,DIRECT
dns:
  enable: true
  nameserver:
    - 223.5.5.5
  nameserver-policy:
    "rule-set:atrust-domain": "atrust://atrust"
`

func TestParseAtrustConfig(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	cfg, err := config.Parse([]byte(atrustBaseConfig))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.RuleProviders["atrust-domain"]; !ok {
		t.Fatal("missing atrust-domain provider")
	}
	if _, ok := cfg.RuleProviders["atrust-ip"]; !ok {
		t.Fatal("missing atrust-ip provider")
	}
	if len(cfg.Rules) != 3 {
		t.Fatalf("rules = %d", len(cfg.Rules))
	}
	if len(cfg.DNS.NameServerPolicy) == 0 {
		t.Fatal("missing DNS policy")
	}
}

func TestParseAtrustCachedResources(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	resource := map[string]any{
		"code": 0,
		"data": map[string]any{
			"appList": map[string]any{"data": map[string]any{
				"appInfo": []any{map[string]any{"apps": []any{map[string]any{
					"id": "cached-app", "nodeGroupID": "group", "accessModel": "L3VPN",
					"addressList": []any{
						map[string]any{"protocol": "tcp", "port": "80", "host": "*.cached.example"},
						map[string]any{"protocol": "udp", "port": "53", "host": "10.9.0.1"},
					},
				}}}},
				"config": map[string]any{"nodeGroupConf": map[string]any{"majorNodeGroup": map[string]any{"id": "group"}}},
			}},
		},
	}
	state := map[string]any{
		"device_id": "device", "sid": "", "cookies": []any{}, "sign_key": "sign", "resources": resource,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(home, "atrust")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(atrustBaseConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RuleProviders["atrust-domain"].Count() != 1 {
		t.Fatalf("cached domain payload count = %d", cfg.RuleProviders["atrust-domain"].Count())
	}
	if cfg.RuleProviders["atrust-ip"].Count() != 1 {
		t.Fatalf("cached IP payload count = %d", cfg.RuleProviders["atrust-ip"].Count())
	}
}

func TestParseAtrustDuplicateProvider(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	cfgText := atrustBaseConfig + `
rule-providers:
  atrust-domain:
    type: inline
    behavior: domain
    payload:
      - example.com
`
	if _, err := config.Parse([]byte(cfgText)); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved provider error, got %v", err)
	}
}

func TestParseAtrustRejectsRemoteAuthListen(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	cfgText := strings.Replace(atrustBaseConfig, "auth:\n  listen: 127.0.0.1:0", "auth:\n  listen: 0.0.0.0:1234", 1)
	if cfgText == atrustBaseConfig {
		cfgText = atrustBaseConfig + "\nauth:\n  listen: 0.0.0.0:1234\n"
	}
	if _, err := config.Parse([]byte(cfgText)); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got %v", err)
	}
}

func TestParseAtrustMultipleNodes(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	cfgText := strings.Replace(atrustBaseConfig, `    state-dir: atrust`, `    state-dir: atrust
  - name: atrust2
    type: atrust
    server: vpn2.example.com
    state-dir: atrust2`, 1)
	if _, err := config.Parse([]byte(cfgText)); err == nil || !strings.Contains(err.Error(), "one node") {
		t.Fatalf("expected single node error, got %v", err)
	}
}
