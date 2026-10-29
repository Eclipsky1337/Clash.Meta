//go:build with_gvisor

package outbound_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/atrust"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/auth"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel"

	D "github.com/miekg/dns"
)

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func liveCredentials(t *testing.T) (server, username, password, stateDir string) {
	t.Helper()
	server = os.Getenv("ATRUST_SERVER")
	if server == "" {
		server = "vpn.zju.edu.cn"
	}
	username = os.Getenv("ATRUST_USER")
	password = os.Getenv("ATRUST_PASSWORD")
	if username == "" || password == "" {
		t.Skip("set ATRUST_USER and ATRUST_PASSWORD to run the live aTrust test")
	}
	stateDir = os.Getenv("ATRUST_STATE_DIR")
	if stateDir == "" {
		stateDir = "/tmp/atrust-home/atrust"
	}
	return server, username, password, stateDir
}

func copyState(t *testing.T, source, target string) {
	t.Helper()
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(source, "state.json"))
	if err != nil {
		t.Skipf("no aTrust state at %s: %v", source, err)
	}
	if err := os.WriteFile(filepath.Join(target, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitPort(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not start", address)
}

func atrustConfig(mixedPort, dnsPort int, server, username, password string) []byte {
	return []byte(fmt.Sprintf(`
mixed-port: %d
external-controller: ""
log-level: debug
mode: rule
auth:
  listen: 127.0.0.1:0
proxies:
  - name: atrust
    type: atrust
    server: %s
    port: 443
    login-domain: Radius
    auth-type: auth/psw
    username: "%s"
    password: "%s"
    state-dir: atrust
    tunnel: l3
    udp: true
    skip-cert-verify: true
rules:
  - RULE-SET,atrust-domain,atrust
  - RULE-SET,atrust-ip,atrust,no-resolve
  - MATCH,DIRECT
dns:
  enable: true
  listen: 127.0.0.1:%d
  enhanced-mode: redir-host
  nameserver:
    - 223.5.5.5
  proxy-server-nameserver:
    - 223.5.5.5
  nameserver-policy:
    "rule-set:atrust-domain": "atrust://atrust"
`, mixedPort, server, username, password, dnsPort))
}

func TestAtrustCoreE2E(t *testing.T) {
	if os.Getenv("ATRUST_E2E") != "1" {
		t.Skip("set ATRUST_E2E=1 to run the live aTrust integration test")
	}
	server, username, password, stateDir := liveCredentials(t)
	home := t.TempDir()
	C.SetHomeDir(home)
	copyState(t, stateDir, filepath.Join(home, "atrust"))

	mixedPort := freePort(t)
	socksPort := freePort(t)
	dnsPort := freePort(t)
	if err := hub.Parse(atrustConfig(mixedPort, dnsPort, server, username, password)); err != nil {
		t.Fatal(err)
	}
	listener.SetBindAddress("127.0.0.1")
	inbound.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	inbound.SetDisAllowedIPs(nil)
	listener.ReCreateMixed(mixedPort, tunnel.Tunnel)
	listener.ReCreateSocks(socksPort, tunnel.Tunnel)
	waitPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort)))
	waitPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)))

	provider, ok := atrust.ProviderByName("atrust")
	if !ok {
		t.Fatal("aTrust provider was not registered")
	}
	session := provider.NewLoginSession(10*time.Minute, 5)
	session.Start()
	select {
	case <-session.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("aTrust login timed out")
	}
	state, _, _, loginErr, _ := session.Snapshot()
	if state != "succeeded" {
		t.Fatalf("aTrust login state %s: %v", state, loginErr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if provider.Status().Resources > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if provider.Status().Resources == 0 {
		t.Fatal("aTrust resources were not published")
	}

	rules := tunnel.RuleProviders()
	if rules["atrust-domain"].Count() == 0 || rules["atrust-ip"].Count() == 0 {
		t.Fatalf("rule providers empty: domain=%d ip=%d", rules["atrust-domain"].Count(), rules["atrust-ip"].Count())
	}
	if !rules["atrust-domain"].Match(&C.Metadata{Host: "www.zju.edu.cn"}, C.RuleMatchHelper{}) {
		t.Fatal("atrust-domain did not match www.zju.edu.cn")
	}
	if !rules["atrust-ip"].Match(&C.Metadata{DstIP: netip.MustParseAddr("10.10.2.21")}, C.RuleMatchHelper{}) {
		t.Fatal("atrust-ip did not match 10.10.2.21")
	}

	// DNS policy: the internal domain must resolve through the aTrust DNS
	// channel, which returns a private address rather than the public one.
	dnsClient := new(D.Client)
	dnsClient.Timeout = 10 * time.Second
	query := new(D.Msg)
	query.SetQuestion("www.zju.edu.cn.", D.TypeA)
	response, _, err := dnsClient.Exchange(query, net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort)))
	if err != nil {
		t.Fatalf("DNS query: %v", err)
	}
	if len(response.Answer) == 0 {
		t.Fatal("DNS returned no answer")
	}
	a, ok := response.Answer[0].(*D.A)
	if !ok {
		t.Fatalf("unexpected DNS answer %T", response.Answer[0])
	}
	if !a.A.IsPrivate() {
		t.Fatalf("DNS answer %s is not the aTrust private address", a.A)
	}
	t.Logf("DNS www.zju.edu.cn -> %s", a.A)

	// Internal TCP through the IP rule set and L3 tunnel.
	tcpConn := socksTCPConnect(t, socksPort, netip.MustParseAddr("10.10.2.21"), 22)
	defer tcpConn.Close()
	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	banner, err := bufio.NewReader(tcpConn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(banner, "SSH-") {
		t.Fatalf("unexpected SSH banner: %q", banner)
	}
	t.Logf("TCP 10.10.2.21:22 -> %s", strings.TrimSpace(banner))

	// Domain rule set: www.zju.edu.cn is matched by atrust-domain, resolved by
	// the aTrust DNS channel, and connected over L3 after the TCP tunnel is
	// unavailable on this gateway.
	domainConn := socksTCPConnectHost(t, socksPort, "www.zju.edu.cn", 443)
	tlsConn := tls.Client(domainConn, &tls.Config{ServerName: "www.zju.edu.cn", InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("TLS handshake through aTrust domain rule: %v", err)
	}
	t.Logf("TLS www.zju.edu.cn:443 -> version 0x%04x", tlsConn.ConnectionState().Version)
	_ = tlsConn.Close()

	// Internal UDP through SOCKS5 UDP ASSOCIATE and the L3 tunnel.
	udpAnswer := socksUDPDNS(t, socksPort, "www.zju.edu.cn.")
	if len(udpAnswer) == 0 {
		t.Fatal("SOCKS5 UDP DNS returned no answer")
	}
	if !udpAnswer[0].IsPrivate() {
		t.Fatalf("SOCKS5 UDP DNS answer %s is not private", udpAnswer[0])
	}
	t.Logf("UDP DNS www.zju.edu.cn -> %s", udpAnswer[0])

	// Loopback auth API: session reuse, status and the rendered login page.
	authAddr := auth.Listen()
	if authAddr == "" {
		t.Fatal("auth listener is not running")
	}
	infoResponse, err := http.Get("http://" + authAddr + "/auth/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	_ = infoResponse.Body.Close()
	if infoResponse.StatusCode != http.StatusOK {
		t.Fatalf("auth info status %d", infoResponse.StatusCode)
	}
	createResponse, err := http.Post("http://"+authAddr+"/auth/v1/providers/atrust/sessions", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		ID    string `json:"id"`
		URL   string `json:"url"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = createResponse.Body.Close()
	if created.URL == "" {
		t.Fatal("auth session has no URL")
	}
	parsedURL, err := url.Parse(created.URL)
	if err != nil {
		t.Fatal(err)
	}
	nonce := parsedURL.Query().Get("t")
	if nonce == "" {
		t.Fatal("auth session URL has no nonce")
	}
	authDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(authDeadline) {
		request, err := http.NewRequest(http.MethodGet, "http://"+authAddr+"/auth/v1/sessions/"+created.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Auth-Nonce", nonce)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot struct {
			State string `json:"state"`
		}
		_ = json.NewDecoder(response.Body).Decode(&snapshot)
		_ = response.Body.Close()
		if snapshot.State == "succeeded" {
			break
		}
		if snapshot.State == "failed" {
			t.Fatalf("auth session failed: %s", snapshot.State)
		}
		time.Sleep(100 * time.Millisecond)
	}
	pageResponse, err := http.Get(created.URL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(pageResponse.Body)
	_ = pageResponse.Body.Close()
	if !strings.Contains(pageResponse.Header.Get("Content-Security-Policy"), "connect-src") || !strings.Contains(string(page), "aTrust") {
		t.Fatal("login page is missing its CSP or title")
	}
}

func socksTCPConnect(t *testing.T, mixedPort int, ip netip.Addr, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting reply: %x", reply)
	}
	request := []byte{0x05, 0x01, 0x00, 0x01}
	request = append(request, ip.AsSlice()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[1] != 0x00 {
		t.Fatalf("SOCKS5 connect failed: %x", header)
	}
	switch header[3] {
	case 0x01:
		_, _ = io.CopyN(io.Discard, conn, 6)
	case 0x04:
		_, _ = io.CopyN(io.Discard, conn, 18)
	default:
		t.Fatalf("unexpected bind address type 0x%02x", header[3])
	}
	return conn
}

func socksTCPConnectHost(t *testing.T, socksPort int, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting reply: %x", reply)
	}
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[1] != 0x00 {
		t.Fatalf("SOCKS5 connect failed: %x", header)
	}
	switch header[3] {
	case 0x01:
		_, _ = io.CopyN(io.Discard, conn, 6)
	case 0x04:
		_, _ = io.CopyN(io.Discard, conn, 18)
	default:
		t.Fatalf("unexpected bind address type 0x%02x", header[3])
	}
	return conn
}

func socksUDPDNS(t *testing.T, mixedPort int, name string) []net.IP {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting reply: %x", reply)
	}
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[1] != 0x00 {
		t.Fatalf("SOCKS5 UDP associate failed: %x", header)
	}
	var relayHost net.IP
	switch header[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			t.Fatal(err)
		}
		relayHost = ip
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			t.Fatal(err)
		}
		relayHost = ip
	default:
		t.Fatalf("unexpected UDP relay address type 0x%02x", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		t.Fatal(err)
	}
	relay := net.JoinHostPort(relayHost.String(), strconv.Itoa(int(binary.BigEndian.Uint16(portBytes))))

	udpConn, err := net.Dial("udp", relay)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(10 * time.Second))

	msg := new(D.Msg)
	msg.SetQuestion(D.Fqdn(name), D.TypeA)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{0, 0, 0, 1, 10, 10, 0, 21, 0, 53}
	packet = append(packet, payload...)
	if _, err := udpConn.Write(packet); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 || buf[3] != 0x01 {
		end := n
		if end > 10 {
			end = 10
		}
		t.Fatalf("unexpected SOCKS5 UDP response header: %x", buf[:end])
	}
	var answer D.Msg
	if err := answer.Unpack(buf[10:n]); err != nil {
		t.Fatal(err)
	}
	var ips []net.IP
	for _, rr := range answer.Answer {
		if record, ok := rr.(*D.A); ok {
			ips = append(ips, record.A)
		}
	}
	return ips
}

func TestAirportConfigE2E(t *testing.T) {
	if os.Getenv("ATRUST_E2E_AIRPORT") != "1" {
		t.Skip("set ATRUST_E2E_AIRPORT=1 to run the real airport config test")
	}
	path := os.Getenv("ATRUST_AIRPORT_CONFIG")
	if path == "" {
		path = "/Users/xuyitian/Downloads/iKuuu_V2.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("airport config: %v", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["external-controller"] = ""
	if rules, ok := raw["rules"].([]any); ok {
		filtered := make([]any, 0, len(rules))
		for _, rule := range rules {
			text := fmt.Sprint(rule)
			if strings.HasPrefix(text, "GEOIP,") || strings.HasPrefix(text, "GEOSITE,") {
				continue
			}
			filtered = append(filtered, rule)
		}
		raw["rules"] = filtered
	}
	config, err := yaml.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	C.SetHomeDir(home)
	if err := hub.Parse(config); err != nil {
		t.Fatal(err)
	}
	mixedPort := freePort(t)
	socksPort := freePort(t)
	listener.SetBindAddress("127.0.0.1")
	inbound.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	inbound.SetDisAllowedIPs(nil)
	listener.ReCreateMixed(mixedPort, tunnel.Tunnel)
	listener.ReCreateSocks(socksPort, tunnel.Tunnel)
	waitPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort)))
	waitPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)))

	selectorProxy, ok := tunnel.Proxies()["🔰 选择节点"]
	if !ok {
		t.Fatal("selector group not found")
	}
	selector, ok := selectorProxy.Adapter().(interface{ Set(string) error })
	if !ok {
		t.Fatalf("selector group has unexpected type %T", selectorProxy.Adapter())
	}
	fallbackProxy, ok := tunnel.Proxies()["🐟 漏网之鱼"]
	if !ok {
		t.Fatal("fallback group not found")
	}
	fallback, ok := fallbackProxy.Adapter().(interface{ Set(string) error })
	if !ok {
		t.Fatalf("fallback group has unexpected type %T", fallbackProxy.Adapter())
	}
	if err := fallback.Set("🔰 选择节点"); err != nil {
		t.Fatal(err)
	}
	candidates := []string{
		"🇭🇰 香港A01", "🇯🇵 日本A01 | IEPL", "🇸🇬 新加坡A01 | IEPL | x2",
		"🇺🇲 美国A01 | IEPL | x1.5", "🇨🇳 台湾A01 | IEPL | x2",
	}
	proxyURL, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort)))
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	var lastErr error
	for _, candidate := range candidates {
		if err := selector.Set(candidate); err != nil {
			lastErr = err
			continue
		}
		response, err := client.Get("http://www.gstatic.com/generate_204")
		if err != nil {
			lastErr = err
			continue
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			lastErr = fmt.Errorf("%s returned %d", candidate, response.StatusCode)
			continue
		}
		t.Logf("airport node %s -> 204", candidate)
		return
	}
	t.Fatalf("no airport node worked: %v", lastErr)
}

func TestAtrustConfigWithoutNodeIsUnchanged(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	config := []byte(`
mixed-port: 0
mode: rule
proxies:
  - {name: direct, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
rules:
  - MATCH,direct
`)
	cfg, err := executor.ParseWithBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.RuleProviders["atrust-domain"]; ok {
		t.Fatal("aTrust providers must not be registered without an aTrust node")
	}
	if err := hub.Parse(config); err != nil {
		t.Fatal(err)
	}
	if auth.Listen() != "" {
		t.Fatal("the auth listener must stay closed without an aTrust node")
	}
	if _, ok := tunnel.RuleProviders()["atrust-domain"]; ok {
		t.Fatal("aTrust providers leaked into a config without an aTrust node")
	}
}

func TestAtrustAirportSplitE2E(t *testing.T) {
	if os.Getenv("ATRUST_E2E_SPLIT") != "1" {
		t.Skip("set ATRUST_E2E_SPLIT=1 to run the split-routing test")
	}
	path := os.Getenv("ATRUST_AIRPORT_CONFIG")
	if path == "" {
		path = "/Users/xuyitian/Downloads/iKuuu_V2.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("airport config: %v", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["external-controller"] = ""
	raw["mixed-port"] = 0
	raw["auth"] = map[string]any{"listen": "127.0.0.1:0"}
	raw["dns"] = map[string]any{
		"enable":                  true,
		"enhanced-mode":           "redir-host",
		"nameserver":              []any{"223.5.5.5"},
		"proxy-server-nameserver": []any{"223.5.5.5"},
		"nameserver-policy": map[string]any{
			"rule-set:atrust-domain": "atrust://atrust",
		},
	}
	server, username, password, stateDir := liveCredentials(t)
	proxies, _ := raw["proxies"].([]any)
	proxies = append([]any{map[string]any{
		"name": "atrust", "type": "atrust", "server": server, "port": 443,
		"login-domain": "Radius", "auth-type": "auth/psw", "username": username,
		"password": password, "state-dir": "atrust", "tunnel": "l3", "udp": true,
		"skip-cert-verify": true,
	}}, proxies...)
	raw["proxies"] = proxies
	rules, _ := raw["rules"].([]any)
	filteredRules := make([]any, 0, len(rules)+2)
	filteredRules = append(filteredRules, "RULE-SET,atrust-domain,atrust", "RULE-SET,atrust-ip,atrust,no-resolve")
	for _, rule := range rules {
		text := fmt.Sprint(rule)
		if strings.HasPrefix(text, "GEOIP,") || strings.HasPrefix(text, "GEOSITE,") {
			continue
		}
		filteredRules = append(filteredRules, rule)
	}
	raw["rules"] = filteredRules
	combined, err := yaml.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	C.SetHomeDir(home)
	copyState(t, stateDir, filepath.Join(home, "atrust"))
	if err := hub.Parse(combined); err != nil {
		t.Fatal(err)
	}
	mixedPort := freePort(t)
	listener.SetBindAddress("127.0.0.1")
	inbound.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	inbound.SetDisAllowedIPs(nil)
	listener.ReCreateMixed(mixedPort, tunnel.Tunnel)
	waitPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort)))

	provider, ok := atrust.ProviderByName("atrust")
	if !ok {
		t.Fatal("aTrust provider was not registered")
	}
	session := provider.NewLoginSession(10*time.Minute, 5)
	session.Start()
	select {
	case <-session.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("aTrust login timed out")
	}
	state, _, _, loginErr, _ := session.Snapshot()
	if state != "succeeded" {
		t.Fatalf("aTrust login state %s: %v", state, loginErr)
	}

	selectorProxy, ok := tunnel.Proxies()["🔰 选择节点"]
	if !ok {
		t.Fatal("selector group not found")
	}
	selector, _ := selectorProxy.Adapter().(interface{ Set(string) error })
	fallbackProxy, ok := tunnel.Proxies()["🐟 漏网之鱼"]
	if !ok {
		t.Fatal("fallback group not found")
	}
	fallback, _ := fallbackProxy.Adapter().(interface{ Set(string) error })
	_ = fallback.Set("🔰 选择节点")
	_ = selector.Set("🇭🇰 香港A01")

	// Internal destination must go through aTrust.
	internal := socksTCPConnect(t, mixedPort, netip.MustParseAddr("10.10.2.21"), 22)
	_ = internal.SetDeadline(time.Now().Add(10 * time.Second))
	banner, err := bufio.NewReader(internal).ReadString('\n')
	_ = internal.Close()
	if err != nil || !strings.HasPrefix(banner, "SSH-") {
		t.Fatalf("internal SSH through aTrust: banner=%q err=%v", banner, err)
	}
	t.Logf("split internal -> %s", strings.TrimSpace(banner))

	// External destination must go through the airport selector.
	proxyURL, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort)))
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatalf("airport request: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("airport request status %d", response.StatusCode)
	}
	t.Logf("split external -> %d", response.StatusCode)
}

func atrustFakeIPConfig(mixedPort, socksPort, dnsPort int, server, username, password string) []byte {
	return []byte(fmt.Sprintf(`
mixed-port: %d
socks-port: %d
external-controller: ""
log-level: warning
mode: rule
auth:
  listen: 127.0.0.1:0
proxies:
  - name: atrust
    type: atrust
    server: %s
    port: 443
    login-domain: Radius
    auth-type: auth/psw
    username: "%s"
    password: "%s"
    state-dir: atrust
    tunnel: l3
    udp: true
    skip-cert-verify: true
rules:
  - RULE-SET,atrust-domain,atrust
  - RULE-SET,atrust-ip,atrust,no-resolve
  - MATCH,DIRECT
dns:
  enable: true
  listen: 127.0.0.1:%d
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
  proxy-server-nameserver:
    - 223.5.5.5
  nameserver-policy:
    "rule-set:atrust-domain": "atrust://atrust"
`, mixedPort, socksPort, server, username, password, dnsPort))
}

func TestAtrustFakeIPE2E(t *testing.T) {
	if os.Getenv("ATRUST_E2E_FAKEIP") != "1" {
		t.Skip("set ATRUST_E2E_FAKEIP=1 to run the fake-ip routing test")
	}
	server, username, password, stateDir := liveCredentials(t)
	home := t.TempDir()
	C.SetHomeDir(home)
	copyState(t, stateDir, filepath.Join(home, "atrust"))
	mixedPort := freePort(t)
	socksPort := freePort(t)
	dnsPort := freePort(t)
	if err := hub.Parse(atrustFakeIPConfig(mixedPort, socksPort, dnsPort, server, username, password)); err != nil {
		t.Fatal(err)
	}
	listener.SetBindAddress("127.0.0.1")
	inbound.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	inbound.SetDisAllowedIPs(nil)
	listener.ReCreateMixed(mixedPort, tunnel.Tunnel)
	listener.ReCreateSocks(socksPort, tunnel.Tunnel)
	waitPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)))
	provider, ok := atrust.ProviderByName("atrust")
	if !ok {
		t.Fatal("aTrust provider was not registered")
	}
	session := provider.NewLoginSession(10*time.Minute, 5)
	session.Start()
	select {
	case <-session.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("aTrust login timed out")
	}
	state, _, _, loginErr, _ := session.Snapshot()
	if state != "succeeded" {
		t.Fatalf("aTrust login state %s: %v", state, loginErr)
	}
	dnsClient := new(D.Client)
	dnsClient.Timeout = 10 * time.Second
	query := new(D.Msg)
	query.SetQuestion("www.zju.edu.cn.", D.TypeA)
	response, _, err := dnsClient.Exchange(query, net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort)))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) == 0 {
		t.Fatal("fake-ip DNS returned no answer")
	}
	a, ok := response.Answer[0].(*D.A)
	if !ok {
		t.Fatalf("unexpected answer %T", response.Answer[0])
	}
	fakeIP, ok := netip.AddrFromSlice(a.A)
	if !ok || !netip.MustParsePrefix("198.18.0.0/16").Contains(fakeIP) {
		t.Fatalf("DNS answer %s is not in the fake-ip range", a.A)
	}
	t.Logf("fake-ip www.zju.edu.cn -> %s", fakeIP)

	conn := socksTCPConnect(t, socksPort, fakeIP, 443)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "www.zju.edu.cn", InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("TLS through fake-ip: %v", err)
	}
	t.Logf("fake-ip TLS -> version 0x%04x", tlsConn.ConnectionState().Version)
	_ = tlsConn.Close()
}
