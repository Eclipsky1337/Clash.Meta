package atrust

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestGraphCheckCode(t *testing.T) {
	raw, err := graphCheckCode([][2]int{{10, 20}, {30, 40}}, 320, 180)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Coordinates [][2]int `json:"coordinates"`
		Width       int      `json:"width"`
		Height      int      `json:"height"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Width != 320 || payload.Height != 180 || len(payload.Coordinates) != 2 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if _, err := graphCheckCode(nil, 320, 180); err == nil {
		t.Fatal("expected empty points to fail")
	}
}

func TestEncryptChunks(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("a password longer than one RSA block: 0123456789abcdefghijklmnopqrstuvwxyz")
	ciphertext, err := encryptChunks(&key.PublicKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	chunkSize := key.PublicKey.Size()
	if len(ciphertext)%chunkSize != 0 {
		t.Fatalf("ciphertext length %d is not a multiple of %d", len(ciphertext), chunkSize)
	}
	var decrypted []byte
	for offset := 0; offset < len(ciphertext); offset += chunkSize {
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, key, ciphertext[offset:offset+chunkSize])
		if err != nil {
			t.Fatal(err)
		}
		decrypted = append(decrypted, chunk...)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted %q, want %q", decrypted, plaintext)
	}
}

func TestTOTPCode(t *testing.T) {
	// RFC 6238 SHA-1 test vector for 2011-09-13 20:46:30 UTC (counter 0x1e6f2f0f).
	code, err := totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("totp = %s, want 287082", code)
	}
}

func TestParseAuthStep(t *testing.T) {
	step := parseAuthStep(authStepData{
		NextService:     "auth/token",
		NextServiceList: []authServiceInfo{{AuthID: "id-1", AuthType: "auth/totp"}},
	})
	if step.Service != "auth/totp" || step.AuthID != "id-1" {
		t.Fatalf("unexpected step: %+v", step)
	}
	step = parseAuthStep(authStepData{NextService: "auth/sms", NextServiceList: []authServiceInfo{{AuthID: "id-2", AuthType: "auth/sms"}}})
	if step.smsMode != 1 {
		t.Fatalf("expected authId SMS mode, got %+v", step)
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	want := &persistedState{DeviceID: "device", SID: "sid", SignKey: "key", Cookies: []Cookie{{Host: "h", Scheme: "https", Name: "sid", Value: "v"}}}
	if err := saveState(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	got, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != want.DeviceID || got.SID != want.SID || len(got.Cookies) != 1 {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestRangeToPrefixes(t *testing.T) {
	minIP := netip.MustParseAddr("10.0.0.0")
	maxIP := netip.MustParseAddr("10.0.0.255")
	prefixes := rangeToPrefixes(minIP, maxIP)
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.0/24" {
		t.Fatalf("unexpected prefixes: %v", prefixes)
	}
	prefixes = rangeToPrefixes(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.1"))
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.1/32" {
		t.Fatalf("unexpected single prefix: %v", prefixes)
	}
}

func TestParsePacketMeta(t *testing.T) {
	packet := make([]byte, 20+20)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 40
	packet[9] = 6
	copy(packet[12:16], net.ParseIP("10.0.0.1").To4())
	copy(packet[16:20], net.ParseIP("10.0.0.2").To4())
	packet[20], packet[21] = 0x12, 0x34
	packet[22], packet[23] = 0x00, 0x50
	meta, err := parsePacketMeta(packet)
	if err != nil {
		t.Fatal(err)
	}
	if meta.protocol() != "tcp" || meta.srcPort != 0x1234 || meta.dstPort != 80 {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if meta.dstIP.String() != "10.0.0.2" {
		t.Fatalf("unexpected destination: %s", meta.dstIP)
	}
}

func testResourceJSON(t *testing.T, server string) []byte {
	t.Helper()
	resource := map[string]any{
		"code": 0,
		"data": map[string]any{
			"appList": map[string]any{
				"data": map[string]any{
					"appInfo": []any{
						map[string]any{"apps": []any{
							map[string]any{
								"id":              "app-1",
								"nodeGroupID":     "group-1",
								"accessModel":     "L3VPN",
								"enableTCPPrefL3": false,
								"addrPretend":     true,
								"addressList": []any{
									map[string]any{"protocol": "tcp", "port": "80", "host": "*.example.com", "ip": []string{"10.1.2.3"}},
									map[string]any{"protocol": "udp", "port": "53", "host": "10.10.0.21"},
									map[string]any{"protocol": "tcp", "port": "8000-8080", "host": "10.20.0.0/24"},
								},
							},
						}},
					},
					"config": map[string]any{
						"nodeGroupConf": map[string]any{
							"majorNodeGroup": map[string]any{"id": "group-1"},
							"nodeGroupList": []any{
								map[string]any{"id": "group-1", "addressInfo": []any{
									map[string]any{"address": "{{sdpcHost}}", "type": "wan"},
								}},
							},
						},
					},
				},
			},
			"sdpPolicy": map[string]any{
				"data": map[string]any{
					"clientOption": map[string]any{
						"dnsOption": map[string]any{"firstDNS": "10.10.0.21", "secondDNS": "10.10.2.21"},
					},
				},
			},
		},
	}
	data, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestResourceMatching(t *testing.T) {
	index, err := parseResource(testResourceJSON(t, "vpn.example.com"), "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(index.nodeGroups) != 1 || index.majorGroup != "group-1" {
		t.Fatalf("unexpected groups: %+v", index.nodeGroups)
	}
	if got := index.nodeGroups["group-1"].WAN; len(got) != 1 || got[0] != "vpn.example.com:441" {
		t.Fatalf("unexpected WAN nodes: %v", got)
	}
	if entry, ok := index.matchDomain("a.example.com", 80, "tcp"); !ok || entry.AppID != "app-1" {
		t.Fatalf("domain did not match: %+v %v", entry, ok)
	}
	if _, ok := index.matchDomain("a.example.com", 81, "tcp"); ok {
		t.Fatal("port should not match")
	}
	if _, ok := index.matchDomain("example.com", 80, "udp"); ok {
		t.Fatal("protocol should not match")
	}
	if resource, ok := index.matchIP(netip.MustParseAddr("10.20.0.42"), 8080, "tcp"); !ok || resource.AppID != "app-1" {
		t.Fatalf("CIDR did not match: %+v %v", resource, ok)
	}
	if _, ok := index.matchIP(netip.MustParseAddr("10.20.0.42"), 8081, "tcp"); ok {
		t.Fatal("port outside range should not match")
	}
	if len(index.snapshot.Domains) != 1 || index.snapshot.Domains[0] != "+.example.com" {
		t.Fatalf("unexpected domain payload: %v", index.snapshot.Domains)
	}
	if len(index.snapshot.CIDRs) == 0 {
		t.Fatal("expected CIDR payload")
	}
}

func TestMatchIPPrefersLastExactResource(t *testing.T) {
	resource := map[string]any{
		"code": 0,
		"data": map[string]any{"appList": map[string]any{"data": map[string]any{
			"appInfo": []any{map[string]any{"apps": []any{
				map[string]any{
					"id": "domain-app", "accessModel": "L3VPN",
					"addressList": []any{map[string]any{"protocol": "tcp", "port": "80", "host": "www.example.com", "ip": []string{"10.1.2.3"}}},
				},
				map[string]any{
					"id": "ip-app", "accessModel": "L3VPN",
					"addressList": []any{map[string]any{"protocol": "tcp", "port": "80", "host": "10.1.2.3"}},
				},
			}}},
			"config": map[string]any{"nodeGroupConf": map[string]any{"majorNodeGroup": map[string]any{"id": "group"}}},
		}}},
	}
	data, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	index, err := parseResource(data, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	matched, ok := index.matchIP(netip.MustParseAddr("10.1.2.3"), 80, "tcp")
	if !ok || matched.AppID != "ip-app" {
		t.Fatalf("matched %+v, want the later exact IP resource", matched)
	}
}

func TestFakeServerLogin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	var decryptedPassword string
	handler := http.NewServeMux()
	handler.HandleFunc("/public/manifest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"server":"aTrust/test","capacities":{},"options":{}}}`)
	})
	handler.HandleFunc("/passport/v1/public/authConfig", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("needTicket") == "0" {
			fmt.Fprint(w, `{"code":0,"data":{"isLogin":1,"security":{"csrfToken":"csrf"},"pubKey":"`+key.PublicKey.N.Text(16)+`","pubKeyExp":"`+big.NewInt(int64(key.PublicKey.E)).Text(10)+`","antiReplayRand":"rand"}}`)
			return
		}
		fmt.Fprint(w, `{"code":0,"data":{"isLogin":0,"security":{"csrfToken":"csrf"},"pubKey":"`+key.PublicKey.N.Text(16)+`","pubKeyExp":"`+big.NewInt(int64(key.PublicKey.E)).Text(10)+`","antiReplayRand":"rand","authServerInfoList":[{"loginDomain":"Radius","authType":"auth/psw"}]}}`)
	})
	handler.HandleFunc("/passport/v1/auth/psw", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ciphertext, err := hex.DecodeString(body.Password)
		if err != nil {
			t.Errorf("password is not hex: %v", err)
			return
		}
		var plain []byte
		for offset := 0; offset < len(ciphertext); offset += key.PublicKey.Size() {
			chunk, err := rsa.DecryptPKCS1v15(rand.Reader, key, ciphertext[offset:offset+key.PublicKey.Size()])
			if err != nil {
				t.Errorf("decrypt: %v", err)
				return
			}
			plain = append(plain, chunk...)
		}
		decryptedPassword = string(plain)
		if body.Username != "user@Radius" {
			t.Errorf("username = %q", body.Username)
		}
		fmt.Fprint(w, `{"code":0,"message":"ok","data":{"ticket":"ticket-1","nextService":""}}`)
	})
	handler.HandleFunc("/passport/v1/auth/authCheck", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "fake-sid", Path: "/", Secure: true})
		fmt.Fprint(w, `{"code":0,"data":{"nextService":""}}`)
	})
	handler.HandleFunc("/controller/v1/public/reportEnv", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"message":"ok"}`)
	})
	handler.HandleFunc("/passport/v1/user/onlineInfo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"username":"user"}}`)
	})
	handler.HandleFunc("/controller/v1/user/clientResource", func(w http.ResponseWriter, r *http.Request) {
		w.Write(testResourceJSON(t, server.Listener.Addr().String()))
	})
	server = httptest.NewTLSServer(handler)
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port := 0
	fmt.Sscanf(portText, "%d", &port)
	client, err := NewClient(Options{
		Name:            "atrust",
		Server:          host,
		Port:            port,
		LoginDomain:     "Radius",
		AuthType:        "auth/psw",
		Username:        "user",
		Password:        "pass",
		Tunnel:          "l3",
		StateDir:        t.TempDir(),
		SkipCertVerify:  true,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := client.NewLoginSession(time.Minute, 5)
	session.Start()
	select {
	case <-session.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("login timed out")
	}
	state, _, _, loginErr, _ := session.Snapshot()
	if state != "succeeded" {
		t.Fatalf("login state %s: %v", state, loginErr)
	}
	if decryptedPassword != "pass_rand" {
		t.Fatalf("decrypted password = %q", decryptedPassword)
	}
	if client.Status().State != StateReady {
		t.Fatalf("status = %+v", client.Status())
	}
	if _, err := client.DialContext(context.Background(), "not-allowed.example", netip.Addr{}, 443); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected resource denial, got %v", err)
	}
	msg := new(D.Msg)
	msg.SetQuestion(D.Fqdn("example.com"), D.TypeA)
	response, err := client.ExchangeContext(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one static DNS answer, got %v", response.Answer)
	}

	restarted, err := NewClient(Options{
		Name:            "atrust",
		Server:          host,
		Port:            port,
		LoginDomain:     "Radius",
		AuthType:        "auth/psw",
		Username:        "user",
		Password:        "pass",
		Tunnel:          "l3",
		StateDir:        client.options.StateDir,
		SkipCertVerify:  true,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.Status().State != StateReady {
		t.Fatalf("restarted state = %s", restarted.Status().State)
	}
	if restarted.Status().Resources == 0 {
		t.Fatal("cached resources were not loaded before login")
	}
	if restarted.Status().Domains == 0 || restarted.Status().CIDRs == 0 {
		t.Fatalf("cached resource counts = %+v", restarted.Status())
	}
	var published Snapshot
	restarted.SetSnapshotHandler(func(snapshot Snapshot) { published = snapshot })
	if len(published.Domains) == 0 {
		t.Fatal("snapshot handler did not receive the cached snapshot")
	}
}

func TestFakeServerSessionExpiryKeepsResources(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/public/manifest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"server":"aTrust/test","capacities":{},"options":{}}}`)
	})
	handler.HandleFunc("/passport/v1/public/authConfig", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("needTicket") == "0" {
			fmt.Fprint(w, `{"code":0,"data":{"isLogin":0,"security":{"csrfToken":"csrf"}}}`)
			return
		}
		fmt.Fprint(w, `{"code":0,"data":{"isLogin":1,"security":{"csrfToken":"csrf"}}}`)
	})
	handler.HandleFunc("/passport/v1/user/onlineInfo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"username":"user"}}`)
	})
	handler.HandleFunc("/controller/v1/user/clientResource", func(w http.ResponseWriter, r *http.Request) {
		w.Write(testResourceJSON(t, "vpn.example.com"))
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port := 0
	fmt.Sscanf(portText, "%d", &port)
	client, err := NewClient(Options{
		Name:            "atrust",
		Server:          host,
		Port:            port,
		Tunnel:          "l3",
		StateDir:        t.TempDir(),
		SkipCertVerify:  true,
		RefreshInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := client.NewLoginSession(time.Minute, 5)
	session.Start()
	select {
	case <-session.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("login timed out")
	}
	if client.Status().State != StateReady {
		t.Fatalf("status after login = %+v", client.Status())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && client.Status().State != StateExpired {
		time.Sleep(50 * time.Millisecond)
	}
	if client.Status().State != StateExpired {
		t.Fatalf("status after refresh failure = %+v", client.Status())
	}
	if client.Status().Resources == 0 {
		t.Fatal("resources were cleared on expiry")
	}
	if _, err := client.DialContext(context.Background(), "a.example.com", netip.Addr{}, 80); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("expired client should fail closed, got %v", err)
	}
}
