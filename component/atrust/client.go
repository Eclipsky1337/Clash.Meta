package atrust

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

// Client owns one aTrust node's session, resources and tunnel. All network
// access after construction is lazy; the constructor only reads persisted
// state so config loading never blocks on the VPN server.
type Client struct {
	options Options

	mu        sync.RWMutex
	auth      *authClient
	persisted *persistedState
	state     State
	lastErr   error
	resources *resourceIndex
	updatedAt time.Time

	tunnelMu sync.Mutex
	tunnel   tunnel

	sessionMu sync.Mutex
	session   *LoginSession

	refreshCancel context.CancelFunc
	closeOnce     sync.Once
	closed        bool
	onSnapshot    func(Snapshot)
	connectionID  string
	rawResource   []byte
}

// NewClient constructs a client from persisted state. It never performs a
// network request; callers start a login session when they need one.
func NewClient(options Options) (*Client, error) {
	if options.Name == "" {
		options.Name = "atrust"
	}
	if options.Server == "" {
		return nil, errors.New("aTrust server is required")
	}
	if options.Port == 0 {
		options.Port = 443
	}
	if options.Tunnel == "" {
		options.Tunnel = "l3"
	}
	if options.Tunnel != "l3" && options.Tunnel != "tcp" {
		return nil, fmt.Errorf("invalid aTrust tunnel %q, expected l3 or tcp", options.Tunnel)
	}
	if options.StateDir == "" {
		options.StateDir = "atrust"
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = 30 * time.Minute
	}
	if options.SessionTTL <= 0 {
		options.SessionTTL = 10 * time.Minute
	}
	auth, err := newAuthClient(options)
	if err != nil {
		return nil, err
	}
	persisted, err := loadState(options.statePath())
	if err != nil {
		return nil, err
	}
	if options.DeviceID == "" {
		options.DeviceID = persisted.DeviceID
	}
	if options.DeviceID == "" {
		options.DeviceID = strings.ToLower(randomHex(32))
		persisted.DeviceID = options.DeviceID
	}
	auth.deviceID = options.DeviceID
	if len(persisted.Cookies) > 0 {
		auth.restoreCookies(persisted.Cookies)
	}
	state := StateNeedLogin
	if persisted.SID == "" {
		state = StateNeedLogin
	}
	client := &Client{
		options:      options,
		auth:         auth,
		persisted:    persisted,
		state:        state,
		updatedAt:    persisted.UpdatedAt,
		connectionID: newConnectionID(options.DeviceID),
	}
	if len(persisted.Resources) > 0 {
		if cached, err := parseResource(persisted.Resources, options.Server); err == nil {
			client.resources = cached
		}
	}
	return client, nil
}

// SetSnapshotHandler registers a callback fired whenever the resource set is
// rebuilt. It is used to update internal rule providers.
func (c *Client) SetSnapshotHandler(handler func(Snapshot)) {
	c.mu.Lock()
	c.onSnapshot = handler
	resources := c.resources
	c.mu.Unlock()
	if resources != nil {
		handler(resources.snapshot)
	}
}

// Name returns the configured proxy name.
func (c *Client) Name() string { return c.options.Name }

// Status returns a copy of the current state.
func (c *Client) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	status := Status{
		Name:       c.options.Name,
		State:      c.state,
		Account:    c.persisted.Username,
		UpdatedAt:  c.updatedAt,
		HasSession: c.persisted.SID != "",
	}
	if c.lastErr != nil {
		status.Error = c.lastErr.Error()
	}
	if c.resources != nil {
		status.Domains = len(c.resources.domains)
		status.CIDRs = len(c.resources.ipResources)
		status.Resources = status.Domains + status.CIDRs
	}
	return status
}

func (c *Client) setState(state State, err error) {
	c.mu.Lock()
	c.state = state
	c.lastErr = err
	c.updatedAt = time.Now()
	c.mu.Unlock()
}

// NewLoginSession returns the active interactive session, or creates one. A
// provider permits one login at a time so a second page cannot race the first.
func (c *Client) NewLoginSession(ttl time.Duration, maxAttempts int) *LoginSession {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.session != nil {
		state, _, _, _, _ := c.session.Snapshot()
		if state == sessionPending || state == sessionAwaiting {
			return c.session
		}
	}
	c.session = newLoginSession(c, ttl, maxAttempts)
	return c.session
}

// Session returns the current login session, if any.
func (c *Client) Session(id string) *LoginSession {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.session == nil || c.session.ID != id {
		return nil
	}
	return c.session
}

func (c *Client) login(ctx context.Context, handler challengeHandler) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	c.state = StateLoggingIn
	c.lastErr = nil
	c.mu.Unlock()

	err := c.loginFlow(ctx, handler)
	if err != nil {
		c.setState(StateError, err)
		return err
	}
	c.setState(StateReady, nil)
	c.startRefresh()
	return nil
}

func (c *Client) loginFlow(ctx context.Context, handler challengeHandler) error {
	auth := c.auth
	if len(c.persisted.ServerManifest) == 0 {
		manifest, err := auth.manifestRequest(ctx)
		if err != nil {
			// The manifest only carries capabilities; login can proceed.
			_ = manifest
		} else {
			c.persisted.ServerManifest = manifest
		}
	}

	isLogin, authList, err := auth.authConfig(ctx, true, true, false)
	if err != nil {
		return err
	}
	if !isLogin {
		if err := c.authenticate(ctx, handler, authList); err != nil {
			return err
		}
	}

	username, err := auth.onlineInfo(ctx)
	if err != nil {
		return err
	}
	resourceData, err := auth.clientResource(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.rawResource = append([]byte(nil), resourceData...)
	c.mu.Unlock()
	resources, err := parseResource(resourceData, c.options.Server)
	if err != nil {
		return err
	}
	if err := c.finishLogin(ctx, username, resources); err != nil {
		return err
	}
	return nil
}

func (c *Client) authenticate(ctx context.Context, handler challengeHandler, authList []authInfo) error {
	auth := c.auth
	authType := c.options.AuthType
	if authType == "" {
		authType = "auth/psw"
	}
	loginDomain := c.options.LoginDomain
	if loginDomain == "" {
		loginDomain = "local"
	}
	var selected *authInfo
	for i := range authList {
		if authList[i].AuthType == authType && authList[i].LoginDomain == loginDomain {
			selected = &authList[i]
			break
		}
	}
	if selected == nil {
		return fmt.Errorf("aTrust auth method %s@%s not offered by server", authType, loginDomain)
	}

	username := c.options.Username
	password := c.options.Password
	if username == "" || password == "" {
		response, err := handler(ctx, &Challenge{
			Type:  ChallengeCredentials,
			Title: "aTrust Sign-in",
			Fields: []Field{
				{Name: "username", Type: "text", Label: "Username", Required: true, Placeholder: "Student / staff ID"},
				{Name: "password", Type: "password", Label: "Password", Required: true},
			},
		})
		if err != nil {
			return err
		}
		if value, ok := stringValue(response.Values["username"]); ok && value != "" {
			username = value
		}
		if value, ok := stringValue(response.Values["password"]); ok && value != "" {
			password = value
		}
	}
	if username == "" || password == "" {
		return errors.New("username and password are required")
	}
	auth.username = username

	graphCode := ""
	for attempt := 0; ; attempt++ {
		result, err := auth.passwordLogin(ctx, username, password, loginDomain, graphCode)
		if err != nil {
			return err
		}
		if result.GraphCheckCodeEnable != 1 {
			break
		}
		if attempt >= maxCaptchaTries {
			return errors.New("captcha verification failed after too many attempts")
		}
		imageData, err := auth.checkCode(ctx)
		if err != nil {
			return err
		}
		if _, _, err := auth.authConfig(ctx, true, true, false); err != nil {
			return err
		}
		graphCode, err = c.askCaptcha(ctx, handler, imageData)
		if err != nil {
			return err
		}
	}

	if err := auth.reportEnv(ctx); err != nil {
		return err
	}
	step := authStep{Service: auth.nextService}
	if step.Service == "" {
		step.Service = "auth/authCheck"
	}
	for i := 0; i < maxAuthSteps; i++ {
		if step.Service == "" {
			return nil
		}
		var err error
		switch step.Service {
		case "auth/authCheck":
			step, err = auth.authCheck(ctx)
		case "auth/sms":
			step, err = c.completeSMS(ctx, handler, step)
		case "auth/customSms":
			step, err = c.completeCustomSMS(ctx, handler)
		case "auth/totp":
			step, err = c.completeTOTP(ctx, handler)
		case "auth/radius":
			step, err = c.completeRadius(ctx, handler, "auth/token")
		case "auth/challenge":
			step, err = c.completeRadius(ctx, handler, "auth/challenge")
		case "auth/accessCheck":
			step, err = auth.accessCheck(ctx)
		case "auth/preEnhancedAuth", "auth/enhancedConfirm", "auth/enhancedDone":
			step, err = auth.requestStep(ctx, "GET", step, nil)
		case "auth/bindAuthDevice":
			body, _ := json.Marshal(map[string]string{"deviceId": c.options.DeviceID})
			step, err = auth.requestStep(ctx, "POST", step, body)
		case "auth/token":
			err = errors.New("token authentication is missing a concrete type")
		default:
			err = fmt.Errorf("unsupported aTrust auth service %s", step.Service)
		}
		if err != nil {
			return err
		}
	}
	return errors.New("aTrust authentication chain exceeded its step limit")
}

func (c *Client) completeSMS(ctx context.Context, handler challengeHandler, step authStep) (authStep, error) {
	auth := c.auth
	if step.smsMode == 1 {
		if _, _, err := auth.authConfig(ctx, true, true, false); err != nil {
			return authStep{}, err
		}
	}
	phone := ""
	if numbers, err := auth.phoneNumber(ctx, step.AuthID); err == nil && len(numbers) > 0 {
		phone = strings.Join(numbers, ", ")
	}
	if err := auth.sendSMS(ctx, step); err != nil {
		return authStep{}, err
	}
	if step.smsMode == 0 {
		if _, _, err := auth.authConfig(ctx, true, true, false); err != nil {
			return authStep{}, err
		}
	}
	response, err := handler(ctx, &Challenge{
		Type:        ChallengeSMS,
		Title:       "SMS verification",
		Description: "A verification code was sent to your phone. Enter it below.",
		Phone:       phone,
		Fields:      []Field{{Name: "code", Type: "code", Label: "Code", Required: true, Count: 6}},
	})
	if err != nil {
		return authStep{}, err
	}
	code, _ := stringValue(response.Values["code"])
	if code == "" {
		return authStep{}, errors.New("SMS code is required")
	}
	return auth.submitSMSCode(ctx, step, code, response.Skip)
}

func (c *Client) completeCustomSMS(ctx context.Context, handler challengeHandler) (authStep, error) {
	auth := c.auth
	if err := auth.sendCustomSMS(ctx); err != nil {
		return authStep{}, err
	}
	response, err := handler(ctx, &Challenge{
		Type:   ChallengeSMS,
		Title:  "SMS verification",
		Fields: []Field{{Name: "code", Type: "code", Label: "Code", Required: true, Count: 6}},
	})
	if err != nil {
		return authStep{}, err
	}
	code, _ := stringValue(response.Values["code"])
	if code == "" {
		return authStep{}, errors.New("SMS code is required")
	}
	return auth.submitCustomSMSCode(ctx, code, response.Skip)
}

func (c *Client) completeTOTP(ctx context.Context, handler challengeHandler) (authStep, error) {
	code := ""
	if c.options.TOTPSecret != "" {
		var err error
		code, err = totpCode(c.options.TOTPSecret, time.Now())
		if err != nil {
			return authStep{}, err
		}
	} else {
		response, err := handler(ctx, &Challenge{
			Type:   ChallengeTOTP,
			Title:  "One-time password",
			Fields: []Field{{Name: "code", Type: "code", Label: "TOTP", Required: true, Count: 6}},
		})
		if err != nil {
			return authStep{}, err
		}
		code, _ = stringValue(response.Values["code"])
	}
	if code == "" {
		return authStep{}, errors.New("TOTP code is required")
	}
	return c.auth.submitToken(ctx, "auth/token", map[string]any{
		"action":            "auth",
		"totpToken":         code,
		"isPrevEffect":      false,
		"skipSecondaryAuth": 0,
	})
}

func (c *Client) completeRadius(ctx context.Context, handler challengeHandler, service string) (authStep, error) {
	response, err := handler(ctx, &Challenge{
		Type:   ChallengeRadius,
		Title:  "RADIUS token",
		Fields: []Field{{Name: "code", Type: "code", Label: "Token", Required: true}},
	})
	if err != nil {
		return authStep{}, err
	}
	code, _ := stringValue(response.Values["code"])
	if code == "" {
		return authStep{}, errors.New("RADIUS token is required")
	}
	payload := map[string]any{}
	if service == "auth/challenge" {
		encrypted, err := c.auth.encryptChallenge(code)
		if err != nil {
			return authStep{}, err
		}
		payload["radiusToken"] = encrypted
	} else {
		payload["radiusToken"] = code
		payload["skipSecondaryAuth"] = 0
	}
	return c.auth.submitToken(ctx, service, payload)
}

func (c *Client) askCaptcha(ctx context.Context, handler challengeHandler, imageData []byte) (string, error) {
	width, height := imageSize(imageData)
	response, err := handler(ctx, &Challenge{
		Type:      ChallengeCaptcha,
		Title:     "Click verification",
		Image:     imageData,
		ImageType: imageMime(imageData),
		Fields: []Field{{
			Name:     "points",
			Type:     "click",
			Label:    "Click the characters in the order shown",
			Count:    4,
			Required: true,
		}},
	})
	if err != nil {
		return "", err
	}
	points, err := pointsValue(response.Values["points"])
	if err != nil {
		return "", err
	}
	if w, ok := intValue(response.Values["width"]); ok && w > 0 {
		width = w
	}
	if h, ok := intValue(response.Values["height"]); ok && h > 0 {
		height = h
	}
	return graphCheckCode(points, width, height)
}

func (c *Client) finishLogin(ctx context.Context, username string, resources *resourceIndex) error {
	sid, cookies := c.auth.sessionCookies()
	c.mu.Lock()
	c.resources = resources
	c.rawResource = append([]byte(nil), c.rawResource...)
	c.persisted.Username = username
	c.persisted.SID = sid
	c.persisted.Cookies = cookies
	c.persisted.SignKey = strings.ToLower(randomHex(64))
	c.persisted.DeviceID = c.options.DeviceID
	c.persisted.ServerManifest = c.auth.manifest
	c.persisted.Resources = append(json.RawMessage(nil), c.rawResource...)
	c.connectionID = newConnectionID(c.options.DeviceID)
	c.updatedAt = time.Now()
	c.mu.Unlock()

	if err := saveState(c.options.statePath(), c.persisted); err != nil {
		return err
	}
	c.publishSnapshot()
	return nil
}

func (c *Client) publishSnapshot() {
	c.mu.RLock()
	resources := c.resources
	handler := c.onSnapshot
	c.mu.RUnlock()
	if handler == nil {
		return
	}
	if resources == nil {
		handler(Snapshot{})
		return
	}
	handler(resources.snapshot)
}

func (c *Client) startRefresh() {
	c.refreshCancelLocked(func(cancel context.CancelFunc) {
		c.refreshCancel = cancel
	}, func(ctx context.Context) {
		interval := c.options.RefreshInterval
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			result, err := c.auth.refresh(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				if errors.Is(err, ErrSessionInvalid) {
					c.setState(StateExpired, err)
					c.closeTunnel()
					return
				}
				backoff := interval
				if backoff > time.Minute {
					backoff = time.Minute
				}
				timer.Reset(backoff)
				continue
			}
			c.mu.Lock()
			c.persisted.SID = result.SID
			c.persisted.Cookies = result.Cookies
			c.updatedAt = time.Now()
			c.mu.Unlock()
			_ = saveState(c.options.statePath(), c.persisted)
			timer.Reset(interval)
		}
	})
}

func (c *Client) refreshCancelLocked(set func(context.CancelFunc), run func(context.Context)) {
	c.mu.Lock()
	if c.refreshCancel != nil {
		c.refreshCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.refreshCancel = cancel
	c.mu.Unlock()
	set(cancel)
	go run(ctx)
}

func (c *Client) closeTunnel() {
	c.tunnelMu.Lock()
	tunnel := c.tunnel
	c.tunnel = nil
	c.tunnelMu.Unlock()
	if tunnel != nil {
		_ = tunnel.Close()
	}
}

// Close stops refresh and closes the tunnel.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		cancel := c.refreshCancel
		c.refreshCancel = nil
		c.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		c.closeTunnel()
		c.sessionMu.Lock()
		if c.session != nil {
			c.session.Cancel()
		}
		c.sessionMu.Unlock()
	})
	return err
}

// Logout clears the persisted session and closes the tunnel.
func (c *Client) Logout(ctx context.Context) error {
	_ = c.auth.logout(ctx)
	c.closeTunnel()
	if auth, err := newAuthClient(c.options); err == nil {
		c.auth = auth
	}
	c.mu.Lock()
	c.persisted = &persistedState{DeviceID: c.options.DeviceID}
	c.rawResource = nil
	c.resources = nil
	c.state = StateNeedLogin
	c.updatedAt = time.Now()
	c.mu.Unlock()
	_ = saveState(c.options.statePath(), c.persisted)
	c.publishSnapshot()
	return nil
}

// Target is a validated destination for the tunnel.
type Target struct {
	Host        string
	IP          netip.Addr
	Port        int
	Protocol    string
	AppID       string
	NodeGroupID string
	PreferL3    bool
	AddrPretend bool
}

type sessionState struct {
	SID          string
	DeviceID     string
	ConnectionID string
	Username     string
	SignKey      string
}

func (c *Client) sessionSnapshot() sessionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return sessionState{
		SID:          c.persisted.SID,
		DeviceID:     c.persisted.DeviceID,
		ConnectionID: c.connectionID,
		Username:     c.persisted.Username,
		SignKey:      c.persisted.SignKey,
	}
}

func (c *Client) zeroRTT() bool {
	c.mu.RLock()
	manifest := append(json.RawMessage(nil), c.persisted.ServerManifest...)
	c.mu.RUnlock()
	if len(manifest) == 0 {
		return false
	}
	var parsed struct {
		Data struct {
			Capacities map[string]struct {
				Version string `json:"version"`
			} `json:"capacities"`
			Options map[string]struct {
				Enable bool `json:"enable"`
			} `json:"options"`
		} `json:"data"`
	}
	if err := json.Unmarshal(manifest, &parsed); err != nil {
		return false
	}
	zeroRTT := parsed.Data.Capacities["zeroRTT"]
	tun0RTT := parsed.Data.Options["tun0rtt"]
	return zeroRTT.Version != "" && tun0RTT.Enable
}

func newConnectionID(deviceID string) string {
	sum := md5.Sum([]byte(deviceID))
	return fmt.Sprintf("%X-%d", sum, time.Now().UnixMicro())
}

func (c *Client) ensureReady() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return ErrClosed
	}
	if c.state != StateReady {
		return fmt.Errorf("%w: proxy %s is %s", ErrAuthRequired, c.options.Name, c.state)
	}
	if c.resources == nil {
		return ErrNotReady
	}
	return nil
}

func (c *Client) resolveTarget(ctx context.Context, host string, ip netip.Addr, port int, protocol string) (Target, error) {
	c.mu.RLock()
	resources := c.resources
	c.mu.RUnlock()
	if resources == nil {
		return Target{}, ErrNotReady
	}
	target := Target{Host: host, IP: ip, Port: port, Protocol: protocol}
	if host != "" {
		if entry, ok := resources.matchDomain(host, port, protocol); ok {
			target.AppID = entry.AppID
			target.NodeGroupID = entry.NodeGroupID
			target.PreferL3 = entry.EnableTCPPrefL3
			target.AddrPretend = entry.AddrPretend
			if !ip.IsValid() {
				if static := resources.dns[strings.ToLower(host)]; len(static) > 0 {
					ip = static[0]
				} else if resolved, err := c.ExchangeDNS(ctx, host); err == nil && len(resolved) > 0 {
					ip = resolved[0]
				} else if c.options.ResolveHost != nil {
					resolved, err := c.options.ResolveHost(ctx, host)
					if err != nil {
						return Target{}, &ResourceDeniedError{Host: host, Port: port, Protocol: protocol}
					}
					ip = resolved
				}
			}
			if !ip.IsValid() {
				return Target{}, fmt.Errorf("aTrust resource %s has no resolvable IP", host)
			}
			target.IP = ip
			log.Debugln("[Atrust] target domain=%s ip=%s appID=%s group=%s preferL3=%t pretend=%t", target.Host, target.IP, target.AppID, target.NodeGroupID, target.PreferL3, target.AddrPretend)
			return target, nil
		}
	}
	if !ip.IsValid() && host != "" {
		if c.options.ResolveHost != nil {
			resolved, err := c.options.ResolveHost(ctx, host)
			if err != nil {
				return Target{}, &ResourceDeniedError{Host: host, Port: port, Protocol: protocol}
			}
			ip = resolved
			target.IP = resolved
		}
	}
	if resource, ok := resources.matchIP(ip, port, protocol); ok {
		target.AppID = resource.AppID
		target.NodeGroupID = resource.NodeGroupID
		target.PreferL3 = resource.EnableTCPPrefL3
		log.Debugln("[Atrust] target ip=%s appID=%s group=%s preferL3=%t range=%s-%s", ip, target.AppID, target.NodeGroupID, target.PreferL3, resource.IPMin, resource.IPMax)
		return target, nil
	}
	return Target{}, &ResourceDeniedError{Host: hostOrIP(host, ip), Port: port, Protocol: protocol}
}

func hostOrIP(host string, ip netip.Addr) string {
	if host != "" {
		return host
	}
	if ip.IsValid() {
		return ip.String()
	}
	return "<unknown>"
}

func (c *Client) getTunnel() (tunnel, error) {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	if c.tunnel != nil {
		return c.tunnel, nil
	}
	c.mu.RLock()
	resources := c.resources
	options := c.options
	c.mu.RUnlock()
	if resources == nil {
		return nil, ErrNotReady
	}
	tunnel, err := newTunnel(c, options, resources)
	if err != nil {
		return nil, err
	}
	c.tunnel = tunnel
	return tunnel, nil
}

// DialContext opens a TCP connection through the aTrust tunnel.
func (c *Client) DialContext(ctx context.Context, host string, ip netip.Addr, port int) (net.Conn, error) {
	if err := c.ensureReady(); err != nil {
		return nil, err
	}
	target, err := c.resolveTarget(ctx, host, ip, port, "tcp")
	if err != nil {
		return nil, err
	}
	tunnel, err := c.getTunnel()
	if err != nil {
		return nil, err
	}
	return tunnel.DialTCP(ctx, target)
}

// ListenPacket opens a UDP socket through the L3 tunnel.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := c.ensureReady(); err != nil {
		return nil, err
	}
	if c.options.Tunnel == "tcp" {
		return nil, errors.New("aTrust TCP tunnel does not support UDP")
	}
	tunnel, err := c.getTunnel()
	if err != nil {
		return nil, err
	}
	return tunnel.ListenPacket(ctx)
}

// ExchangeDNS resolves through the aTrust DNS channel. It is called by the
// atrust:// DNS client registered in dns/.
func (c *Client) ExchangeDNS(ctx context.Context, host string) ([]netip.Addr, error) {
	if err := c.ensureReady(); err != nil {
		return nil, err
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	c.mu.RLock()
	resources := c.resources
	c.mu.RUnlock()
	if resources == nil {
		return nil, ErrNotReady
	}
	if ips, ok := resources.dns[host]; ok && len(ips) > 0 {
		return append([]netip.Addr(nil), ips...), nil
	}
	tunnel, err := c.getTunnel()
	if err != nil {
		return nil, err
	}
	return tunnel.ResolveDNS(ctx, host, resources.dnsServers)
}

func imageSize(data []byte) (int, int) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}

func imageMime(data []byte) string {
	switch {
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8:
		return "image/jpeg"
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png"
	case len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a"):
		return "image/gif"
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return "image/webp"
	default:
		return "application/octet-stream"
	}
}

func stringValue(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case fmt.Stringer:
		return v.String(), true
	default:
		return "", false
	}
}

func intValue(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		return int(n), err == nil
	default:
		return 0, false
	}
}

func pointsValue(value any) ([][2]int, error) {
	raw, ok := value.([]any)
	if !ok {
		if typed, ok := value.([][2]int); ok {
			return typed, nil
		}
		return nil, errors.New("captcha points must be a list of coordinate pairs")
	}
	points := make([][2]int, 0, len(raw))
	for _, item := range raw {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			return nil, errors.New("captcha points must be [x, y] pairs")
		}
		x, okX := intValue(pair[0])
		y, okY := intValue(pair[1])
		if !okX || !okY {
			return nil, errors.New("captcha coordinates must be numbers")
		}
		points = append(points, [2]int{x, y})
	}
	return points, nil
}

func totpCode(secret string, now time.Time) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("decode TOTP secret: %w", err)
	}
	counter := uint64(now.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000), nil
}

// Address implements the dns client contract used by mihomo's atrust:// scheme.
func (c *Client) Address() string {
	return "atrust://" + c.options.Name
}

// ResetConnection implements the dns client contract; the tunnel owns its own
// reconnects, so there is nothing to reset here.
func (c *Client) ResetConnection() {}

// ExchangeContext answers A and AAAA queries through the aTrust DNS channel.
// A missing session is an error, not NXDOMAIN, so mihomo can retry after login.
func (c *Client) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("empty DNS question")
	}
	question := msg.Question[0]
	response := new(D.Msg)
	response.SetReply(msg)
	response.RecursionAvailable = true
	if question.Qclass != D.ClassINET || (question.Qtype != D.TypeA && question.Qtype != D.TypeAAAA) {
		response.Rcode = D.RcodeSuccess
		return response, nil
	}
	ips, err := c.ExchangeDNS(ctx, question.Name)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if question.Qtype == D.TypeA && !ip.Is4() {
			continue
		}
		if question.Qtype == D.TypeAAAA && !ip.Is6() {
			continue
		}
		header := D.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: D.ClassINET, Ttl: 3600}
		if question.Qtype == D.TypeA {
			response.Answer = append(response.Answer, &D.A{Hdr: header, A: net.IP(ip.AsSlice())})
		} else {
			response.Answer = append(response.Answer, &D.AAAA{Hdr: header, AAAA: net.IP(ip.AsSlice())})
		}
	}
	return response, nil
}
