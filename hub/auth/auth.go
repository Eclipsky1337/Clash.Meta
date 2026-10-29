package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/atrust"
	"github.com/metacubex/mihomo/log"
)

type Config struct {
	Listen      string
	SessionTTL  int
	MaxAttempts int
}

type server struct {
	config   Config
	listener net.Listener
	http     *http.Server

	mu       sync.Mutex
	sessions map[string]*authSession
	byProxy  map[string]*authSession
	closed   bool
}

type authSession struct {
	login    *atrust.LoginSession
	nonce    string
	provider atrust.Provider
	lastSeen time.Time
}

var (
	globalMu sync.Mutex
	global   *server
)

// ReCreateServer replaces the loopback login listener. The listener is
// independent of the external controller on purpose: it carries credentials
// and must never inherit the controller's bind address or CORS policy.
func ReCreateServer(cfg Config) {
	globalMu.Lock()
	previous := global
	global = nil
	globalMu.Unlock()
	if previous != nil {
		previous.close()
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 600
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Errorln("[Auth] listen %s: %v", cfg.Listen, err)
		return
	}
	s := &server{
		config:   cfg,
		listener: listener,
		sessions: map[string]*authSession{},
		byProxy:  map[string]*authSession{},
	}
	s.http = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := s.http.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Debugln("[Auth] server stopped: %v", err)
		}
	}()
	go s.cleanup()
	globalMu.Lock()
	global = s
	globalMu.Unlock()
	log.Infoln("[Auth] listening on %s", listener.Addr())
}

// Stop shuts down the loopback login listener, if any.
func Stop() {
	globalMu.Lock()
	previous := global
	global = nil
	globalMu.Unlock()
	if previous != nil {
		previous.close()
	}
}

// Listen returns the current loopback address, or "" when the server is off.
func Listen() string {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global == nil {
		return ""
	}
	return global.listener.Addr().String()
}

func (s *server) close() {
	s.mu.Lock()
	s.closed = true
	sessions := s.sessions
	s.sessions = map[string]*authSession{}
	s.byProxy = map[string]*authSession{}
	s.mu.Unlock()
	for _, session := range sessions {
		session.login.Cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

func (s *server) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		for id, session := range s.sessions {
			if now.After(session.login.ExpiresAt) {
				session.login.Cancel()
				delete(s.sessions, id)
				if s.byProxy[session.provider.Name()] == session {
					delete(s.byProxy, session.provider.Name())
				}
			}
		}
		s.mu.Unlock()
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch {
	case r.URL.Path == "/auth/v1/info":
		s.handleInfo(w, r)
	case r.URL.Path == "/auth/v1/providers":
		s.handleProviders(w, r)
	case strings.HasPrefix(r.URL.Path, "/auth/v1/providers/"):
		s.handleProvider(w, r)
	case strings.HasPrefix(r.URL.Path, "/auth/v1/sessions/"):
		s.handleSession(w, r)
	case strings.HasPrefix(r.URL.Path, "/auth/v1/s/"):
		s.handlePage(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, map[string]any{
		"version":   1,
		"listen":    s.listener.Addr().String(),
		"providers": len(atrust.Providers()),
	})
}

func (s *server) handleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	providers := atrust.Providers()
	out := make([]atrust.Status, 0, len(providers))
	for _, provider := range providers {
		out = append(out, provider.Status())
	}
	writeJSON(w, map[string]any{"providers": out})
}

func (s *server) handleProvider(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/auth/v1/providers/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	name := parts[0]
	provider, ok := atrust.ProviderByName(name)
	if !ok {
		writeError(w, http.StatusNotFound, "session_not_found", "provider not found")
		return
	}
	switch parts[1] {
	case "sessions":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		s.createSession(w, provider)
	case "resources":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		s.handleResources(w, provider)
	case "resources-raw":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		s.handleRawResources(w, provider)
	case "logout":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if err := provider.Logout(r.Context()); err != nil {
			writeError(w, http.StatusBadGateway, "provider_error", err.Error())
			return
		}
		s.dropProviderSessions(name)
		writeJSON(w, map[string]any{"state": provider.Status().State})
	default:
		http.NotFound(w, r)
	}
}

func (s *server) handleResources(w http.ResponseWriter, provider atrust.Provider) {
	type snapshotProvider interface {
		Snapshot() atrust.Snapshot
	}
	snapshot, ok := provider.(snapshotProvider)
	if !ok {
		writeJSON(w, map[string]any{"domains": []string{}, "cidrs": []string{}})
		return
	}
	writeJSON(w, snapshot.Snapshot())
}

func (s *server) handleRawResources(w http.ResponseWriter, provider atrust.Provider) {
	rawProvider, ok := provider.(interface{ ResourceJSON() []byte })
	if !ok {
		writeJSON(w, map[string]any{})
		return
	}
	raw := rawProvider.ResourceJSON()
	if len(raw) == 0 {
		writeJSON(w, map[string]any{})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(raw)
}

func (s *server) createSession(w http.ResponseWriter, provider atrust.Provider) {
	s.mu.Lock()
	if existing := s.byProxy[provider.Name()]; existing != nil {
		state, _, _, _, _ := existing.login.Snapshot()
		if state == "pending" || state == "awaiting_input" {
			s.mu.Unlock()
			s.writeSession(w, existing, provider)
			return
		}
	}
	login := provider.NewLoginSession(time.Duration(s.config.SessionTTL)*time.Second, s.config.MaxAttempts)
	session := &authSession{
		login:    login,
		nonce:    randomNonce(),
		provider: provider,
		lastSeen: time.Now(),
	}
	s.sessions[login.ID] = session
	s.byProxy[provider.Name()] = session
	s.mu.Unlock()
	login.Start()
	s.writeSession(w, session, provider)
}

func (s *server) writeSession(w http.ResponseWriter, session *authSession, provider atrust.Provider) {
	state, challenge, attempts, err, expires := session.login.Snapshot()
	payload := map[string]any{
		"id":            session.login.ID,
		"url":           fmt.Sprintf("http://%s/auth/v1/s/%s?t=%s", s.listener.Addr().String(), session.login.ID, session.nonce),
		"proxy":         provider.Name(),
		"state":         state,
		"expires_at":    expires,
		"attempts_left": attempts,
		"step":          s.stepJSON(session, challenge),
	}
	if err != nil {
		payload["error"] = err.Error()
	}
	writeJSON(w, payload)
}

func (s *server) stepJSON(session *authSession, challenge *atrust.Challenge) any {
	if challenge == nil {
		return nil
	}
	step := map[string]any{
		"id":          challenge.ID,
		"type":        challenge.Type,
		"title":       challenge.Title,
		"description": challenge.Description,
		"fields":      challenge.Fields,
	}
	if len(challenge.Image) > 0 {
		step["image"] = fmt.Sprintf("/auth/v1/sessions/%s/captcha?step=%s&t=%s", session.login.ID, challenge.ID, session.nonce)
		step["image_type"] = challenge.ImageType
	}
	if challenge.URL != "" {
		step["url"] = challenge.URL
	}
	if challenge.Phone != "" {
		step["phone"] = challenge.Phone
	}
	return step
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/auth/v1/sessions/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	session, ok := s.lookup(id)
	if !ok {
		writeError(w, http.StatusNotFound, "session_not_found", "session not found")
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			if !s.authorized(r, session) {
				writeError(w, http.StatusForbidden, "invalid_nonce", "invalid or missing nonce")
				return
			}
			s.touch(session)
			s.writeSession(w, session, session.provider)
		case http.MethodDelete:
			session.login.Cancel()
			s.drop(id)
			writeJSON(w, map[string]any{"state": "cancelled"})
		default:
			methodNotAllowed(w)
		}
		return
	}
	switch parts[1] {
	case "submit":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if !s.authorized(r, session) {
			writeError(w, http.StatusForbidden, "invalid_nonce", "invalid or missing nonce")
			return
		}
		s.submit(w, r, session)
	case "captcha":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		s.captcha(w, r, session)
	case "events":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if !s.authorized(r, session) {
			writeError(w, http.StatusForbidden, "invalid_nonce", "invalid or missing nonce")
			return
		}
		s.events(w, r, session)
	default:
		if r.Method == http.MethodDelete {
			session.login.Cancel()
			s.drop(id)
			writeJSON(w, map[string]any{"state": "cancelled"})
			return
		}
		http.NotFound(w, r)
	}
}

func (s *server) submit(w http.ResponseWriter, r *http.Request, session *authSession) {
	var body struct {
		StepID string         `json:"step_id"`
		Values map[string]any `json:"values"`
		Skip   bool           `json:"skip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_value", err.Error())
		return
	}
	if err := session.login.Submit(body.StepID, body.Values, body.Skip); err != nil {
		code := "provider_error"
		status := http.StatusBadGateway
		switch err {
		case atrust.ErrStaleStep:
			code = "stale_step"
			status = http.StatusConflict
		case atrust.ErrSessionEnded:
			code = "session_expired"
			status = http.StatusGone
		}
		writeError(w, status, code, err.Error())
		return
	}
	s.touch(session)
	s.writeSession(w, session, session.provider)
}

func (s *server) captcha(w http.ResponseWriter, r *http.Request, session *authSession) {
	if !s.authorizedQuery(r, session) {
		writeError(w, http.StatusForbidden, "invalid_nonce", "invalid or missing nonce")
		return
	}
	stepID := r.URL.Query().Get("step")
	_, challenge, _, _, _ := session.login.Snapshot()
	if challenge == nil || challenge.ID != stepID || len(challenge.Image) == 0 {
		writeError(w, http.StatusNotFound, "stale_step", "captcha is no longer available")
		return
	}
	w.Header().Set("Content-Type", challenge.ImageType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(challenge.Image)
}

func (s *server) events(w http.ResponseWriter, r *http.Request, session *authSession) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "provider_error", "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-store")
	for {
		select {
		case <-r.Context().Done():
			return
		case <-session.login.Done():
			state, _, _, _, _ := session.login.Snapshot()
			fmt.Fprintf(w, "data: {\"state\":%q}\n\n", state)
			flusher.Flush()
			return
		case <-session.login.Events():
			state, challenge, attempts, err, expires := session.login.Snapshot()
			payload := map[string]any{
				"state":         state,
				"step":          s.stepJSON(session, challenge),
				"attempts_left": attempts,
				"expires_at":    expires,
			}
			if err != nil {
				payload["error"] = err.Error()
			}
			data, _ := json.Marshal(payload)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *server) handlePage(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/auth/v1/s/")
	id := strings.Split(rest, "/")[0]
	session, ok := s.lookup(id)
	if !ok || !s.authorizedQuery(r, session) {
		http.Error(w, "登录会话不存在或已过期", http.StatusNotFound)
		return
	}
	s.touch(session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'")
	_, _ = w.Write([]byte(loginPage))
}

func (s *server) lookup(id string) (*authSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	return session, ok
}

func (s *server) authorized(r *http.Request, session *authSession) bool {
	return constantTimeEqual(r.Header.Get("X-Auth-Nonce"), session.nonce)
}

func (s *server) authorizedQuery(r *http.Request, session *authSession) bool {
	nonce := r.URL.Query().Get("t")
	if nonce == "" {
		nonce = r.Header.Get("X-Auth-Nonce")
	}
	return constantTimeEqual(nonce, session.nonce)
}

func constantTimeEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *server) touch(session *authSession) {
	s.mu.Lock()
	session.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *server) drop(id string) {
	s.mu.Lock()
	session := s.sessions[id]
	delete(s.sessions, id)
	if session != nil && s.byProxy[session.provider.Name()] == session {
		delete(s.byProxy, session.provider.Name())
	}
	s.mu.Unlock()
}

func (s *server) dropProviderSessions(name string) {
	s.mu.Lock()
	session := s.byProxy[name]
	if session != nil {
		delete(s.sessions, session.login.ID)
		delete(s.byProxy, name)
	}
	s.mu.Unlock()
	if session != nil {
		session.login.Cancel()
	}
}

func randomNonce() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}
