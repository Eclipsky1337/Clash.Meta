package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ChallengeType is the renderer-independent step kind the login page switches
// on. The auth API exposes it verbatim.
type ChallengeType string

const (
	ChallengeCredentials ChallengeType = "credentials"
	ChallengeCaptcha     ChallengeType = "captcha"
	ChallengeTOTP        ChallengeType = "totp"
	ChallengeSMS         ChallengeType = "sms"
	ChallengeRadius      ChallengeType = "radius"
	ChallengeConfirm     ChallengeType = "confirm"
	ChallengeCAS         ChallengeType = "cas"
	ChallengeOAuth       ChallengeType = "oauth"
)

// Field describes one input on a challenge. Type is one of text, password,
// code, click or hidden.
type Field struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Label       string `json:"label,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Count       int    `json:"count,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Challenge is the step shown to the user. Image is only set for captcha
// steps; the auth API serves it from memory.
type Challenge struct {
	ID          string        `json:"id"`
	Type        ChallengeType `json:"type"`
	Title       string        `json:"title,omitempty"`
	Description string        `json:"description,omitempty"`
	Image       []byte        `json:"-"`
	ImageType   string        `json:"image_type,omitempty"`
	URL         string        `json:"url,omitempty"`
	Phone       string        `json:"phone,omitempty"`
	Fields      []Field       `json:"fields,omitempty"`
}

// ChallengeResponse is what a renderer returns for one step.
type ChallengeResponse struct {
	Values map[string]any
	Skip   bool
}

type challengeHandler func(ctx context.Context, challenge *Challenge) (*ChallengeResponse, error)

var (
	ErrStaleStep    = errors.New("stale aTrust login step")
	ErrSessionGone  = errors.New("aTrust login session not found")
	ErrSessionEnded = errors.New("aTrust login session has ended")
)

// LoginSession is one interactive login attempt. The auth HTTP server owns its
// lifetime; the outbound owns the network side.
type LoginSession struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time

	client *Client
	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.Mutex
	state        string
	challenge    *Challenge
	stepID       string
	stepSeq      int
	attemptsLeft int
	err          error
	response     chan *ChallengeResponse
	done         chan struct{}
	events       chan struct{}
}

const (
	sessionPending   = "pending"
	sessionAwaiting  = "awaiting_input"
	sessionDone      = "succeeded"
	sessionFailed    = "failed"
	sessionCancelled = "cancelled"
)

func newLoginSession(client *Client, ttl time.Duration, maxAttempts int) *LoginSession {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	return &LoginSession{
		ID:           randomHex(32),
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		client:       client,
		ctx:          ctx,
		cancel:       cancel,
		state:        sessionPending,
		attemptsLeft: maxAttempts,
		response:     make(chan *ChallengeResponse, 1),
		done:         make(chan struct{}),
		events:       make(chan struct{}, 1),
	}
}

// Start runs the login flow in the background. It is safe to call once.
func (s *LoginSession) Start() {
	go func() {
		err := s.client.login(s.ctx, s.ask)
		s.mu.Lock()
		s.challenge = nil
		if err == nil {
			s.state = sessionDone
		} else if errors.Is(err, context.Canceled) {
			s.state = sessionCancelled
			s.err = err
		} else {
			s.state = sessionFailed
			s.err = err
		}
		s.mu.Unlock()
		s.cancel()
		close(s.done)
		s.notify()
	}()
}

func (s *LoginSession) ask(ctx context.Context, challenge *Challenge) (*ChallengeResponse, error) {
	s.mu.Lock()
	if s.attemptsLeft <= 0 {
		s.mu.Unlock()
		return nil, errors.New("too many login attempts")
	}
	s.stepSeq++
	s.stepID = fmt.Sprintf("step-%d", s.stepSeq)
	challenge.ID = s.stepID
	s.challenge = challenge
	s.state = sessionAwaiting
	s.mu.Unlock()
	s.notify()

	select {
	case response := <-s.response:
		return response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrSessionEnded
	}
}

// Submit answers the current step. A stale step is rejected so an old page
// cannot overwrite a newer challenge.
func (s *LoginSession) Submit(stepID string, values map[string]any, skip bool) error {
	s.mu.Lock()
	if s.state != sessionAwaiting || s.stepID == "" || s.stepID != stepID {
		s.mu.Unlock()
		return ErrStaleStep
	}
	if s.attemptsLeft <= 0 {
		s.mu.Unlock()
		return errors.New("too many login attempts")
	}
	s.attemptsLeft--
	s.state = sessionPending
	s.mu.Unlock()

	select {
	case s.response <- &ChallengeResponse{Values: values, Skip: skip}:
		return nil
	case <-s.done:
		return ErrSessionEnded
	case <-s.ctx.Done():
		return ErrSessionEnded
	}
}

func (s *LoginSession) Cancel() {
	s.cancel()
	s.mu.Lock()
	if s.state != sessionDone {
		s.state = sessionCancelled
	}
	s.mu.Unlock()
	s.notify()
}

// Snapshot returns the current state for the auth API. The challenge pointer
// is copied so callers cannot mutate session state.
func (s *LoginSession) Snapshot() (string, *Challenge, int, error, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var challenge *Challenge
	if s.challenge != nil {
		copied := *s.challenge
		challenge = &copied
	}
	return s.state, challenge, s.attemptsLeft, s.err, s.ExpiresAt
}

func (s *LoginSession) Events() <-chan struct{} {
	return s.events
}

func (s *LoginSession) Done() <-chan struct{} {
	return s.done
}

func (s *LoginSession) notify() {
	select {
	case s.events <- struct{}{}:
	default:
	}
}

func (s *LoginSession) expired(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.After(s.ExpiresAt) && s.state != sessionDone && s.state != sessionFailed && s.state != sessionCancelled
}

func graphCheckCode(points [][2]int, width, height int) (string, error) {
	if len(points) == 0 {
		return "", errors.New("captcha requires at least one point")
	}
	if width <= 0 || height <= 0 {
		return "", fmt.Errorf("invalid captcha dimensions %dx%d", width, height)
	}
	payload := struct {
		Coordinates [][2]int `json:"coordinates"`
		Width       int      `json:"width"`
		Height      int      `json:"height"`
	}{Coordinates: points, Width: width, Height: height}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
