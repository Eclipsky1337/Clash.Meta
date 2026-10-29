package atrust

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// State is the lifecycle state of one aTrust outbound.
type State string

const (
	StateIdle      State = "idle"
	StateNeedLogin State = "need_login"
	StateLoggingIn State = "logging_in"
	StateReady     State = "ready"
	StateExpired   State = "expired"
	StateError     State = "error"
)

var (
	ErrAuthRequired   = errors.New("aTrust authentication required")
	ErrResourceDenied = errors.New("aTrust resource denied")
	ErrClosed         = errors.New("aTrust client closed")
	ErrNotReady       = errors.New("aTrust client is not ready")
	ErrSessionInvalid = errors.New("aTrust session is invalid")
)

// ResourceDeniedError carries the target that failed the resource ACL so the
// connection list and logs can explain why traffic was rejected.
type ResourceDeniedError struct {
	Host     string
	Port     int
	Protocol string
}

func (e *ResourceDeniedError) Error() string {
	target := e.Host
	if e.Port != 0 {
		target = fmt.Sprintf("%s:%d", e.Host, e.Port)
	}
	if e.Protocol == "" {
		return fmt.Sprintf("%s: %s", ErrResourceDenied, target)
	}
	return fmt.Sprintf("%s: %s/%s", ErrResourceDenied, e.Protocol, target)
}

func (e *ResourceDeniedError) Is(target error) bool {
	return target == ErrResourceDenied
}

// IPResource is one address range granted by the server.
type IPResource struct {
	IPMin           netip.Addr
	IPMax           netip.Addr
	PortMin         int
	PortMax         int
	Protocol        string
	AppID           string
	NodeGroupID     string
	EnableTCPPrefL3 bool
}

// DomainResource is one domain grant. Domain is a suffix beginning with a
// dot ("example.com" or ".example.com" both match example.com and children).
type DomainResource struct {
	Domain          string
	PortMin         int
	PortMax         int
	Protocol        string
	AppID           string
	NodeGroupID     string
	EnableTCPPrefL3 bool
	AddrPretend     bool
}

// Snapshot is the immutable resource view published to rule providers and the
// DNS client. Domains are provider-ready suffixes, CIDRs are canonical.
type Snapshot struct {
	Domains []string
	CIDRs   []string
}

// Options configures a Client. It deliberately has no mihomo types so the
// protocol layer stays testable without the tunnel.
type Options struct {
	Name            string
	Server          string
	Port            int
	LoginDomain     string
	AuthType        string
	Username        string
	Password        string
	TOTPSecret      string
	Tunnel          string
	StateDir        string
	DeviceID        string
	RefreshInterval time.Duration
	SessionTTL      time.Duration
	SkipCertVerify  bool

	// DialContext dials the aTrust server. Outbound wires this to mihomo's
	// dialer so the server host resolves through proxy-server-nameserver.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// ResolveHost resolves an ACL-only host when no domain resource matched.
	// It must not use the default resolver, or fake-ip loops back here.
	ResolveHost func(ctx context.Context, host string) (netip.Addr, error)
}

func (o Options) serverHost() string {
	if o.Port == 0 || o.Port == 443 {
		return o.Server
	}
	return fmt.Sprintf("%s:%d", o.Server, o.Port)
}

func (o Options) statePath() string {
	return stateFilePath(o.StateDir)
}

// Status is the read-only state exposed to the GUI and auth API.
type Status struct {
	Name       string    `json:"name"`
	State      State     `json:"state"`
	Account    string    `json:"account,omitempty"`
	Error      string    `json:"error,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	HasSession bool      `json:"has_session"`
	Resources  int       `json:"resources"`
}
