//go:build no_atrust

package outbound

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

type Atrust struct {
	*Base
}

type AtrustOption struct {
	BasicOption
	Name            string `proxy:"name"`
	Server          string `proxy:"server"`
	Port            int    `proxy:"port,omitempty"`
	LoginDomain     string `proxy:"login-domain,omitempty"`
	AuthType        string `proxy:"auth-type,omitempty"`
	Username        string `proxy:"username,omitempty"`
	Password        string `proxy:"password,omitempty"`
	TOTPSecret      string `proxy:"totp-secret,omitempty"`
	Tunnel          string `proxy:"tunnel,omitempty"`
	StateDir        string `proxy:"state-dir,omitempty"`
	RefreshInterval int    `proxy:"refresh-interval,omitempty"`
	SkipCertVerify  *bool  `proxy:"skip-cert-verify,omitempty"`
	UDP             *bool  `proxy:"udp,omitempty"`
}

func NewAtrust(AtrustOption) (*Atrust, error) {
	return nil, fmt.Errorf("aTrust support is disabled by the \"no_atrust\" build tag")
}

func (a *Atrust) IsL3Protocol(*C.Metadata) bool { return false }
