package atrust

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	atrustUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"
	maxAuthSteps    = 8
	maxCaptchaTries = 5
)

var sharedQuery = url.Values{
	"clientType": {"SDPClient"},
	"platform":   {"Linux"},
	"lang":       {"en-US"},
}

type authClient struct {
	baseURL  string
	baseHost string
	client   *http.Client
	jar      http.CookieJar

	deviceID   string
	username   string
	totpSecret string

	csrfToken      string
	pubKey         string
	pubKeyExp      string
	antiReplayRand string
	ticket         string
	nextService    string

	manifest json.RawMessage
}

type authInfo struct {
	LoginDomain string `json:"loginDomain"`
	AuthType    string `json:"authType"`
	AuthName    string `json:"authName"`
	LoginURL    string `json:"loginUrl"`
}

type authStep struct {
	Service string
	AuthID  string
	// smsMode is 0 when the gateway omits authId and 1 when it carries one.
	smsMode int
}

type authServiceInfo struct {
	AuthID   string `json:"authId"`
	AuthType string `json:"authType"`
	SubType  string `json:"subType"`
}

type authStepData struct {
	NextService     string            `json:"nextService"`
	NextServiceList []authServiceInfo `json:"nextServiceList"`
}

type loginResult struct {
	Username string
	SID      string
	Cookies  []Cookie
}

type passwordResult struct {
	Ticket               string
	NextService          string
	AntiReplayRand       string
	GraphCheckCodeEnable int
}

type refreshResult struct {
	IsLogin bool
	SID     string
	Cookies []Cookie
}

func newAuthClient(options Options) (*authClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: options.SkipCertVerify,
		},
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if options.DialContext != nil {
		transport.DialContext = options.DialContext
	}
	host := options.serverHost()
	return &authClient{
		baseURL:  "https://" + host,
		baseHost: host,
		client:   &http.Client{Transport: transport, Jar: jar, Timeout: 20 * time.Second},
		jar:      jar,
		deviceID: options.DeviceID,
	}, nil
}

func (a *authClient) restoreCookies(cookies []Cookie) {
	for _, cookie := range cookies {
		u := &url.URL{Host: cookie.Host, Scheme: cookie.Scheme}
		a.jar.SetCookies(u, []*http.Cookie{{Name: cookie.Name, Value: cookie.Value}})
	}
}

func (a *authClient) sessionCookies() (string, []Cookie) {
	cookies := a.jar.Cookies(&url.URL{Host: a.baseHost, Scheme: "https"})
	out := make([]Cookie, 0, len(cookies))
	sid := ""
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			sid = cookie.Value
		}
		out = append(out, Cookie{Host: a.baseHost, Scheme: "https", Name: cookie.Name, Value: cookie.Value})
	}
	return sid, out
}

func randomHex(n int) string {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return strings.ToUpper(hex.EncodeToString(buf))[:n]
}

func (a *authClient) traceID() string {
	return strings.ToLower(randomHex(8))
}

func (a *authClient) headers() http.Header {
	h := make(http.Header)
	h.Set("User-Agent", atrustUserAgent)
	h.Set("x-sdp-rid", base64.StdEncoding.EncodeToString([]byte(a.baseHost)))
	h.Set("x-sdp-traceid", a.traceID())
	if a.csrfToken != "" {
		h.Set("x-csrf-token", a.csrfToken)
	}
	if a.deviceID != "" {
		env, _ := json.Marshal(map[string]string{"deviceId": a.deviceID})
		h.Set("x-sdp-env", base64.StdEncoding.EncodeToString(env))
	}
	return h
}

func withShared(values url.Values) url.Values {
	out := make(url.Values, len(sharedQuery)+len(values))
	for key, items := range sharedQuery {
		out[key] = append([]string(nil), items...)
	}
	for key, items := range values {
		out.Set(key, items[0])
	}
	return out
}

func (a *authClient) request(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) ([]byte, *http.Response, error) {
	u := a.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, nil, err
	}
	req.Header = a.headers()
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, resp, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return data, resp, ErrSessionInvalid
	}
	return data, resp, nil
}

type authConfigResponse struct {
	Code *int `json:"code"`
	Data struct {
		AuthServerInfoList []authInfo `json:"authServerInfoList"`
		IsLogin            *int       `json:"isLogin"`
		CSRF               string     `json:"csrfToken"`
		Security           struct {
			CSRF string `json:"csrfToken"`
		} `json:"security"`
		PubKey         string `json:"pubKey"`
		PubKeyExp      string `json:"pubKeyExp"`
		AntiReplayRand string `json:"antiReplayRand"`
	} `json:"data"`
}

func (a *authClient) authConfig(ctx context.Context, mod, needTicket, refresh bool) (bool, []authInfo, error) {
	query := withShared(nil)
	if mod {
		query.Set("mod", "1")
	}
	if needTicket {
		query.Set("needTicket", "1")
	} else if refresh {
		query.Set("needTicket", "0")
	}
	data, _, err := a.request(ctx, http.MethodGet, "/passport/v1/public/authConfig", query, nil, "")
	if err != nil {
		return false, nil, err
	}
	var response authConfigResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return false, nil, fmt.Errorf("parse authConfig: %w", err)
	}
	if response.Code != nil && *response.Code != 0 {
		if *response.Code == 10000004 || *response.Code == 75500002 {
			return false, nil, ErrSessionInvalid
		}
		return false, nil, fmt.Errorf("authConfig failed with code %d", *response.Code)
	}
	a.csrfToken = response.Data.CSRF
	if a.csrfToken == "" {
		a.csrfToken = response.Data.Security.CSRF
	}
	a.pubKey = response.Data.PubKey
	a.pubKeyExp = response.Data.PubKeyExp
	if response.Data.AntiReplayRand != "" {
		a.antiReplayRand = response.Data.AntiReplayRand
	}
	isLogin := response.Data.IsLogin != nil && *response.Data.IsLogin == 1
	return isLogin, response.Data.AuthServerInfoList, nil
}

func (a *authClient) manifestRequest(ctx context.Context) (json.RawMessage, error) {
	data, resp, err := a.request(ctx, http.MethodGet, "/public/manifest", nil, nil, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}
	var check struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(data, &check); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if check.Code != 0 {
		return nil, fmt.Errorf("manifest code %d", check.Code)
	}
	a.manifest = append(json.RawMessage(nil), data...)
	return a.manifest, nil
}

func (a *authClient) checkCode(ctx context.Context) ([]byte, error) {
	query := withShared(url.Values{"rnd": {strconv.FormatInt(time.Now().UnixMilli(), 10)}})
	data, resp, err := a.request(ctx, http.MethodGet, "/passport/v1/public/checkCode", query, nil, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checkCode HTTP %d", resp.StatusCode)
	}
	if len(data) == 0 {
		return nil, errors.New("checkCode returned an empty image")
	}
	return data, nil
}

func (a *authClient) passwordLogin(ctx context.Context, username, password, domain, graphCode string) (passwordResult, error) {
	if a.pubKey == "" || a.pubKeyExp == "" {
		return passwordResult{}, errors.New("authConfig did not provide an RSA public key")
	}
	modulus, ok := new(big.Int).SetString(a.pubKey, 16)
	if !ok {
		return passwordResult{}, errors.New("invalid RSA modulus")
	}
	exponent, err := strconv.Atoi(a.pubKeyExp)
	if err != nil || exponent <= 0 {
		return passwordResult{}, fmt.Errorf("invalid RSA exponent %q", a.pubKeyExp)
	}
	pub := &rsa.PublicKey{N: modulus, E: exponent}
	encrypted, err := encryptChunks(pub, []byte(password+"_"+a.antiReplayRand))
	if err != nil {
		return passwordResult{}, err
	}
	payload := map[string]any{
		"username":    username + "@" + domain,
		"password":    hex.EncodeToString(encrypted),
		"rememberPwd": "0",
	}
	if graphCode != "" {
		payload["graphCheckCode"] = graphCode
	}
	body, _ := json.Marshal(payload)
	data, _, err := a.request(ctx, http.MethodPost, "/passport/v1/auth/psw", withShared(nil), body, "application/json;charset=utf-8")
	if err != nil {
		return passwordResult{}, err
	}
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Ticket               string `json:"ticket"`
			NextService          string `json:"nextService"`
			AntiReplayRand       string `json:"antiReplayRand"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return passwordResult{}, fmt.Errorf("parse password login: %w", err)
	}
	result := passwordResult{
		Ticket:               response.Data.Ticket,
		NextService:          response.Data.NextService,
		AntiReplayRand:       response.Data.AntiReplayRand,
		GraphCheckCodeEnable: response.Data.GraphCheckCodeEnable,
	}
	if response.Code != 0 {
		if response.Data.GraphCheckCodeEnable == 1 {
			return result, nil
		}
		if response.Code == 10000004 || response.Code == 75500002 {
			return result, ErrSessionInvalid
		}
		return result, fmt.Errorf("password login failed with code %d: %s", response.Code, response.Message)
	}
	if result.Ticket == "" && result.GraphCheckCodeEnable == 0 {
		return result, errors.New("password login succeeded without a ticket")
	}
	a.ticket = result.Ticket
	a.nextService = result.NextService
	if result.AntiReplayRand != "" {
		a.antiReplayRand = result.AntiReplayRand
	}
	return result, nil
}

func encryptChunks(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	chunkSize := pub.Size() - 11
	if chunkSize <= 0 {
		return nil, errors.New("RSA public key is too small")
	}
	out := make([]byte, 0, (len(plaintext)+chunkSize-1)/chunkSize*pub.Size())
	for len(plaintext) > 0 {
		n := chunkSize
		if len(plaintext) < n {
			n = len(plaintext)
		}
		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		plaintext = plaintext[n:]
	}
	return out, nil
}

func (a *authClient) encryptChallenge(code string) (string, error) {
	if a.pubKey == "" {
		return "", errors.New("missing RSA public key")
	}
	modulus, ok := new(big.Int).SetString(a.pubKey, 16)
	if !ok {
		return "", errors.New("invalid RSA modulus")
	}
	exponent, err := strconv.Atoi(a.pubKeyExp)
	if err != nil || exponent <= 0 {
		return "", fmt.Errorf("invalid RSA exponent %q", a.pubKeyExp)
	}
	encrypted, err := encryptChunks(&rsa.PublicKey{N: modulus, E: exponent}, []byte(code+"_"+a.antiReplayRand))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

func (a *authClient) reportEnv(ctx context.Context) error {
	if a.ticket == "" {
		return errors.New("reportEnv requires a ticket")
	}
	payload := map[string]any{
		"ticket":   a.ticket,
		"deviceId": a.deviceID,
		"env": map[string]any{
			"endpoint": map[string]any{
				"device_id": a.deviceID,
				"device":    map[string]any{"type": "browser"},
			},
		},
	}
	body, _ := json.Marshal(payload)
	data, _, err := a.request(ctx, http.MethodPost, "/controller/v1/public/reportEnv", withShared(nil), body, "application/json;charset=utf-8")
	if err != nil {
		return err
	}
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("parse reportEnv: %w", err)
	}
	if response.Code != 0 {
		return fmt.Errorf("reportEnv failed with code %d: %s", response.Code, response.Message)
	}
	return nil
}

func (a *authClient) authCheck(ctx context.Context) (authStep, error) {
	data, _, err := a.request(ctx, http.MethodGet, "/passport/v1/auth/authCheck", withShared(nil), nil, "")
	if err != nil {
		return authStep{}, err
	}
	var response struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return authStep{}, fmt.Errorf("parse authCheck: %w", err)
	}
	if response.Code != 0 {
		return authStep{}, fmt.Errorf("authCheck failed with code %d: %s", response.Code, response.Message)
	}
	return parseAuthStep(response.Data), nil
}

func (a *authClient) onlineInfo(ctx context.Context) (string, error) {
	paths := []string{"/passport/v1/user/onlineInfo", "/controller/v1/public/onlineInfo"}
	var lastErr error
	for _, path := range paths {
		data, resp, err := a.request(ctx, http.MethodGet, path, withShared(nil), nil, "")
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			lastErr = fmt.Errorf("%s HTTP %d", path, resp.StatusCode)
			continue
		}
		var response struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Username string `json:"username"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			lastErr = err
			continue
		}
		if response.Code != 0 {
			lastErr = fmt.Errorf("onlineInfo failed with code %d: %s", response.Code, response.Message)
			continue
		}
		return response.Data.Username, nil
	}
	return "", lastErr
}

func (a *authClient) clientResource(ctx context.Context) ([]byte, error) {
	payload := map[string]any{
		"resourceType": map[string]any{
			"sdpPolicy":       struct{}{},
			"appList":         struct{}{},
			"favoriteAppList": struct{}{},
			"featureCenter":   struct{}{},
			"uemSpace": map[string]any{
				"params": map[string]string{"action": "login"},
			},
		},
	}
	body, _ := json.Marshal(payload)
	paths := []string{"/controller/v1/user/clientResource", "/controller/v1/public/client/resource"}
	var lastErr error
	for _, path := range paths {
		data, resp, err := a.request(ctx, http.MethodPost, path, withShared(nil), body, "application/json;charset=utf-8")
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			lastErr = fmt.Errorf("%s HTTP %d", path, resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s HTTP %d", path, resp.StatusCode)
			continue
		}
		var status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(data, &status); err != nil {
			lastErr = fmt.Errorf("parse %s: %w", path, err)
			continue
		}
		if status.Code != 0 {
			lastErr = fmt.Errorf("%s failed with code %d: %s", path, status.Code, status.Message)
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

func (a *authClient) refresh(ctx context.Context) (refreshResult, error) {
	isLogin, _, err := a.authConfig(ctx, false, false, true)
	if err != nil {
		return refreshResult{}, err
	}
	if !isLogin {
		return refreshResult{}, ErrSessionInvalid
	}
	sid, cookies := a.sessionCookies()
	return refreshResult{IsLogin: true, SID: sid, Cookies: cookies}, nil
}

func (a *authClient) logout(ctx context.Context) error {
	paths := []string{"/passport/v1/auth/logout", "/controller/v1/public/logout"}
	var lastErr error
	for _, path := range paths {
		_, resp, err := a.request(ctx, http.MethodPost, path, withShared(nil), []byte("{}"), "application/json;charset=utf-8")
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
			return nil
		}
		lastErr = fmt.Errorf("%s HTTP %d", path, resp.StatusCode)
	}
	return lastErr
}

func (a *authClient) sendSMS(ctx context.Context, step authStep) error {
	query := withShared(url.Values{"action": {"sendsms"}})
	if step.smsMode == 1 {
		if step.AuthID == "" {
			return errors.New("SMS authentication requires authId")
		}
		query.Set("isPrevEffect", "0")
		query.Set("taskId", "")
		query.Set("authId", step.AuthID)
	}
	data, _, err := a.request(ctx, http.MethodGet, "/passport/v1/auth/sms", query, nil, "")
	if err != nil {
		return err
	}
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips string `json:"tips"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("parse SMS send: %w", err)
	}
	if response.Code != 0 && response.Code != 75500401 {
		return fmt.Errorf("SMS send failed with code %d: %s", response.Code, response.Message)
	}
	return nil
}

func (a *authClient) submitSMSCode(ctx context.Context, step authStep, code string, skip bool) (authStep, error) {
	query := withShared(url.Values{"action": {"checkcode"}})
	skipValue := "0"
	if skip {
		skipValue = "1"
	}
	var body []byte
	contentType := ""
	if step.smsMode == 0 {
		form := url.Values{"code": {code}, "skipSecondaryAuth": {skipValue}}
		body = []byte(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else {
		payload := map[string]any{
			"isPrevEffect":      false,
			"code":              code,
			"skipSecondaryAuth": skipValue,
			"taskId":            "",
			"authId":            step.AuthID,
		}
		body, _ = json.Marshal(payload)
		contentType = "application/json;charset=utf-8"
	}
	data, _, err := a.request(ctx, http.MethodPost, "/passport/v1/auth/sms", query, body, contentType)
	if err != nil {
		return authStep{}, err
	}
	var response struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return authStep{}, fmt.Errorf("parse SMS check: %w", err)
	}
	if response.Code != 0 {
		return authStep{}, fmt.Errorf("SMS check failed with code %d: %s", response.Code, response.Message)
	}
	return parseAuthStep(response.Data), nil
}

func (a *authClient) submitToken(ctx context.Context, service string, payload map[string]any) (authStep, error) {
	if service != "auth/token" && service != "auth/challenge" {
		return authStep{}, fmt.Errorf("unsupported token service %s", service)
	}
	if a.username != "" {
		payload["username"] = a.username
	}
	body, _ := json.Marshal(payload)
	data, _, err := a.request(ctx, http.MethodPost, "/passport/v1/"+service, withShared(nil), body, "application/json;charset=utf-8")
	if err != nil {
		return authStep{}, err
	}
	var response struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return authStep{}, fmt.Errorf("parse token response: %w", err)
	}
	if response.Code != 0 {
		return authStep{}, fmt.Errorf("token authentication failed with code %d: %s", response.Code, response.Message)
	}
	return parseAuthStep(response.Data), nil
}

func parseAuthStep(data authStepData) authStep {
	service := data.NextService
	chosen := selectAuthService(data.NextServiceList, service)
	if chosen != nil {
		switch {
		case service == "":
			service = chosen.AuthType
		case service == "auth/token":
			service = tokenAuthService(chosen)
		}
	}
	step := authStep{Service: service}
	if chosen != nil {
		step.AuthID = chosen.AuthID
	}
	if step.Service == "auth/sendSms" {
		step.Service = "auth/sms"
	}
	if step.Service == "" && step.AuthID != "" {
		step.Service = "auth/sms"
	}
	if step.Service == "auth/sms" {
		if step.AuthID == "" {
			step.smsMode = 0
		} else {
			step.smsMode = 1
		}
	}
	return step
}

func selectAuthService(list []authServiceInfo, service string) *authServiceInfo {
	for i := range list {
		if service != "" && list[i].AuthType == service {
			return &list[i]
		}
	}
	if len(list) > 0 {
		return &list[0]
	}
	return nil
}

func tokenAuthService(info *authServiceInfo) string {
	switch info.AuthType {
	case "auth/totp", "auth/radius", "auth/challenge":
		return info.AuthType
	case "auth/token":
		if info.SubType == "totp" {
			return "auth/totp"
		}
	}
	return "auth/token"
}

func (a *authClient) phoneNumber(ctx context.Context, authID string) ([]string, error) {
	query := withShared(nil)
	if authID != "" {
		query.Set("authId", authID)
	}
	data, _, err := a.request(ctx, http.MethodGet, "/passport/v1/public/phoneNumber", query, nil, "")
	if err != nil {
		return nil, err
	}
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			PhoneNumber         json.RawMessage `json:"phoneNumber"`
			MaskIdentifierValue string          `json:"maskIdentifierValue"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("parse phoneNumber: %w", err)
	}
	if response.Code != 0 {
		return nil, fmt.Errorf("phoneNumber failed with code %d: %s", response.Code, response.Message)
	}
	var numbers []string
	if len(response.Data.PhoneNumber) > 0 && string(response.Data.PhoneNumber) != "null" {
		if err := json.Unmarshal(response.Data.PhoneNumber, &numbers); err != nil {
			var single string
			if err := json.Unmarshal(response.Data.PhoneNumber, &single); err != nil {
				return nil, fmt.Errorf("parse phoneNumber value: %w", err)
			}
			if single != "" {
				numbers = []string{single}
			}
		}
	}
	if len(numbers) == 0 && response.Data.MaskIdentifierValue != "" {
		numbers = []string{response.Data.MaskIdentifierValue}
	}
	return numbers, nil
}

func (a *authClient) accessCheck(ctx context.Context) (authStep, error) {
	data, _, err := a.request(ctx, http.MethodGet, "/passport/v1/auth/accessCheck", withShared(nil), nil, "")
	if err != nil {
		return authStep{}, err
	}
	var response struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return authStep{}, fmt.Errorf("parse accessCheck: %w", err)
	}
	if response.Code != 0 {
		return authStep{}, fmt.Errorf("accessCheck failed with code %d: %s", response.Code, response.Message)
	}
	return parseAuthStep(response.Data), nil
}

func (a *authClient) requestStep(ctx context.Context, method string, step authStep, body []byte) (authStep, error) {
	query := withShared(nil)
	if step.AuthID != "" {
		query.Set("authId", step.AuthID)
	}
	contentType := ""
	if body != nil {
		contentType = "application/json;charset=utf-8"
	}
	data, _, err := a.request(ctx, method, "/passport/v1/"+step.Service, query, body, contentType)
	if err != nil {
		return authStep{}, err
	}
	var response struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return authStep{}, fmt.Errorf("parse %s: %w", step.Service, err)
	}
	if response.Code != 0 {
		return authStep{}, fmt.Errorf("%s failed with code %d: %s", step.Service, response.Code, response.Message)
	}
	return parseAuthStep(response.Data), nil
}

func (a *authClient) sendCustomSMS(ctx context.Context) error {
	payload := map[string]string{"isPrevEffect": "0", "taskId": ""}
	body, _ := json.Marshal(payload)
	data, _, err := a.request(ctx, http.MethodPost, "/passport/v1/auth/customSms", withShared(url.Values{"action": {"sendcustomsms"}}), body, "application/json;charset=utf-8")
	if err != nil {
		return err
	}
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips string `json:"tips"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("parse custom SMS send: %w", err)
	}
	if response.Code != 0 {
		return fmt.Errorf("custom SMS send failed with code %d: %s", response.Code, response.Message)
	}
	return nil
}

func (a *authClient) submitCustomSMSCode(ctx context.Context, code string, skip bool) (authStep, error) {
	skipValue := "0"
	if skip {
		skipValue = "1"
	}
	payload := map[string]any{
		"isPrevEffect":      false,
		"customCode":        code,
		"skipSecondaryAuth": skipValue,
		"taskId":            "",
	}
	body, _ := json.Marshal(payload)
	data, _, err := a.request(ctx, http.MethodPost, "/passport/v1/auth/customSms", withShared(url.Values{"action": {"checkcustomcode"}}), body, "application/json;charset=utf-8")
	if err != nil {
		return authStep{}, err
	}
	var response struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return authStep{}, fmt.Errorf("parse custom SMS check: %w", err)
	}
	if response.Code != 0 {
		return authStep{}, fmt.Errorf("custom SMS check failed with code %d: %s", response.Code, response.Message)
	}
	return parseAuthStep(response.Data), nil
}
