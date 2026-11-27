// Package relay implements the yonder relay: it accepts tunnel connections
// from clients, gives each one an ad-hoc subdomain, gates visitors with the
// share code and proxies their HTTP traffic into the tunnel.
package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/vloothuis/yonder/internal/wire"
)

const (
	cookieName      = "__Host-yonder"
	authPath        = "/_yonder/auth"
	gateJSPath      = "/_yonder/gate.js"
	reservedPrefix  = "/_yonder/"
	approvalTimeout = 60 * time.Second
	maxPendingShare = 8
	maxSessions     = 1000
)

// Config configures a relay.
type Config struct {
	// BaseDomain is the host (with port, if not default) under which shares
	// get subdomains, for example "share.example.com" or "share.localhost:8080".
	BaseDomain string
	// Scheme is the public scheme visitors use: "https", or "http" for a
	// *.localhost base domain.
	Scheme string
	// Tokens are the accepted client tokens.
	Tokens []string
	// MaxSharesPerToken limits concurrent shares per token. Zero means 20.
	MaxSharesPerToken int
	// TrustedProxies are the networks whose X-Forwarded-For is believed.
	TrustedProxies []netip.Prefix
	// SessionIdleTTL ends visitor sessions after this much inactivity. Zero means 12h.
	SessionIdleTTL time.Duration
	Logger         *slog.Logger
}

// Server is the relay. It implements http.Handler.
type Server struct {
	cfg    Config
	base   string
	tokens map[[32]byte]bool
	log    *slog.Logger

	mu      sync.Mutex
	shares  map[string]*share
	byToken map[[32]byte]int
}

// New validates cfg and returns a relay.
func New(cfg Config) (*Server, error) {
	base := strings.ToLower(strings.TrimSpace(cfg.BaseDomain))
	if base == "" {
		return nil, errors.New("relay: BaseDomain is required")
	}
	host := base
	if h, _, err := net.SplitHostPort(base); err == nil {
		host = h
	}
	switch cfg.Scheme {
	case "https":
	case "http":
		if host != "localhost" && !strings.HasSuffix(host, ".localhost") {
			return nil, errors.New("relay: http scheme is only allowed for a *.localhost base domain")
		}
	default:
		return nil, fmt.Errorf("relay: Scheme must be http or https, not %q", cfg.Scheme)
	}
	if len(cfg.Tokens) == 0 {
		return nil, errors.New("relay: at least one token is required")
	}
	if cfg.MaxSharesPerToken == 0 {
		cfg.MaxSharesPerToken = 20
	}
	if cfg.SessionIdleTTL == 0 {
		cfg.SessionIdleTTL = 12 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:     cfg,
		base:    base,
		tokens:  map[[32]byte]bool{},
		log:     cfg.Logger,
		shares:  map[string]*share{},
		byToken: map[[32]byte]int{},
	}
	for _, t := range cfg.Tokens {
		if t == "" {
			return nil, errors.New("relay: empty token")
		}
		s.tokens[sha256.Sum256([]byte(t))] = true
	}
	return s, nil
}

// ServeHTTP routes share subdomains to their share and everything else to the
// connect endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if id, ok := strings.CutSuffix(host, "."+s.base); ok && validID(id) {
		s.mu.Lock()
		sh := s.shares[id]
		s.mu.Unlock()
		if sh == nil {
			http.Error(w, "This share has ended.", http.StatusNotFound)
			return
		}
		sh.serve(w, r)
		return
	}
	if r.URL.Path == wire.ConnectPath {
		s.handleConnect(w, r)
		return
	}
	http.Error(w, "yonder relay", http.StatusNotFound)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(wire.HeaderVersion) != wire.Version {
		http.Error(w, "unsupported protocol version, want "+wire.Version, http.StatusBadRequest)
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokHash := sha256.Sum256([]byte(tok))
	if !ok || !s.tokens[tokHash] {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	codeHash, err := hex.DecodeString(r.Header.Get(wire.HeaderCodeHash))
	if err != nil || len(codeHash) != sha256.Size {
		http.Error(w, "invalid code hash", http.StatusBadRequest)
		return
	}
	approve := r.Header.Get(wire.HeaderApprove) == "1"

	sh := &share{
		srv:      s,
		codeHash: codeHash,
		approve:  approve,
		sessions: map[string]time.Time{},
		pending:  map[string]bool{},
		wrong:    newLimiter(10, time.Minute, 10000),
	}
	s.mu.Lock()
	if s.byToken[tokHash] >= s.cfg.MaxSharesPerToken {
		s.mu.Unlock()
		http.Error(w, "too many shares for this token", http.StatusTooManyRequests)
		return
	}
	for {
		sh.id = newID()
		if _, taken := s.shares[sh.id]; !taken {
			break
		}
	}
	sh.host = sh.id + "." + s.base
	sh.origin = s.cfg.Scheme + "://" + sh.host
	// Reserve the slot now so concurrent connects respect the limit.
	s.shares[sh.id] = nil
	s.byToken[tokHash]++
	s.mu.Unlock()
	release := func() {
		s.mu.Lock()
		delete(s.shares, sh.id)
		s.byToken[tokHash]--
		if s.byToken[tokHash] == 0 {
			delete(s.byToken, tokHash)
		}
		s.mu.Unlock()
	}

	w.Header().Set(wire.HeaderVersion, wire.Version)
	w.Header().Set(wire.HeaderURL, sh.origin+"/")
	if approve {
		w.Header().Set(wire.HeaderApprove, "1")
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		release()
		return
	}
	ws.SetReadLimit(4 << 20)
	nc := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard
	sess, err := yamux.Client(nc, cfg)
	if err != nil {
		release()
		ws.Close(websocket.StatusInternalError, "yamux")
		return
	}
	sh.sess = sess
	sh.initProxy()

	s.mu.Lock()
	s.shares[sh.id] = sh
	s.mu.Unlock()
	s.log.Info("share opened", "id", sh.id, "approve", approve, "client", s.clientIP(r))

	select {
	case <-sess.CloseChan():
	case <-r.Context().Done():
	}
	release()
	sess.Close()
	sh.transport.CloseIdleConnections()
	ws.Close(websocket.StatusNormalClosure, "")
	s.log.Info("share closed", "id", sh.id)
}

// clientIP returns the visitor's IP, trusting X-Forwarded-For only from TrustedProxies.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(ip) {
			xff := r.Header.Values("X-Forwarded-For")
			if len(xff) == 0 {
				break
			}
			parts := strings.Split(xff[len(xff)-1], ",")
			if fwd, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return fwd.Unmap().String()
			}
			break
		}
	}
	return ip.String()
}

type share struct {
	srv      *Server
	id       string
	host     string
	origin   string
	codeHash []byte
	approve  bool
	wrong    *limiter // wrong codes per client network

	sess      *yamux.Session
	transport *http.Transport
	proxy     *httputil.ReverseProxy

	mu       sync.Mutex
	sessions map[string]time.Time // session token -> last seen
	pending  map[string]bool      // client IP -> approval in progress
}

type visitorKey struct{}

func (sh *share) initProxy() {
	sh.transport = &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			st, err := sh.sess.OpenStream()
			if err != nil {
				return nil, err
			}
			p, _ := ctx.Value(visitorKey{}).(wire.Preamble)
			p.Type = wire.TypeHTTP
			if err := wire.WritePreamble(st, p); err != nil {
				st.Close()
				return nil, err
			}
			return st, nil
		},
		ResponseHeaderTimeout: 0,
		IdleConnTimeout:       30 * time.Second,
	}
	scheme := sh.srv.cfg.Scheme
	sh.proxy = &httputil.ReverseProxy{
		Transport: sh.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: pr.In.Host})
			pr.Out.Host = pr.In.Host
			stripYonderCookie(pr.Out)
			for k := range pr.Out.Header {
				if strings.HasPrefix(k, "Yonder-") {
					pr.Out.Header.Del(k)
				}
			}
			pr.Out.Header.Set("X-Forwarded-For", sh.srv.clientIP(pr.In))
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", scheme)
		},
		ModifyResponse: func(resp *http.Response) error {
			filterSetCookies(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "The shared app did not answer.", http.StatusBadGateway)
		},
	}
}

func (sh *share) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case authPath:
		sh.handleAuth(w, r)
		return
	case gateJSPath:
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, gateJS)
		return
	}
	if strings.HasPrefix(r.URL.Path, reservedPrefix) {
		http.NotFound(w, r)
		return
	}
	if !sh.validSession(r) {
		sh.serveGate(w, r)
		return
	}
	if !sh.originAllowed(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	ip := sh.srv.clientIP(r)
	p := wire.Preamble{RemoteAddr: ip, UserAgent: truncate(r.UserAgent(), 256)}
	sh.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), visitorKey{}, p)))
}

// originAllowed rejects WebSocket upgrades and unsafe methods coming from any
// other origin, including sibling shares, which browsers treat as same-site.
func (sh *share) originAllowed(r *http.Request) bool {
	safe := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
	upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if safe && !upgrade {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Browsers always send Origin on these requests; its absence means a
		// non-browser client, which already holds the session cookie.
		return r.Header.Get("Sec-Fetch-Site") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	return strings.EqualFold(origin, sh.origin)
}

func (sh *share) validSession(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	ttl := sh.srv.cfg.SessionIdleTTL
	sh.mu.Lock()
	defer sh.mu.Unlock()
	seen, ok := sh.sessions[c.Value]
	if !ok {
		return false
	}
	now := time.Now()
	if now.Sub(seen) > ttl {
		delete(sh.sessions, c.Value)
		return false
	}
	sh.sessions[c.Value] = now
	return true
}

func (sh *share) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.EqualFold(r.Header.Get("Origin"), sh.origin) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	ip := sh.srv.clientIP(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The right code always gets in, so wrong guesses cannot lock anyone out.
	// Wrong guesses are limited per share and client network.
	sum := sha256.Sum256([]byte(r.PostForm.Get("code")))
	if subtle.ConstantTimeCompare(sum[:], sh.codeHash) != 1 {
		if !sh.wrong.hit(clientNet(ip)) {
			http.Error(w, "Too many wrong codes. Try again in a minute.", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "Wrong code.", http.StatusForbidden)
		return
	}
	if sh.approve {
		allowed, err := sh.askApproval(r.Context(), ip, r.UserAgent())
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if !allowed {
			http.Error(w, "The owner did not let you in.", http.StatusForbidden)
			return
		}
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	val := base64.RawURLEncoding.EncodeToString(tok)
	sh.mu.Lock()
	if len(sh.sessions) >= maxSessions {
		sh.pruneSessions()
	}
	sh.sessions[val] = time.Now()
	sh.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    val,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// pruneSessions drops expired sessions, and the oldest one if none expired.
// Callers hold sh.mu.
func (sh *share) pruneSessions() {
	ttl := sh.srv.cfg.SessionIdleTTL
	var oldest string
	var oldestT time.Time
	for k, t := range sh.sessions {
		if time.Since(t) > ttl {
			delete(sh.sessions, k)
			continue
		}
		if oldest == "" || t.Before(oldestT) {
			oldest, oldestT = k, t
		}
	}
	if len(sh.sessions) >= maxSessions {
		delete(sh.sessions, oldest)
	}
}

var errBusy = errors.New("Too many people are waiting for approval. Try again later.")

func (sh *share) askApproval(ctx context.Context, ip, ua string) (bool, error) {
	sh.mu.Lock()
	if sh.pending[ip] {
		sh.mu.Unlock()
		return false, errors.New("You already have a pending request.")
	}
	if len(sh.pending) >= maxPendingShare {
		sh.mu.Unlock()
		return false, errBusy
	}
	sh.pending[ip] = true
	sh.mu.Unlock()
	defer func() {
		sh.mu.Lock()
		delete(sh.pending, ip)
		sh.mu.Unlock()
	}()

	st, err := sh.sess.OpenStream()
	if err != nil {
		return false, errors.New("The share is not reachable.")
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(ctx, approvalTimeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		st.Close()
	}()
	if err := wire.WritePreamble(st, wire.Preamble{Type: wire.TypeApprove, RemoteAddr: ip, UserAgent: truncate(ua, 256)}); err != nil {
		return false, errors.New("The share is not reachable.")
	}
	var reply wire.ApproveReply
	if err := json.NewDecoder(io.LimitReader(st, 256)).Decode(&reply); err != nil {
		if ctx.Err() != nil {
			return false, nil
		}
		return false, errors.New("The share is not reachable.")
	}
	return reply.Allow, nil
}

func (sh *share) serveGate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Error(w, "This share needs its access code.", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, gateHTML)
}

// stripYonderCookie removes the relay's session cookie before a request reaches the app.
func stripYonderCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	var kept []string
	for _, c := range cookies {
		if c.Name != cookieName {
			kept = append(kept, c.String())
		}
	}
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}

// filterSetCookies drops app cookies that could reach other shares or shadow the relay cookie.
func filterSetCookies(h http.Header) {
	lines := h.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Domain != "" || strings.EqualFold(c.Name, cookieName) || strings.HasPrefix(strings.ToLower(c.Name), "__host-yonder") {
			continue
		}
		h.Add("Set-Cookie", line)
	}
}

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func newID() string {
	b := make([]byte, 7)
	rand.Read(b)
	return idEncoding.EncodeToString(b)[:10]
}

func validID(id string) bool {
	if len(id) != 10 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// limiter counts failures per key in fixed windows. It tracks at most maxKeys
// keys per window; once full, new keys count as over the limit.
type limiter struct {
	perKey  int
	window  time.Duration
	maxKeys int

	mu     sync.Mutex
	start  time.Time
	counts map[string]int
}

func newLimiter(perKey int, window time.Duration, maxKeys int) *limiter {
	return &limiter{perKey: perKey, window: window, maxKeys: maxKeys, counts: map[string]int{}}
}

// hit records a failure for key and reports whether key is still within the limit.
func (l *limiter) hit(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.start) > l.window {
		l.start = time.Now()
		l.counts = map[string]int{}
	}
	n, ok := l.counts[key]
	if !ok && len(l.counts) >= l.maxKeys {
		return false
	}
	l.counts[key] = n + 1
	return n < l.perKey
}

// clientNet groups IPv6 clients by /64, since one host often holds a whole /64.
func clientNet(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is4() {
		return ip
	}
	p, _ := a.Prefix(64)
	return p.String()
}

//go:embed gate.html
var gateHTML string

//go:embed gate.js
var gateJS string
