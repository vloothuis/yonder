// Package yonder shares an in-process HTTP server on an ad-hoc URL through a
// yonder relay. The app never listens on a local port: Listen returns a
// net.Listener whose connections arrive over the relay tunnel.
//
//	l, err := yonder.Listen(ctx, yonder.Options{Relay: "https://share.example.com", Token: tok})
//	fmt.Println(l.URL())
//	http.Serve(l, handler)
//
// The URL stops working as soon as the listener is closed or the process exits.
package yonder

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/vloothuis/yonder/internal/wire"
)

// ErrRelayClosed is reported by Err and Accept when the relay connection ended
// without Close being called.
var ErrRelayClosed = errors.New("yonder: relay connection closed")

// Options configures Listen.
type Options struct {
	// Relay is the relay's base URL, for example "https://share.example.com".
	// Plain http is accepted only for loopback and *.localhost hosts.
	Relay string
	// Token authenticates this client to the relay.
	Token string
	// Approve, if set, is called for each visitor who presented the right
	// code. It runs concurrently on a library goroutine. ctx ends when the
	// relay stops waiting. Return true to let the visitor in.
	Approve func(ctx context.Context, v Visitor) bool
	// HTTPClient is used for the handshake. Defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// Visitor describes someone asking to open a share.
type Visitor struct {
	RemoteAddr string // as seen by the relay
	UserAgent  string // untrusted; sanitize before displaying
}

// Listener is a net.Listener for one share. It is safe for concurrent use.
//
// It owns one goroutine that accepts tunnel streams and one goroutine per
// stream while its preamble is read or an approval runs. Close stops them all
// and waits for them.
type Listener struct {
	ws      *websocket.Conn
	sess    *yamux.Session
	url     string
	addr    Addr
	approve func(context.Context, Visitor) bool

	conns  chan net.Conn
	done   chan struct{}
	closed chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	err       error
	wg        sync.WaitGroup
}

// Addr is the share's public URL without the code.
type Addr string

func (Addr) Network() string  { return "yonder" }
func (a Addr) String() string { return string(a) }

// Listen registers a new share with the relay. ctx bounds only the handshake;
// the share lives until Close or until the relay connection ends.
func Listen(ctx context.Context, opts Options) (*Listener, error) {
	u, err := url.Parse(opts.Relay)
	if err != nil {
		return nil, fmt.Errorf("yonder: relay URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		if !isLocalHost(u.Hostname()) {
			return nil, errors.New("yonder: plain http relay is only allowed on localhost")
		}
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("yonder: unsupported relay scheme %q", u.Scheme)
	}
	u.Path = wire.ConnectPath
	u.RawQuery, u.Fragment = "", ""

	code, err := randomCode()
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set(wire.HeaderVersion, wire.Version)
	h.Set("Authorization", "Bearer "+opts.Token)
	h.Set(wire.HeaderCodeHash, wire.HashCode(code))
	if opts.Approve != nil {
		h.Set(wire.HeaderApprove, "1")
	}

	ws, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient: opts.HTTPClient,
		HTTPHeader: h,
	})
	if err != nil {
		if resp != nil && resp.Body != nil {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("yonder: relay refused (%s): %s", resp.Status, strings.TrimSpace(string(msg)))
		}
		return nil, fmt.Errorf("yonder: connect: %w", err)
	}
	fail := func(msg string) (*Listener, error) {
		ws.Close(websocket.StatusPolicyViolation, msg)
		return nil, errors.New("yonder: " + msg)
	}
	if v := resp.Header.Get(wire.HeaderVersion); v != wire.Version {
		return fail(fmt.Sprintf("relay speaks protocol %q, want %q", v, wire.Version))
	}
	shareURL := resp.Header.Get(wire.HeaderURL)
	if shareURL == "" {
		return fail("relay sent no share URL")
	}
	if opts.Approve != nil && resp.Header.Get(wire.HeaderApprove) != "1" {
		return fail("relay does not enforce approval")
	}

	ws.SetReadLimit(4 << 20)
	nc := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard
	sess, err := yamux.Server(nc, cfg)
	if err != nil {
		return fail("yamux: " + err.Error())
	}

	l := &Listener{
		ws:      ws,
		sess:    sess,
		url:     strings.TrimSuffix(shareURL, "/") + "/#c=" + code,
		addr:    Addr(shareURL),
		approve: opts.Approve,
		conns:   make(chan net.Conn),
		done:    make(chan struct{}),
		closed:  make(chan struct{}),
	}
	l.wg.Add(1)
	go l.acceptLoop()
	return l, nil
}

// URL returns the link to hand out. It includes the access code in the
// fragment, which browsers never send to servers.
func (l *Listener) URL() string { return l.url }

// Addr returns the share URL without the code.
func (l *Listener) Addr() net.Addr { return l.addr }

// Done is closed when the share has ended, by Close or by losing the relay.
func (l *Listener) Done() <-chan struct{} { return l.done }

// Err returns nil while the share is live, net.ErrClosed after Close, and
// ErrRelayClosed if the relay connection ended first.
func (l *Listener) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Accept waits for the next visitor connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, l.Err()
	}
}

// Close ends the share. The relay drops the URL immediately.
func (l *Listener) Close() error {
	l.shutdown(net.ErrClosed)
	l.wg.Wait()
	return nil
}

func (l *Listener) shutdown(reason error) {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.err = reason
		l.mu.Unlock()
		close(l.done)
		l.sess.Close()
		l.ws.Close(websocket.StatusNormalClosure, "")
	})
}

func (l *Listener) acceptLoop() {
	defer l.wg.Done()
	for {
		st, err := l.sess.AcceptStream()
		if err != nil {
			l.shutdown(ErrRelayClosed)
			return
		}
		l.wg.Add(1)
		go l.handleStream(st)
	}
}

func (l *Listener) handleStream(st *yamux.Stream) {
	defer l.wg.Done()
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	p, err := wire.ReadPreamble(st)
	if err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})

	switch p.Type {
	case wire.TypeHTTP:
		c := &conn{Stream: st, remote: visitorAddr(p.RemoteAddr)}
		select {
		case l.conns <- c:
		case <-l.done:
			st.Close()
		}
	case wire.TypeApprove:
		l.handleApprove(st, p)
	default:
		st.Close()
	}
}

func (l *Listener) handleApprove(st *yamux.Stream, p wire.Preamble) {
	defer st.Close()
	if l.approve == nil {
		json.NewEncoder(st).Encode(wire.ApproveReply{Allow: false})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// The relay sends nothing more; a read returns when it gives up or the share ends.
		io.Copy(io.Discard, st)
		cancel()
	}()
	go func() {
		select {
		case <-l.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	allow := l.approve(ctx, Visitor{RemoteAddr: p.RemoteAddr, UserAgent: p.UserAgent})
	if ctx.Err() == nil {
		json.NewEncoder(st).Encode(wire.ApproveReply{Allow: allow})
	}
}

// conn is a visitor connection; RemoteAddr reports the visitor, not the relay.
type conn struct {
	*yamux.Stream
	remote net.Addr
}

func (c *conn) RemoteAddr() net.Addr { return c.remote }

type visitorAddr string

func (visitorAddr) Network() string  { return "tcp" }
func (a visitorAddr) String() string { return string(a) }

func randomCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func isLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
