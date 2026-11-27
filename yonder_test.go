package yonder_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/vloothuis/yonder"
	"github.com/vloothuis/yonder/internal/relay"
)

type env struct {
	relayURL string
	visitor  *http.Client
	dialer   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv, err := relay.New(relay.Config{
		BaseDomain: "share.localhost:" + strconv.Itoa(port),
		Scheme:     "http",
		Tokens:     []string{"secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(srv)
	hs.Listener.Close()
	hs.Listener = ln
	hs.Start()
	t.Cleanup(hs.Close)

	addr := ln.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return &env{
		relayURL: "http://" + addr,
		dialer:   dial,
		visitor: &http.Client{
			Transport:     &http.Transport{DialContext: dial},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// split returns the share origin and the code from a share URL.
func split(t *testing.T, shareURL string) (origin, code string) {
	t.Helper()
	u, err := url.Parse(shareURL)
	if err != nil {
		t.Fatal(err)
	}
	code = strings.TrimPrefix(u.Fragment, "c=")
	return u.Scheme + "://" + u.Host, code
}

func (e *env) auth(t *testing.T, origin, code, originHdr string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", origin+"/_yonder/auth", strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", originHdr)
	resp, err := e.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (e *env) login(t *testing.T, origin, code string) *http.Cookie {
	t.Helper()
	resp := e.auth(t, origin, code, origin)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("auth: %s", resp.Status)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-yonder" {
			if !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" {
				t.Fatalf("cookie attributes: %+v", c)
			}
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func (e *env) get(t *testing.T, u string, cookie *http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "text/html")
	if cookie != nil {
		req.AddCookie(cookie)
		req.AddCookie(&http.Cookie{Name: "app", Value: "1"})
	}
	resp, err := e.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func serve(t *testing.T, l *yonder.Listener, h http.Handler) {
	t.Helper()
	go http.Serve(l, h)
	t.Cleanup(func() { l.Close() })
}

func TestShareLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	l, err := yonder.Listen(ctx, yonder.Options{Relay: e.relayURL, Token: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "evil", Value: "x", Domain: "share.localhost"})
		http.SetCookie(w, &http.Cookie{Name: "__Host-yonder", Value: "x", Path: "/", Secure: true})
		http.SetCookie(w, &http.Cookie{Name: "ok", Value: "1"})
		io.WriteString(w, "hello remote="+r.RemoteAddr+" xff="+r.Header.Get("X-Forwarded-For")+" cookie="+r.Header.Get("Cookie")+" host="+r.Host)
	}))
	origin, code := split(t, l.URL())
	if l.Addr().String() != origin+"/" {
		t.Fatalf("Addr %q, URL %q", l.Addr(), l.URL())
	}

	resp, body := e.get(t, origin+"/", nil)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "access code") {
		t.Fatalf("gate: %s %q", resp.Status, body)
	}
	if r := e.auth(t, origin, "wrong", origin); r.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong code: %s", r.Status)
	}
	if r := e.auth(t, origin, code, "http://other.share.localhost"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin auth: %s", r.Status)
	}
	cookie := e.login(t, origin, code)

	resp, body = e.get(t, origin+"/", cookie)
	if resp.StatusCode != 200 {
		t.Fatalf("proxied: %s %q", resp.Status, body)
	}
	for _, want := range []string{"remote=127.0.0.1", "xff=127.0.0.1", "cookie=app=1", "host=" + strings.TrimPrefix(origin, "http://")} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q lacks %q", body, want)
		}
	}
	var names []string
	for _, c := range resp.Cookies() {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "ok" {
		t.Errorf("Set-Cookie passed through: %v", names)
	}

	// Cookie from this share is useless on another share.
	l2, err := yonder.Listen(ctx, yonder.Options{Relay: e.relayURL, Token: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "two") }))
	origin2, _ := split(t, l2.URL())
	if resp, _ := e.get(t, origin2+"/", cookie); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cookie crossed shares: %s", resp.Status)
	}

	l.Close()
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	if !errors.Is(l.Err(), net.ErrClosed) {
		t.Fatalf("Err: %v", l.Err())
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, _ := e.get(t, origin+"/", cookie)
		if resp.StatusCode == http.StatusNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("share still up after Close: %s", resp.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The other share is unaffected.
	if resp, _ := e.get(t, origin2+"/", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second share: %s", resp.Status)
	}
}

func TestWebSocketOriginCheck(t *testing.T) {
	e := newEnv(t)
	l, err := yonder.Listen(context.Background(), yonder.Options{Relay: e.relayURL, Token: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ctx := r.Context()
		typ, msg, err := c.Read(ctx)
		if err == nil {
			c.Write(ctx, typ, append([]byte("echo:"), msg...))
		}
		c.Close(websocket.StatusNormalClosure, "")
	}))
	origin, code := split(t, l.URL())
	cookie := e.login(t, origin, code)
	wsURL := "ws" + strings.TrimPrefix(origin, "http") + "/ws"

	dial := func(originHdr string) (*websocket.Conn, *http.Response, error) {
		h := http.Header{}
		h.Set("Origin", originHdr)
		h.Set("Cookie", cookie.Name+"="+cookie.Value)
		return websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{HTTPClient: e.visitor, HTTPHeader: h})
	}
	if _, resp, err := dial("http://aaaaaaaaaa.share.localhost"); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("sibling-origin websocket was not refused: %v", err)
	}
	c, _, err := dial(origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c.Write(ctx, websocket.MessageText, []byte("hi"))
	_, msg, err := c.Read(ctx)
	if err != nil || string(msg) != "echo:hi" {
		t.Fatalf("echo: %q %v", msg, err)
	}
	c.Close(websocket.StatusNormalClosure, "")
}

func TestApprove(t *testing.T) {
	e := newEnv(t)
	answers := make(chan bool, 2)
	answers <- false
	answers <- true
	var seen []yonder.Visitor
	l, err := yonder.Listen(context.Background(), yonder.Options{
		Relay: e.relayURL, Token: "secret",
		Approve: func(ctx context.Context, v yonder.Visitor) bool {
			seen = append(seen, v)
			return <-answers
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "in") }))
	origin, code := split(t, l.URL())
	if r := e.auth(t, origin, code, origin); r.StatusCode != http.StatusForbidden {
		t.Fatalf("denied visitor: %s", r.Status)
	}
	cookie := e.login(t, origin, code)
	if _, body := e.get(t, origin+"/", cookie); body != "in" {
		t.Fatalf("approved visitor got %q", body)
	}
	if len(seen) != 2 || seen[0].RemoteAddr != "127.0.0.1" {
		t.Fatalf("visitors: %+v", seen)
	}
}

func TestRejects(t *testing.T) {
	e := newEnv(t)
	if _, err := yonder.Listen(context.Background(), yonder.Options{Relay: e.relayURL, Token: "nope"}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := yonder.Listen(context.Background(), yonder.Options{Relay: "http://example.com", Token: "secret"}); err == nil {
		t.Fatal("plain http to a public host was allowed")
	}
}

func TestRelayLoss(t *testing.T) {
	e := newEnv(t)
	// A raw TCP proxy in front of the relay, so the test can cut the connection.
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	upstreamc := make(chan net.Conn, 1)
	go func() {
		c, err := pl.Accept()
		if err != nil {
			return
		}
		u, _ := e.dialer(context.Background(), "tcp", "")
		upstreamc <- u
		go io.Copy(u, c)
		io.Copy(c, u)
		c.Close()
	}()
	l, err := yonder.Listen(context.Background(), yonder.Options{Relay: "http://" + pl.Addr().String(), Token: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	(<-upstreamc).Close()
	select {
	case <-l.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Done not closed after relay loss")
	}
	if !errors.Is(l.Err(), yonder.ErrRelayClosed) {
		t.Fatalf("Err: %v", l.Err())
	}
	l.Close()
}

func TestWrongCodesLimitPerShare(t *testing.T) {
	e := newEnv(t)
	listen := func() *yonder.Listener {
		l, err := yonder.Listen(context.Background(), yonder.Options{Relay: e.relayURL, Token: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		serve(t, l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		return l
	}
	a, b := listen(), listen()
	originA, codeA := split(t, a.URL())
	originB, codeB := split(t, b.URL())
	for i := 0; i < 10; i++ {
		if r := e.auth(t, originA, "wrong", originA); r.StatusCode != http.StatusForbidden {
			t.Fatalf("wrong code %d: %s", i, r.Status)
		}
	}
	if r := e.auth(t, originA, "wrong", originA); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %s", r.Status)
	}
	// The right code still gets in, and other shares are not affected.
	e.login(t, originA, codeA)
	if r := e.auth(t, originB, "wrong", originB); r.StatusCode != http.StatusForbidden {
		t.Fatalf("other share: %s", r.Status)
	}
	e.login(t, originB, codeB)
}
