# yonder

Share a running app on an ad-hoc URL. The app embeds a Go library, opens the
tunnel itself, and serves HTTP over it. It never listens on a local port. The
URL dies when the app closes the listener or exits.

## Parts

- `yonder` (Go package): the client library. `yonder.Listen` returns a
  `net.Listener`.
- `internal/relay` and `cmd/yonder-relay`: the relay server.
- `internal/wire`: stream preamble encoding and protocol headers.
- `yonder-swift/`: the Swift SDK. `Package.swift` is at the repository root
  so SwiftPM can use the repository directly.
- [yterm](https://github.com/vloothuis/yterm), in its own repository, is the
  demo: it shares your terminal session in the browser, rendered with
  ghostty-web (libghostty compiled to WASM).

## Client API

```go
l, err := yonder.Listen(ctx, yonder.Options{Relay: "https://share.example.com", Token: tok})
fmt.Println(l.URL())    // https://k7f2q9xw3a.share.example.com/#c=<code>
http.Serve(l, handler)
l.Close()
```

`Listen` returns a concrete `*yonder.Listener`. `ctx` bounds only the
handshake. `Options.Approve(ctx, Visitor) bool`, if set, is called
concurrently from a library goroutine for each visitor after the code checks
out; `ctx` ends when the relay gives up waiting. `l.Done()` closes when the
relay connection ends and `l.Err()` says why. `Accept` returns
`net.ErrClosed` after `Close`. `Conn.RemoteAddr()` is the visitor's address.
There is no reconnect: a new connection means a new URL. `Listen` refuses a
plain-HTTP relay unless it is on a loopback or `*.localhost` host.

## Protocol

1. The client generates a 128-bit code. It sends
   `GET /_yonder/connect` to the relay as a WebSocket upgrade, with
   `Yonder-Version: 1`, `Authorization: Bearer <token>`,
   `Yonder-Code-Hash: <hex sha256(code)>` and optionally `Yonder-Approve: 1`.
   The relay never learns the code from the client.
2. The relay looks up the token by its hash, assigns a random share ID and
   returns `Yonder-Version`, `Yonder-URL` and, if requested, `Yonder-Approve: 1`
   in the upgrade response. `Listen` fails if approval was requested and not
   echoed.
3. Both sides run yamux over the WebSocket. The relay opens streams, the
   client accepts them. Each stream starts with a preamble: one type byte, a
   2-byte length and a JSON header (`remote_addr`, `user_agent`). The client
   reads preambles in per-stream goroutines with a deadline, so one stalled
   stream blocks nothing. Unknown types are closed.
   - `0x01`: one HTTP request (keep-alives are off), then plain HTTP/1.1.
   - `0x02`: one approval request; the client answers `{"allow":bool}`.
4. yamux keepalive runs every 10 seconds. When the session closes, the relay
   deletes the share at once.

## Relay

- Routes by Host. `<id>.<base>` is a share; anything else serves only
  `/_yonder/connect`.
- Gate: a request to a share without a valid session cookie gets a small page.
  The page reads the code from `location.hash`, posts it to `/_yonder/auth`,
  removes the hash and reloads. Without a hash it shows a form.
- `/_yonder/auth` requires the share's own `Origin` and compares
  `sha256(code)` with the stored hash in constant time. If the share requires
  approval, it then asks the client and waits up to 60 seconds. On success it
  sets `__Host-yonder` (`Secure`, `HttpOnly`, `SameSite=Lax`, no `Domain`)
  holding a random session token bound to that share, with a 12-hour idle
  timeout.
- Sibling shares are same-site, so `SameSite` does not isolate them. The relay
  therefore rejects WebSocket upgrades and unsafe methods whose `Origin` is
  not the share's own origin, and drops any `Set-Cookie` from an app that sets
  a `Domain` or uses the yonder cookie name.
- Proxy: `httputil.ReverseProxy` whose transport dials type-`0x01` streams. It
  keeps the inbound `Host`, removes the yonder cookie and incoming
  `X-Forwarded-*` and `Yonder-*` headers, then sets `X-Forwarded-For`,
  `-Proto` and `-Host`. WebSocket upgrades pass through.
- TLS: either a wildcard certificate from files, or plain HTTP behind a TLS
  proxy with `-scheme https` and `-trusted-proxy <CIDR>`, which makes the
  relay take the client IP from `X-Forwarded-For`. Local development uses
  `*.localhost`.

## Threat model

| Threat | Mitigation |
|---|---|
| Guessing a code | 128-bit code; wrong codes are rate-limited per source IP and globally, never per share (the share ID is public through DNS and SNI) |
| Code leaks into logs or Referer | Code lives in the URL fragment, which browsers never send; the gate removes it after use |
| Leaked link | `Approve` gives live per-visitor approval; sessions expire after 12 idle hours |
| Approval flood | Pending approvals are capped per share and per source IP |
| Hostile sibling share (cross-site WebSocket hijacking, login CSRF) | Origin check on upgrades, unsafe methods and the gate |
| Cookie tossing from a sibling share | `__Host-` cookie; app `Set-Cookie` with `Domain` or the yonder name is dropped |
| Strangers create tunnels | Bearer token per client, constant-time compare, share limit per token |
| Cookie valid on another share | Host-only cookie, session token bound to one share |
| Visitor forges identity or proxy headers | Relay strips them and sets its own |
| Relay sees the code at the gate, and all traffic | Accepted: TLS ends at the relay, and you run the relay |
| Malicious relay | It could approve-spoof or send arbitrary HTTP; the app must treat traffic as coming from the internet, as with any public URL |
| A slow visitor stalls the app | yamux flow control per stream; the demo drops slow viewers instead of blocking |
| Many streams exhaust the client | yamux accept backlog and a stream limit per share |
| Visitor IP hidden behind a TLS proxy | `-trusted-proxy` |
| Terminal escapes in an approval prompt | yterm strips control characters from visitor data |
| Stale route after a crash or sleep | Socket reset on exit; keepalive timeout otherwise |

## yterm demo

See [yterm](https://github.com/vloothuis/yterm).

## Not in v1

Revoking a single viewer before its session expires.

## Swift SDK (`yonder-swift/`)

A Swift package, `Yonder`, for macOS 14 and iOS 17, with no dependencies.

- **Transport:** `URLSessionWebSocketTask`, with the handshake headers set on
  the `URLRequest`. The share URL comes from the upgrade response headers.
- **yamux:** its own implementation of the spec, server side only: it accepts
  streams and never opens them. Rules that hashicorp/yamux enforces by ending
  the session:
  - The reader ACKs a stream as soon as its SYN arrives, before the app sees
    it, and accepts data before the ACK goes out.
  - FIN is sent exactly once per stream, after the stream's last data frame.
  - Flags are applied on data and window-update frames alike.
  - Data never exceeds the peer's window; the window starts at 256 KB and
    grows by each window-update length.
  - Frames for unknown streams are ignored; a bad SYN ends the session.
  - The byte stream spans WebSocket messages; only binary messages are valid.

  One writer task sends frames. Control frames (ACK, FIN, RST, window
  updates, ping replies) go first; each stream has at most one data frame
  queued, so ping replies never wait behind bulk data and the relay's
  10-second ping deadline holds. With nothing received for 25 seconds, the
  share ends.
- **API:**

  ```swift
  let listener = try await YonderListener.listen(relay: url, token: token, approve: { visitor in true })
  listener.url                 // link with the code
  for await conn in listener.connections { … }   // YonderConnection: read, write, close, visitor
  listener.close()
  ```

- **`YonderHTTPServer`:** a minimal HTTP/1.1 server over the connections, for
  apps without a server framework. It accepts one request per connection (the
  relay turns keep-alive off), with no request bodies over 64 KB and headers
  under 16 KB. A handler returns a body or an `AsyncStream<Data>`; streamed
  responses end with the connection and can send a keep-alive chunk when idle.
  The server keeps a read pending during a streamed response; when the visitor
  leaves, the relay sends FIN, the read ends and the response is cancelled.
  Writes on a connection are serialised.
- **Handshake:** redirects are refused, so the token never goes to another
  host. Plain http is allowed only for loopback and `*.localhost`. Refusals
  are mapped from the status code (400, 401, 429).

### Threats specific to the SDK

| Threat | Mitigation |
|---|---|
| A misbehaving relay floods streams or data | At most 256 open streams; each stream buffers at most its 256 KB window, and data beyond it ends the session |
| Malformed HTTP from the relay | Size limits on headers and bodies; a 10-second timeout for the request head; any parse error closes the stream |
| Viewers that never leave keep streams open | The streamed-response cancellation above; the app can cap concurrent viewers |
