# yonder

Share an app on an ad-hoc URL without opening a local port. The app embeds the
Go library, which opens the tunnel and returns a `net.Listener`. The URL dies
when the listener closes or the process exits. See [DESIGN.md](DESIGN.md).

## Try it locally

```bash
go run ./cmd/yonder-relay -token dev
```

Then share something through it, for example a terminal with
[yterm](https://github.com/vloothuis/yterm).

## Go library

```bash
go get github.com/vloothuis/yonder
```

## Swift SDK

`yonder-swift` holds a Swift package (`Yonder`, macOS 14 and iOS 17, no
dependencies) with the same model: `YonderListener.listen` opens the share,
`connections` yields visitors, and `YonderHTTPServer` serves HTTP over them.
Add it with SwiftPM:

```swift
.package(url: "https://github.com/vloothuis/yonder", branch: "main")
```

Its tests run against a built relay:

```bash
go build -o /tmp/yonder-relay ./cmd/yonder-relay
YONDER_RELAY_BIN=/tmp/yonder-relay swift test
```

## License

MIT
