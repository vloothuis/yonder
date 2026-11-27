// Command yonder-relay runs a yonder relay.
//
// Local development:
//
//	yonder-relay -listen :8787 -base share.localhost:8787 -scheme http -token dev
//
// Production behind a wildcard certificate:
//
//	yonder-relay -listen :443 -base share.example.com -tls-cert c.pem -tls-key k.pem -tokens-file tokens
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/vloothuis/yonder/internal/relay"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var (
		listen     = flag.String("listen", ":8787", "address to listen on")
		base       = flag.String("base", "share.localhost:8787", "base domain for share subdomains, with port if not default")
		scheme     = flag.String("scheme", "", "public scheme: https or http (default https, or http for a *.localhost base)")
		tlsCert    = flag.String("tls-cert", "", "wildcard certificate file")
		tlsKey     = flag.String("tls-key", "", "certificate key file")
		tokensFile = flag.String("tokens-file", "", "file with one client token per line")
		maxShares  = flag.Int("max-shares", 20, "concurrent shares per token")
		tokens     listFlag
		proxies    listFlag
	)
	flag.Var(&tokens, "token", "accepted client token (repeatable; also $YONDER_TOKENS, comma-separated)")
	flag.Var(&proxies, "trusted-proxy", "CIDR whose X-Forwarded-For is trusted (repeatable)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if env := os.Getenv("YONDER_TOKENS"); env != "" {
		tokens = append(tokens, strings.Split(env, ",")...)
	}
	if *tokensFile != "" {
		ft, err := readLines(*tokensFile)
		if err != nil {
			fatal(err)
		}
		tokens = append(tokens, ft...)
	}
	if *scheme == "" {
		*scheme = "https"
		if *tlsCert == "" && strings.Contains(strings.Split(*base, ":")[0], "localhost") {
			*scheme = "http"
		}
	}
	var prefixes []netip.Prefix
	for _, p := range proxies {
		pf, err := netip.ParsePrefix(p)
		if err != nil {
			fatal(fmt.Errorf("-trusted-proxy %q: %w", p, err))
		}
		prefixes = append(prefixes, pf)
	}

	srv, err := relay.New(relay.Config{
		BaseDomain:        *base,
		Scheme:            *scheme,
		Tokens:            tokens,
		MaxSharesPerToken: *maxShares,
		TrustedProxies:    prefixes,
		Logger:            log,
	})
	if err != nil {
		fatal(err)
	}

	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("relay listening", "addr", *listen, "base", *base, "scheme", *scheme)
	if *tlsCert != "" {
		err = hs.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = hs.ListenAndServe()
	}
	fatal(err)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "yonder-relay:", err)
	os.Exit(1)
}
