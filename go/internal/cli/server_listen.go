// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
	"github.com/spf13/cobra"
)

var (
	serverListenAddr     string
	serverListenCert     string
	serverListenKey      string
	serverListenHostname string
)

// serverListenCmd runs the HTTP/3-ALPN tunnel server that pairs with the
// Wave 20 HTTP3Tunnel client. Each incoming QUIC bidi stream carries a
// length-prefixed "host:port" target followed by the tunneled payload.
var serverListenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Run the HTTP/3-ALPN tunnel server (peer for --http3-server clients)",
	Long: `Run the HTTP/3-ALPN tunnel server.

Listens for QUIC connections with ALPN "h3" and bridges each bidi stream
to its requested TCP target. Pairs with "nowifi" clients invoked with
--http3-server pointing at this instance.

Certificate: pass --cert and --key to use an existing TLS cert (e.g. from
Let's Encrypt). Omit both to auto-generate a self-signed cert at startup.
A self-signed cert is sufficient for tunneling because the payload is
TLS-in-TLS end-to-end; the outer cert only has to look like a normal h3
server cert to middleboxes.

Examples:
  sudo nowifi server listen                                         # auto-cert, 0.0.0.0:443
  sudo nowifi server listen --addr 0.0.0.0:8443                     # non-privileged port
  nowifi server listen --cert fullchain.pem --key privkey.pem      # Let's Encrypt cert
  nowifi server listen --write-cert /tmp/self.crt --write-key /tmp/self.key --hostname h3.example.com
`,
	RunE: runServerListen,
}

var (
	serverListenWriteCert string
	serverListenWriteKey  string
	serverListenMode      string
)

func init() {
	serverListenCmd.Flags().StringVar(&serverListenAddr, "addr", "0.0.0.0:443",
		"UDP listen address (default: 0.0.0.0:443)")
	serverListenCmd.Flags().StringVar(&serverListenCert, "cert", "",
		"TLS certificate PEM file (auto-generate if omitted)")
	serverListenCmd.Flags().StringVar(&serverListenKey, "key", "",
		"TLS private key PEM file (auto-generate if omitted)")
	serverListenCmd.Flags().StringVar(&serverListenHostname, "hostname", "nowifi.local",
		"SNI hostname for auto-generated certs")
	serverListenCmd.Flags().StringVar(&serverListenWriteCert, "write-cert", "",
		"Write a fresh self-signed cert to this path and exit")
	serverListenCmd.Flags().StringVar(&serverListenWriteKey, "write-key", "",
		"Write a fresh self-signed key to this path and exit (use with --write-cert)")
	serverListenCmd.Flags().StringVar(&serverListenMode, "mode", "quic",
		`Server mode: "quic" (raw QUIC streams, HTTP3Tunnel #22 clients) or "h3" (HTTP/3 Extended CONNECT + WebTransport, MASQUE #27 + WT #28 clients)`)

	serverCmd.AddCommand(serverListenCmd)
}

func runServerListen(cmd *cobra.Command, _ []string) error {
	// Shortcut: --write-cert --write-key just materializes a cert pair.
	if serverListenWriteCert != "" || serverListenWriteKey != "" {
		if serverListenWriteCert == "" || serverListenWriteKey == "" {
			return fmt.Errorf("--write-cert and --write-key must be provided together")
		}
		if err := os.MkdirAll(filepath.Dir(serverListenWriteCert), 0o755); err != nil {
			return fmt.Errorf("mkdir cert dir: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(serverListenWriteKey), 0o700); err != nil {
			return fmt.Errorf("mkdir key dir: %w", err)
		}
		if err := tunnel.WriteSelfSignedCertFiles(serverListenHostname, serverListenWriteCert, serverListenWriteKey); err != nil {
			return fmt.Errorf("generate cert: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s (cert) and %s (key) for %s\n",
			serverListenWriteCert, serverListenWriteKey, serverListenHostname)
		return nil
	}

	cfg := tunnel.HTTP3ServerConfig{
		Listen:   serverListenAddr,
		CertFile: serverListenCert,
		KeyFile:  serverListenKey,
		Hostname: serverListenHostname,
	}

	if serverListenMode == "h3" {
		return runH3UnifiedServer(cmd, cfg)
	}

	srv, err := tunnel.ListenHTTP3Tunnel(cfg)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = srv.Close() }()

	fmt.Fprintf(cmd.OutOrStdout(), "nowifi HTTP/3 tunnel server listening on %s (ALPN h3, raw QUIC mode)\n", srv.Addr())
	fmt.Fprintln(cmd.OutOrStdout(), "Tip: use --mode h3 for MASQUE + WebTransport client support")
	if serverListenCert == "" {
		fmt.Fprintln(cmd.OutOrStdout(), "Using self-signed certificate (pass --cert/--key for a real cert)")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Fprintln(cmd.OutOrStdout(), "\nshutting down...")
	return nil
}

func runH3UnifiedServer(cmd *cobra.Command, cfg tunnel.HTTP3ServerConfig) error {
	srv, err := tunnel.ListenH3Unified(cfg)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = srv.Close() }()

	fmt.Fprintf(cmd.OutOrStdout(), "nowifi unified HTTP/3 server listening on %s\n", srv.Addr())
	fmt.Fprintf(cmd.OutOrStdout(), "Protocols: %v\n", srv.Protocols())
	if serverListenCert == "" {
		fmt.Fprintln(cmd.OutOrStdout(), "Using self-signed certificate (pass --cert/--key for a real cert)")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Fprintln(cmd.OutOrStdout(), "\nshutting down...")
	return nil
}
