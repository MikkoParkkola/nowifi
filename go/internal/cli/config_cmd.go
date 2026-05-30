// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	cfgpkg "github.com/MikkoParkkola/nowifi/internal/config"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/server"
	"github.com/spf13/cobra"
)

var configShowSecrets bool

type configEntry struct {
	Key    string
	Secret bool
	Get    func(*cfgpkg.Config) string
	Set    func(*cfgpkg.Config, string) error
	Unset  func(*cfgpkg.Config)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View and edit saved nowifi defaults",
	Long: `View and edit saved nowifi defaults.

Values are stored in ~/.nowifi/config.json and are reused when matching CLI
flags are not explicitly provided.`,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved config values",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cfgpkg.Load()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Config: %s\n\n", cfgpkg.Path())
		for _, entry := range sortedConfigEntries() {
			value := entry.Get(cfg)
			if entry.Secret && !configShowSecrets {
				value = redactConfigValue(value)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  %-18s %s\n", entry.Key, value)
		}
		return nil
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Print one config value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		entry, ok := lookupConfigEntry(args[0])
		if !ok {
			return unknownConfigKey(args[0])
		}
		cfg, err := cfgpkg.Load()
		if err != nil {
			return err
		}
		value := entry.Get(cfg)
		if entry.Secret && !configShowSecrets {
			value = redactConfigValue(value)
		}
		fmt.Fprintln(cmd.OutOrStdout(), value)
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set one config value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		entry, ok := lookupConfigEntry(args[0])
		if !ok {
			return unknownConfigKey(args[0])
		}
		cfg, err := cfgpkg.Load()
		if err != nil {
			return err
		}
		if err := entry.Set(cfg, args[1]); err != nil {
			return err
		}
		if err := cfgpkg.Save(cfg); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Set %s\n", entry.Key)
		return nil
	},
}

var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "Unset one config value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		entry, ok := lookupConfigEntry(args[0])
		if !ok {
			return unknownConfigKey(args[0])
		}
		cfg, err := cfgpkg.Load()
		if err != nil {
			return err
		}
		entry.Unset(cfg)
		if err := cfgpkg.Save(cfg); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Unset %s\n", entry.Key)
		return nil
	},
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the config file path",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(cmd.OutOrStdout(), cfgpkg.Path())
	},
}

func init() {
	configCmd.PersistentFlags().BoolVar(&configShowSecrets, "show-secrets", false, "Show token-bearing values without redaction")
	configCmd.AddCommand(configListCmd, configGetCmd, configSetCmd, configUnsetCmd, configPathCmd)
}

func sortedConfigEntries() []configEntry {
	entries := configEntries()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

func lookupConfigEntry(key string) (configEntry, bool) {
	key = strings.TrimSpace(strings.ToLower(key))
	for _, entry := range configEntries() {
		if entry.Key == key {
			return entry, true
		}
		if entry.Key == "cf_workers_url" && key == "cf_workers" {
			return entry, true
		}
	}
	return configEntry{}, false
}

func unknownConfigKey(key string) error {
	keys := make([]string, 0, len(configEntries()))
	for _, entry := range sortedConfigEntries() {
		keys = append(keys, entry.Key)
	}
	return fmt.Errorf("unknown config key %q; valid keys: %s", key, strings.Join(keys, ", "))
}

func redactConfigValue(value string) string {
	if value == "" {
		return ""
	}
	return server.RedactURLSecrets(value)
}

func configEntries() []configEntry {
	defaults := cfgpkg.Defaults()
	stringEntry := func(key, _ string, get func(*cfgpkg.Config) string, set func(*cfgpkg.Config, string), unset func(*cfgpkg.Config), validate func(string) (string, error)) configEntry {
		return configEntry{
			Key: key,
			Get: get,
			Set: func(cfg *cfgpkg.Config, value string) error {
				value = strings.TrimSpace(value)
				if validate != nil {
					normalized, err := validate(value)
					if err != nil {
						return err
					}
					value = normalized
				}
				set(cfg, value)
				return nil
			},
			Unset: unset,
		}
	}

	boolEntry := func(key, _ string, get func(*cfgpkg.Config) bool, set func(*cfgpkg.Config, bool), unset func(*cfgpkg.Config)) configEntry {
		return configEntry{
			Key: key,
			Get: func(cfg *cfgpkg.Config) string {
				return strconv.FormatBool(get(cfg))
			},
			Set: func(cfg *cfgpkg.Config, value string) error {
				parsed, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("%s must be a boolean", key)
				}
				set(cfg, parsed)
				return nil
			},
			Unset: unset,
		}
	}

	cfWorkersEntry := stringEntry("cf_workers_url", "Authenticated Cloudflare Workers proxy URL", func(c *cfgpkg.Config) string {
		if c.CFWorkersURL != "" {
			return c.CFWorkersURL
		}
		return c.CFWorkers
	}, func(c *cfgpkg.Config, v string) {
		c.CFWorkersURL = v
		c.CFWorkers = v
	}, func(c *cfgpkg.Config) {
		c.CFWorkersURL = ""
		c.CFWorkers = ""
	}, validateCFWorkersConfigURL)
	cfWorkersEntry.Secret = true

	return []configEntry{
		stringEntry("connectip_server", "CONNECT-IP proxy URL", func(c *cfgpkg.Config) string { return c.ConnectIPServer }, func(c *cfgpkg.Config, v string) { c.ConnectIPServer = v }, func(c *cfgpkg.Config) { c.ConnectIPServer = "" }, platform.ValidateURL),
		cfWorkersEntry,
		stringEntry("dns_domain", "DNS tunnel domain", func(c *cfgpkg.Config) string { return c.DNSDomain }, func(c *cfgpkg.Config, v string) { c.DNSDomain = v }, func(c *cfgpkg.Config) { c.DNSDomain = "" }, platform.ValidateDomain),
		stringEntry("doq_server", "DNS-over-QUIC resolver host:port", func(c *cfgpkg.Config) string { return c.DoQServer }, func(c *cfgpkg.Config, v string) { c.DoQServer = v }, func(c *cfgpkg.Config) { c.DoQServer = "" }, platform.ValidateServerAddr),
		stringEntry("ech_config_list", "Base64 ECHConfigList", func(c *cfgpkg.Config) string { return c.ECHConfigList }, func(c *cfgpkg.Config, v string) { c.ECHConfigList = v }, func(c *cfgpkg.Config) { c.ECHConfigList = "" }, nil),
		stringEntry("ech_server", "ECH-capable proxy URL", func(c *cfgpkg.Config) string { return c.ECHServer }, func(c *cfgpkg.Config, v string) { c.ECHServer = v }, func(c *cfgpkg.Config) { c.ECHServer = "" }, platform.ValidateURL),
		stringEntry("grpc_server", "gRPC tunnel server URL", func(c *cfgpkg.Config) string { return c.GRPCServer }, func(c *cfgpkg.Config, v string) { c.GRPCServer = v }, func(c *cfgpkg.Config) { c.GRPCServer = "" }, platform.ValidateURL),
		stringEntry("h2_proxy", "HTTP/2 CONNECT proxy URL", func(c *cfgpkg.Config) string { return c.H2Proxy }, func(c *cfgpkg.Config, v string) { c.H2Proxy = v }, func(c *cfgpkg.Config) { c.H2Proxy = "" }, platform.ValidateURL),
		stringEntry("http3_server", "HTTP/3 tunnel URL or host:port", func(c *cfgpkg.Config) string { return c.HTTP3Server }, func(c *cfgpkg.Config, v string) { c.HTTP3Server = v }, func(c *cfgpkg.Config) { c.HTTP3Server = "" }, validateURLOrServerAddr),
		stringEntry("icmp_server", "ICMP tunnel server IP", func(c *cfgpkg.Config) string { return c.ICMPServer }, func(c *cfgpkg.Config, v string) { c.ICMPServer = v }, func(c *cfgpkg.Config) { c.ICMPServer = "" }, platform.ValidateIP),
		stringEntry("interface", "WiFi interface", func(c *cfgpkg.Config) string { return c.Interface }, func(c *cfgpkg.Config, v string) { c.Interface = v }, func(c *cfgpkg.Config) { c.Interface = defaults.Interface }, platform.ValidateInterface),
		stringEntry("masque_server", "MASQUE proxy URL", func(c *cfgpkg.Config) string { return c.MASQUEServer }, func(c *cfgpkg.Config, v string) { c.MASQUEServer = v }, func(c *cfgpkg.Config) { c.MASQUEServer = "" }, platform.ValidateURL),
		stringEntry("ntp_server", "NTP tunnel server IP", func(c *cfgpkg.Config) string { return c.NTPServer }, func(c *cfgpkg.Config, v string) { c.NTPServer = v }, func(c *cfgpkg.Config) { c.NTPServer = "" }, platform.ValidateIP),
		stringEntry("quic_server", "QUIC/Hysteria2 server address", func(c *cfgpkg.Config) string { return c.QUICServer }, func(c *cfgpkg.Config, v string) { c.QUICServer = v }, func(c *cfgpkg.Config) { c.QUICServer = "" }, platform.ValidateServerAddr),
		stringEntry("sse_server", "SSE relay server URL", func(c *cfgpkg.Config) string { return c.SSEServer }, func(c *cfgpkg.Config, v string) { c.SSEServer = v }, func(c *cfgpkg.Config) { c.SSEServer = "" }, platform.ValidateURL),
		stringEntry("tunnel_server", "Chisel tunnel endpoint URL", func(c *cfgpkg.Config) string { return c.TunnelServer }, func(c *cfgpkg.Config, v string) { c.TunnelServer = v }, func(c *cfgpkg.Config) { c.TunnelServer = "" }, platform.ValidateURL),
		stringEntry("vpn_server", "VPN-on-port-53 server host:port", func(c *cfgpkg.Config) string { return c.VPNServer }, func(c *cfgpkg.Config, v string) { c.VPNServer = v }, func(c *cfgpkg.Config) { c.VPNServer = "" }, platform.ValidateServerAddr),
		stringEntry("ws_server", "WebSocket tunnel server URL", func(c *cfgpkg.Config) string { return c.WSServer }, func(c *cfgpkg.Config, v string) { c.WSServer = v }, func(c *cfgpkg.Config) { c.WSServer = "" }, platform.ValidateURL),
		stringEntry("wt_server", "WebTransport tunnel server URL", func(c *cfgpkg.Config) string { return c.WTServer }, func(c *cfgpkg.Config, v string) { c.WTServer = v }, func(c *cfgpkg.Config) { c.WTServer = "" }, platform.ValidateURL),
		boolEntry("auto_login", "Enable saved portal login automation", func(c *cfgpkg.Config) bool { return c.AutoLogin }, func(c *cfgpkg.Config, v bool) { c.AutoLogin = v }, func(c *cfgpkg.Config) { c.AutoLogin = defaults.AutoLogin }),
		boolEntry("stealth", "Enable randomized probe timing by default", func(c *cfgpkg.Config) bool { return c.Stealth }, func(c *cfgpkg.Config, v bool) { c.Stealth = v }, func(c *cfgpkg.Config) { c.Stealth = defaults.Stealth }),
		boolEntry("report_failures", "Offer to file a GitHub issue (with consent) when nowifi cannot bypass a network", func(c *cfgpkg.Config) bool { return c.ReportFailures }, func(c *cfgpkg.Config, v bool) { c.ReportFailures = v }, func(c *cfgpkg.Config) { c.ReportFailures = defaults.ReportFailures }),
	}
}

func validateURLOrServerAddr(value string) (string, error) {
	if normalized, err := platform.ValidateURL(value); err == nil {
		return normalized, nil
	}
	return platform.ValidateServerAddr(value)
}

func validateCFWorkersConfigURL(value string) (string, error) {
	normalized, err := platform.ValidateURL(value)
	if err != nil {
		return "", err
	}
	if !cfWorkersURLHasToken(normalized) {
		return "", fmt.Errorf("missing nowifi_token query parameter; recreate the Worker with `nowifi server create -p cloudflare`")
	}
	return normalized, nil
}
