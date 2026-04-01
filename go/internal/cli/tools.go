package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var toolsDownload bool

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "List required external tools and their install status",
	Long: `List required external tools and their install status.

Shows which tools are installed, missing, or auto-downloadable.
Use -d to automatically download missing tools that support it.`,
	Run: runTools,
}

func init() {
	toolsCmd.Flags().BoolVarP(&toolsDownload, "download", "d", false,
		"Auto-download missing tools that support it")
}

func runTools(cmd *cobra.Command, args []string) {
	fmt.Printf("\nnowifi — External Tools\n\n")

	// Tool registry — each tool with name, description, and install hint.
	type toolEntry struct {
		name        string
		desc        string
		installHint string
		downloadable bool
	}

	tools := []toolEntry{
		{"chisel", "HTTPS/WebSocket tunnel client", "go install github.com/jpillora/chisel@latest", true},
		{"hysteria", "QUIC tunnel (Hysteria2)", "go install github.com/apernet/hysteria/app/v2@latest", true},
		{"iodine", "DNS tunnel client", "brew install iodine", false},
		{"hans", "ICMP tunnel client", "brew install hans", false},
		{"hcxdumptool", "PMKID/handshake capture", "brew install hcxdumptool", false},
		{"hcxpcapngtool", "Convert captures to hashcat format", "brew install hcxtools", false},
		{"hashcat", "GPU-accelerated password cracking", "brew install hashcat", false},
		{"aircrack-ng", "CPU password cracking (fallback)", "brew install aircrack-ng", false},
		{"cloudflared", "Cloudflare tunnel / DoH proxy", "brew install cloudflare/cloudflare/cloudflared", true},
		{"bettercap", "Network MITM framework", "brew install bettercap", false},
		{"dnscrypt-proxy", "DNS encryption proxy", "brew install dnscrypt-proxy", false},
		{"reaver", "WPS PIN brute force", "brew install reaver", false},
	}

	for _, t := range tools {
		// TODO: check if tool is installed via toolchain.FindTool(t.name)
		status := "missing"
		if toolsDownload && t.downloadable {
			status = "(would download)"
		} else if t.installHint != "" {
			status = fmt.Sprintf("missing  install: %s", t.installHint)
		}
		fmt.Printf("  %-20s %s\n", t.name, status)
		if t.desc != "" {
			fmt.Printf("  %-20s   %s\n", "", t.desc)
		}
	}

	fmt.Println()
}
