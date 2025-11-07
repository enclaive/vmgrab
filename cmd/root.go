package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version information (set by main package)
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

// SetVersion sets version information from main package
func SetVersion(v, c, b string) {
	version = v
	commit = c
	buildTime = b
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, buildTime)
}

var rootCmd = &cobra.Command{
	Use:   "vmgrab",
	Short: "KVM VM Memory Dump Attack Demo Tool",
	Long: `
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██╗  ██╗██╗   ██╗███╗   ███╗    ███╗   ███╗███████╗███╗   ███╗██████╗ ║
║   ██║ ██╔╝██║   ██║████╗ ████║    ████╗ ████║██╔════╝████╗ ████║██╔══██╗║
║   █████╔╝ ██║   ██║██╔████╔██║    ██╔████╔██║█████╗  ██╔████╔██║██║  ██║║
║   ██╔═██╗ ╚██╗ ██╔╝██║╚██╔╝██║    ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║  ██║║
║   ██║  ██╗ ╚████╔╝ ██║ ╚═╝ ██║    ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║██████╔╝║
║   ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝    ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝╚═════╝ ║
║                                                                           ║
║              🔓 Attack VMs • 🔒 Prove Encryption Works                    ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

🎯 Demonstrate the power of Confidential Computing (AMD SEV-SNP)
   Attack VMs via memory dumps and prove that encrypted memory cannot be exploited!

🚀 Quick Start:
   • list           - Show all VMs on this host
   • disk-search    - Search VM disk for sensitive data
   • attack         - Dump memory and search for patterns

🔐 Powered by AMD SEV-SNP | Made with ❤️  by Enclaive
`,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Note: CLI runs directly on KVM host, no SSH needed
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
}
