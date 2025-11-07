package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version information
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

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
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildDate),
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Note: CLI runs directly on KVM host, no SSH needed
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
}
