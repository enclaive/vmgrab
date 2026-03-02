package cmd

import (
	"fmt"

	"github.com/enclaive/vmgrab/pkg/backend"
	// Import backends to register them
	_ "github.com/enclaive/vmgrab/pkg/backend/libvirt"
	_ "github.com/enclaive/vmgrab/pkg/backend/procmem"
	_ "github.com/enclaive/vmgrab/pkg/backend/qemu"
	"github.com/spf13/cobra"
)

var (
	// Version information (set by main package)
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"

	// Backend selection
	backendName string
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
	Short: "VM Memory Dump Tool for Confidential Computing Demo",
	Long: `
 ██╗   ██╗███╗   ███╗ ██████╗ ██████╗  █████╗ ██████╗
 ██║   ██║████╗ ████║██╔════╝ ██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██╔████╔██║██║  ███╗██████╔╝███████║██████╔╝
 ╚██╗ ██╔╝██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║██╔══██╗
  ╚████╔╝ ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═══╝  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

  VM Memory Dump Tool — Prove Confidential Computing Works

  Dump VM memory via /proc/pid/mem and search for sensitive data.
  Compare standard VMs (vulnerable) vs SEV-SNP protected VMs (encrypted).

Quick Start:
  vmgrab list                      List all VMs with security status
  vmgrab dump <vm> -o /tmp         Dump VM memory to file
  vmgrab search <dump> <pattern>   Search dump for secrets

Example:
  sudo vmgrab dump vm-NON-snp -o /tmp
  vmgrab search /tmp/vm-NON-snp-*.dump "POSTGRES_PASSWORD="

(c) 2025 enclaive.io | https://github.com/enclaive/vmgrab
`,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Note: CLI runs directly on KVM host, no SSH needed
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVar(&backendName, "backend", "", "Backend to use (libvirt, qemu, procmem). Auto-detect if not specified.")
}

// GetBackend returns the selected backend
func GetBackend(verbose bool) backend.Backend {
	if backendName != "" {
		b := backend.Get(backendName, verbose)
		if b == nil {
			fmt.Printf("Unknown backend: %s. Available: %v\n", backendName, backend.List())
			return nil
		}
		if !b.Available() {
			fmt.Printf("Backend %s is not available on this system\n", backendName)
			return nil
		}
		return b
	}
	return backend.AutoSelect(verbose)
}
