package cmd

import (
	"fmt"
	"time"

	"github.com/enclaive/vmgrab/pkg/backend"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var dumpCmd = &cobra.Command{
	Use:   "dump <vm-name>",
	Short: "Dump VM memory to file",
	Long:  "Create a memory dump of the specified VM",
	Args:  cobra.ExactArgs(1),
	RunE:  runDump,
}

var (
	dumpPath string
)

func init() {
	rootCmd.AddCommand(dumpCmd)
	dumpCmd.Flags().StringVarP(&dumpPath, "output", "o", "/tmp", "Output directory for dump file")
}

func runDump(cmd *cobra.Command, args []string) error {
	vmName := args[0]
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Use specific backend if specified, otherwise find VM across all backends
	var b backend.Backend
	var vm *backend.VM

	if backendName != "" {
		// Use explicitly specified backend
		b = GetBackend(verbose)
		if b == nil {
			return fmt.Errorf("backend not available: %s", backendName)
		}
		// Find VM in this specific backend
		vms, err := b.List()
		if err != nil {
			return fmt.Errorf("failed to list VMs: %w", err)
		}
		for i := range vms {
			if vms[i].Name == vmName {
				vm = &vms[i]
				break
			}
		}
		if vm == nil {
			return fmt.Errorf("VM not found in %s backend: %s", backendName, vmName)
		}
	} else {
		// Auto-detect: find VM across all backends
		b, vm = backend.FindVM(vmName, verbose)
		if b == nil || vm == nil {
			return fmt.Errorf("VM not found: %s", vmName)
		}
	}

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("\n💾 Dumping VM Memory: %s\n", vmName)
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	fmt.Printf("📍 Target VM:      %s (PID %d)\n", color.CyanString(vmName), vm.PID)
	fmt.Printf("💾 Output dir:     %s\n", color.HiBlackString(dumpPath))

	// Show SEV status
	if vm.Security != "" {
		fmt.Printf("🔒 Security:       %s\n", color.GreenString("%s Protected", vm.Security))
	} else {
		fmt.Printf("⚠️  Security:       %s\n", color.RedString("No encryption"))
	}

	fmt.Printf("🔧 Backend:        %s\n", color.HiBlackString(b.Name()))
	fmt.Println()

	// Show progress bar
	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("⏳ Creating memory dump..."),
		progressbar.OptionSetWidth(40),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerPadding: "░",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	// Start progress animation in background
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				bar.Add(1)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Execute dump
	startTime := time.Now()
	outputFile, err := b.Dump(vmName, dumpPath)

	// Signal goroutine to stop
	done <- true
	time.Sleep(150 * time.Millisecond)
	bar.Finish()

	if err != nil {
		return fmt.Errorf("failed to dump VM memory: %w", err)
	}

	duration := time.Since(startTime)

	// Get dump file info
	size, err := b.GetFileSize(outputFile)
	if err != nil {
		color.Yellow("⚠️  Warning: Could not get dump file info: %v", err)
	}

	// Success message
	color.Green("\n✅ Memory dump completed successfully!")
	fmt.Printf("⏱️  Duration:      %s\n", color.HiBlackString(duration.Round(time.Second).String()))
	if size > 0 {
		fmt.Printf("📊 Dump size:     %s\n", color.HiBlackString(formatBytes(size)))
	}
	fmt.Printf("🔍 Location:      %s\n", color.HiBlackString(outputFile))

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	// Show next steps
	fmt.Println()
	color.Cyan("📝 Next steps:")
	fmt.Printf("   Search dump:  %s\n", color.HiWhiteString("vmgrab search %s <pattern>", outputFile))
	fmt.Println()

	return nil
}

// formatBytes formats bytes as human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
