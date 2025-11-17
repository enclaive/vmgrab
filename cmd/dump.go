package cmd

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/enclaive/vmgrab/pkg/virsh"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var dumpCmd = &cobra.Command{
	Use:   "dump <vm-name> [output-file]",
	Short: "Dump VM memory to file",
	Long:  "Execute 'virsh dump' to create a memory dump of the specified VM",
	Args:  cobra.RangeArgs(1, 2),
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

	var outputFile string
	if len(args) > 1 {
		outputFile = args[1]
	} else {
		timestamp := time.Now().Format("20060102-150405")
		outputFile = filepath.Join(dumpPath, fmt.Sprintf("%s-%s.dump", vmName, timestamp))
	}

	verbose, _ := cmd.Flags().GetBool("verbose")
	v := virsh.NewLocal(verbose)

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("\n💾 Dumping VM Memory: %s\n", vmName)
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	fmt.Printf("📍 Target VM:      %s\n", color.CyanString(vmName))
	fmt.Printf("💾 Output path:    %s\n", color.HiBlackString(outputFile))
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

	// Execute virsh dump
	startTime := time.Now()
	err := v.Dump(vmName, outputFile)

	// Signal goroutine to stop and wait briefly for it to finish
	done <- true
	time.Sleep(150 * time.Millisecond) // Give goroutine time to exit cleanly

	// Finish the progress bar
	bar.Finish()

	if err != nil {
		return fmt.Errorf("failed to dump VM memory: %w", err)
	}

	duration := time.Since(startTime)

	// Get dump file info
	size, err := v.GetFileSize(outputFile)
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
