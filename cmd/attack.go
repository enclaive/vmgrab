package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/enclaive/vmgrab/pkg/config"
	"github.com/enclaive/vmgrab/pkg/search"
	"github.com/enclaive/vmgrab/pkg/virsh"
	"github.com/enclaive/vmgrab/pkg/visualizer"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var attackCmd = &cobra.Command{
	Use:   "attack <vm-name>",
	Short: "Perform complete memory dump attack on a VM",
	Long: `Perform a complete memory dump attack on a single VM.

This command combines dump, search, and visualization in one step:
1. Creates memory dump of the VM
2. Searches dump for sensitive data patterns
3. Visualizes results with animations

Perfect for testing individual VMs without running the full demo.`,
	Args: cobra.ExactArgs(1),
	RunE: runAttack,
}

var (
	attackPattern     string
	attackPatternName string
	attackCleanup     bool
	attackContext     int
	attackAnimate     bool
	attackMaxMatches  int
	attackOutput      string
)

func init() {
	rootCmd.AddCommand(attackCmd)
	attackCmd.Flags().StringVarP(&attackPattern, "pattern", "p", "", "Pattern to search for (overrides config)")
	attackCmd.Flags().StringVar(&attackPatternName, "pattern-name", "", "Pattern description")
	attackCmd.Flags().BoolVarP(&attackCleanup, "cleanup", "c", true, "Clean up dump file after attack")
	attackCmd.Flags().IntVarP(&attackContext, "context", "C", 100, "Characters of context before match")
	attackCmd.Flags().BoolVarP(&attackAnimate, "animate", "a", true, "Show animated cursor moving to match")
	attackCmd.Flags().IntVarP(&attackMaxMatches, "max", "m", 10, "Maximum matches to display")
	attackCmd.Flags().StringVarP(&attackOutput, "output", "o", "/tmp", "Output directory for dump file")
}

func runAttack(cmd *cobra.Command, args []string) error {
	vmName := args[0]

	// Load config (optional)
	cfg, err := config.Load("")
	if err != nil {
		cfg = &config.Config{}
	}

	// Get pattern (priority: flag > config)
	pattern := attackPattern
	patternName := attackPatternName
	if pattern == "" {
		if len(cfg.Search) == 0 {
			return fmt.Errorf("no search pattern specified (use --pattern)")
		}
		pattern = cfg.Search[0].Pattern
		patternName = cfg.Search[0].Name
	}
	if patternName == "" {
		patternName = "Sensitive Data"
	}

	verbose, _ := cmd.Flags().GetBool("verbose")

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("\n🔴 Memory Dump Attack: %s\n", vmName)
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	fmt.Printf("🖥️  Target VM:     %s\n", color.CyanString(vmName))
	fmt.Printf("🔍 Pattern:       %s (%s)\n", color.YellowString(pattern), color.HiBlackString(patternName))
	fmt.Println()

	// Step 1: Dump memory
	color.Cyan("📍 Step 1: Dumping VM memory...")
	fmt.Printf("   Target: %s\n", vmName)

	// Create dump path
	dumpPath := filepath.Join(attackOutput, fmt.Sprintf("attack-%s.dump", vmName))
	fmt.Printf("   Output: %s\n", dumpPath)
	fmt.Println()

	if verbose {
		fmt.Println(color.HiBlackString("   Using: virsh dump " + vmName + " --memory-only"))
	}

	// Create local virsh client
	client := virsh.NewLocal(verbose)

	// Setup cleanup (even if error occurs)
	if attackCleanup {
		defer func() {
			client.RemoveFile(dumpPath)
		}()
	}

	// Dump memory
	err = client.Dump(vmName, dumpPath)
	if err != nil {
		return fmt.Errorf("memory dump failed: %w", err)
	}

	// Get file size
	dumpSize, _ := client.GetFileSize(dumpPath)

	color.Green("✅ Dump completed: %s", formatBytes(dumpSize))
	fmt.Println()

	// Step 2: Search dump
	color.Cyan("🔍 Step 2: Searching for sensitive data...")
	fmt.Printf("   Pattern: %s\n", color.YellowString(pattern))
	fmt.Println()

	if verbose {
		fmt.Println(color.HiBlackString(fmt.Sprintf("   grep -a -b '%s' %s", pattern, dumpPath)))
	}

	searcher := search.New(dumpPath, verbose)
	matches, err := searcher.Search(pattern, attackMaxMatches)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	// Step 3: Display results
	color.Cyan("📊 Step 3: Results")
	fmt.Println()

	if len(matches) == 0 {
		// Perform baseline check: search for Linux kernel banner
		// This is a reliable way to determine if memory is encrypted
		// Reference: https://blogs.oracle.com/linux/live-kernel-debugging-2
		color.HiBlack("Performing baseline encryption check (Linux kernel banner)...")
		fmt.Println()

		bannerFound, err := searcher.CheckLinuxBanner()
		if err != nil {
			color.Yellow("⚠️  Baseline check failed: %v", err)
			color.HiBlack("Unable to determine encryption status reliably.")
		} else if !bannerFound {
			// Linux banner NOT found = memory IS encrypted
			color.Green("✅ NO MATCHES FOUND - Memory appears ENCRYPTED!")
			fmt.Println()
			color.HiBlack("This is expected for confidential VMs with AMD SEV-SNP or Intel TDX.")
			color.HiBlack("The memory is encrypted at the hardware level, so sensitive data cannot be read.")
			fmt.Println()

			// Show encrypted memory snippets with animation
			if attackAnimate {
				color.Cyan("🔐 Sample of encrypted memory:")
				fmt.Println()

				snippets, err := searcher.GetRandomSnippets(3, 256)
				if err == nil && len(snippets) > 0 {
					for i, snippet := range snippets {
						if i > 0 {
							fmt.Println()
						}
						fmt.Printf("%s\n", color.HiBlackString(fmt.Sprintf("Offset: 0x%x", snippet.Offset)))
						visualizer.AnimateEncryptedSnippet(snippet.Data, 50)
					}
					fmt.Println()
					color.HiBlack("↑ High entropy data - typical of encrypted memory")
				}
			}

			fmt.Println()
			color.Green("🔒 CONCLUSION: Memory is PROTECTED by encryption")
		} else {
			// Linux banner found but user pattern not found
			color.Yellow("⚠️  No matches found for pattern, but memory is NOT encrypted")
			fmt.Println()
			color.HiBlack("Linux kernel banner was found (baseline check passed).")
			color.HiBlack("This means memory is NOT encrypted, but your pattern didn't match.")
			fmt.Println()
			color.HiBlack("This could mean:")
			color.HiBlack("  • The specific data is not in memory at this time")
			color.HiBlack("  • The pattern doesn't match the actual data format")
			color.HiBlack("  • Try different search patterns or verify the data exists in the VM")
			fmt.Println()
			color.Yellow("⚠️  CONCLUSION: Memory is VULNERABLE (not encrypted)")
		}
	} else {
		color.Red("❌ VULNERABLE - %d match(es) found in memory!", len(matches))
		fmt.Println()
		color.HiBlack("This indicates the VM has no memory encryption and sensitive data is exposed!")
		color.HiBlack("Attackers with host access can extract sensitive data from memory dumps.")

		// Show matches with animation
		displayCount := len(matches)
		if displayCount > 3 {
			displayCount = 3
		}

		for i := 0; i < displayCount; i++ {
			match := matches[i]

			fmt.Println()
			fmt.Printf("%s\n", color.RedString(fmt.Sprintf("══════════ Match %d/%d ══════════", i+1, len(matches))))
			fmt.Printf("📍 Offset: %s\n", color.HiBlackString(fmt.Sprintf("0x%x (%d bytes)", match.Offset, match.Offset)))
			fmt.Println()

			if attackAnimate {
				// Get context for animation
				contextData := searcher.GetContext(match.Offset, attackContext)
				if contextData != nil {
					visualizer.AnimateCursorToMatch(contextData, pattern)
				} else {
					visualizer.ShowMatchContext(match.Data, pattern)
				}
			} else {
				// Just show context
				contextData := searcher.GetContext(match.Offset, attackContext)
				if contextData != nil {
					highlighted := search.HighlightPattern(contextData, pattern)
					fmt.Println(color.HiWhiteString(highlighted))
				} else {
					fmt.Println(color.HiWhiteString(string(match.Data)))
				}
			}
		}

		if len(matches) > displayCount {
			fmt.Println()
			color.HiBlack("... and %d more match(es) (use --max to show more)", len(matches)-displayCount)
		}

		fmt.Println()
		fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
		fmt.Println()
		color.Red("❌ CONCLUSION: VM is VULNERABLE - data exposed!")
	}

	fmt.Println()

	// Note: Cleanup happens via defer if attackCleanup is true
	if !attackCleanup {
		color.HiBlack("📁 Dump file kept at: %s", dumpPath)
		fmt.Println()
	}

	return nil
}
