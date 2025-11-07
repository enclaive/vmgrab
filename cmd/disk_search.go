package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/enclaive/vmgrab/pkg/config"
	"github.com/enclaive/vmgrab/pkg/virsh"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var diskSearchCmd = &cobra.Command{
	Use:   "disk-search <vm-name>",
	Short: "Search for patterns in VM disk files",
	Long: `Search VM disk files for sensitive data patterns (Demo 2 - Disk Attack).

This command performs a file system grep attack by searching the VM's disk
file directly on the KVM host. This demonstrates that without disk encryption
(LUKS), sensitive data is exposed even on the host filesystem.

For confidential VMs with LUKS encryption, this attack fails.`,
	Args: cobra.ExactArgs(1),
	RunE: runDiskSearch,
}

var (
	diskSearchPattern     string
	diskSearchPatternName string
	diskSearchMaxMatches  int
	diskSearchContext     int
)

func init() {
	rootCmd.AddCommand(diskSearchCmd)
	diskSearchCmd.Flags().StringVarP(&diskSearchPattern, "pattern", "p", "", "Pattern to search for (overrides config)")
	diskSearchCmd.Flags().StringVar(&diskSearchPatternName, "pattern-name", "", "Pattern description")
	diskSearchCmd.Flags().IntVarP(&diskSearchMaxMatches, "max", "m", 10, "Maximum matches to display")
	diskSearchCmd.Flags().IntVarP(&diskSearchContext, "context", "C", 80, "Characters of context before match")
}

func runDiskSearch(cmd *cobra.Command, args []string) error {
	vmName := args[0]

	// Load config
	cfg, err := config.Load("")
	if err != nil {
		// Config is optional now
		cfg = &config.Config{}
	}

	// Get pattern (priority: flag > config)
	pattern := diskSearchPattern
	patternName := diskSearchPatternName
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
	cyan.Printf("\n💾 Disk Search Attack: %s\n", vmName)
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	fmt.Printf("🖥️  Target VM:     %s\n", color.CyanString(vmName))
	fmt.Printf("🔍 Pattern:       %s (%s)\n", color.YellowString(pattern), color.HiBlackString(patternName))
	fmt.Println()

	// Create local virsh client
	client := virsh.NewLocal(verbose)

	// Step 1: Find disk path
	color.Cyan("📍 Step 1: Finding VM disk...")
	if verbose {
		fmt.Println(color.HiBlackString("   Using: virsh domblklist " + vmName))
	}

	diskPath, err := client.GetDiskPath(vmName)
	if err != nil {
		return fmt.Errorf("failed to find disk: %w", err)
	}

	color.Green("✅ Disk found: %s", diskPath)

	// Get disk size
	diskSize, _ := client.GetFileSize(diskPath)
	if diskSize > 0 {
		fmt.Printf("   Size: %s\n", formatBytes(diskSize))
	}
	fmt.Println()

	// Step 2: Search disk
	color.Cyan("🔍 Step 2: Searching disk for pattern...")
	if verbose {
		fmt.Println(color.HiBlackString(fmt.Sprintf("   grep -a -b --text '%s' %s", pattern, diskPath)))
	}

	matches, err := client.SearchDisk(diskPath, pattern, diskSearchMaxMatches)
	if err != nil {
		return fmt.Errorf("disk search failed: %w", err)
	}

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	// Step 3: Display results
	color.Cyan("📊 Step 3: Results")
	fmt.Println()

	if len(matches) == 0 {
		// Check if likely encrypted (based on path/name heuristics)
		isEncrypted := strings.Contains(strings.ToLower(diskPath), "luks") ||
			strings.Contains(strings.ToLower(diskPath), "crypt") ||
			strings.Contains(strings.ToLower(diskPath), "cvm")

		if isEncrypted {
			color.Green("✅ NO MATCHES FOUND - Disk appears ENCRYPTED!")
			fmt.Println()
			color.HiBlack("This is expected for confidential VMs with LUKS disk encryption.")
			color.HiBlack("The entire disk is encrypted, so sensitive data cannot be read from host.")
			fmt.Println()
			color.Green("🔒 CONCLUSION: Disk is PROTECTED by encryption")
		} else {
			color.Yellow("⚠️  No matches found")
			fmt.Println()
			color.HiBlack("The pattern was not found, but disk may not be encrypted.")
			color.HiBlack("Try different search patterns or check if data exists in VM.")
		}
	} else {
		color.Red("❌ VULNERABLE - %d match(es) found in disk!", len(matches))
		fmt.Println()
		color.HiBlack("This indicates the disk is NOT encrypted and sensitive data is exposed!")
		color.HiBlack("Attackers with host access can read the disk files directly.")

		// Show first few matches
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

			// Get context if requested
			if diskSearchContext > 0 {
				contextData, _ := client.GetDiskContext(diskPath, match.Offset, diskSearchContext)
				if contextData != nil {
					// Show context with highlighted pattern
					highlighted := highlightPattern(contextData, pattern)
					fmt.Println(color.HiWhiteString(highlighted))
				} else {
					// Just show match data
					fmt.Println(color.HiWhiteString(sanitizeBytes(match.Data)))
				}
			} else {
				fmt.Println(color.HiWhiteString(sanitizeBytes(match.Data)))
			}
		}

		if len(matches) > displayCount {
			fmt.Println()
			color.HiBlack("... and %d more match(es) (use --max to show more)", len(matches)-displayCount)
		}

		fmt.Println()
		fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
		fmt.Println()
		color.Red("❌ CONCLUSION: Disk is VULNERABLE - data exposed!")
	}

	fmt.Println()

	return nil
}

// Helper functions

func sanitizeBytes(data []byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			result[i] = b
		} else {
			result[i] = '.'
		}
	}
	return string(result)
}

func highlightPattern(data []byte, pattern string) string {
	text := sanitizeBytes(data)
	re := regexp.MustCompile(pattern)

	loc := re.FindStringIndex(text)
	if loc == nil {
		return text
	}

	before := text[:loc[0]]
	match := text[loc[0]:loc[1]]
	after := text[loc[1]:]

	return fmt.Sprintf("%s\033[1;31m%s\033[0m%s", before, match, after)
}
