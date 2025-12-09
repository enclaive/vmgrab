package cmd

import (
	"fmt"
	"os"

	"github.com/enclaive/vmgrab/pkg/search"
	"github.com/enclaive/vmgrab/pkg/visualizer"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var searchCmd = &cobra.Command{
	Use:   "search <dump-file> <pattern>",
	Short: "Search for patterns in memory dump",
	Long:  "Search memory dump for sensitive data patterns with visual effects",
	Args:  cobra.ExactArgs(2),
	RunE:  runSearch,
}

var (
	searchContext  int
	searchAnimate  bool
	searchMaxMatch int
)

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().IntVarP(&searchContext, "context", "C", 100, "Show N characters before and after match")
	searchCmd.Flags().BoolVarP(&searchAnimate, "animate", "a", false, "Show animated cursor moving to match")
	searchCmd.Flags().IntVarP(&searchMaxMatch, "max", "m", 10, "Maximum number of matches to display")
}

func runSearch(cmd *cobra.Command, args []string) error {
	dumpFile := args[0]
	pattern := args[1]

	verbose, _ := cmd.Flags().GetBool("verbose")

	// Check if file exists
	info, err := os.Stat(dumpFile)
	if err != nil {
		return fmt.Errorf("cannot access dump file: %w", err)
	}

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("\n🔍 Searching Memory Dump\n")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	fmt.Printf("📂 Dump file:     %s\n", color.CyanString(dumpFile))
	fmt.Printf("📊 File size:     %s\n", color.HiBlackString(formatBytes(info.Size())))
	fmt.Printf("🔎 Pattern:       %s\n", color.YellowString(pattern))
	fmt.Printf("📏 Context:       %s\n", color.HiBlackString(fmt.Sprintf("%d chars before/after match", searchContext)))
	fmt.Println()

	// Create searcher
	s := search.New(dumpFile, verbose)

	// Search for pattern
	color.Cyan("⏳ Scanning memory dump...")
	matches, err := s.Search(pattern, searchMaxMatch)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	// Display results
	if len(matches) == 0 {
		color.Yellow("No matches found for pattern: %s", pattern)
		fmt.Println()

		// Check multiple indicators to determine if memory is encrypted
		color.HiBlack("Analyzing memory dump for encryption indicators...")
		fmt.Println()

		// Only check reliable indicators (ELF can appear in shared memory even for SEV-SNP)
		indicators := []struct {
			name    string
			pattern string
		}{
			{"Linux kernel", `Linux version [0-9]+\.[0-9]+`},
		}

		foundCount := 0
		for _, ind := range indicators {
			indMatches, err := s.Search(ind.pattern, 1)
			if err != nil {
				continue
			}

			if len(indMatches) > 0 {
				foundCount++
				color.Red("  ✗ %-15s FOUND", ind.name)
			} else {
				color.Green("  ✓ %-15s not found", ind.name)
			}
		}

		fmt.Println()

		if foundCount == 0 {
			color.Green("✅ ENCRYPTED - No readable data found")
			fmt.Println()
			color.HiBlack("This memory dump appears to be from a SEV-SNP protected VM.")
			color.HiBlack("Guest memory is encrypted and not readable from the host.")

			// Show random memory snippets from guest VM
			fmt.Println()
			color.Cyan("📜 Random snippets from guest VM memory:")
			color.HiBlack("(SEV-SNP encrypted pages appear as zeros to the host)")
			fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

			snippets, _ := s.GetRandomSnippets(3, 128)
			for i, snippet := range snippets {
				fmt.Printf("\n%s\n", color.HiBlackString(fmt.Sprintf("Snippet %d (offset: 0x%x):", i+1, snippet.Offset)))
				visualizer.ShowEncryptedSnippet(snippet.Data)
			}
		} else {
			color.Red("❌ NOT ENCRYPTED - Memory is readable")
			fmt.Println()
			color.HiBlack("This VM does NOT have memory encryption enabled.")
			color.HiBlack("Pattern '%s' was not found, but memory contains readable data.", pattern)
			color.HiBlack("Try different search patterns.")
		}
	} else {
		color.Red("⚠️  VULNERABLE - %d match(es) found!", len(matches))
		fmt.Println()
		color.HiBlack("This indicates the memory is NOT encrypted and sensitive data is exposed!")

		for i, match := range matches {
			fmt.Println()
			fmt.Printf("%s\n", color.RedString(fmt.Sprintf("══════════ Match %d/%d ══════════", i+1, len(matches))))
			fmt.Printf("📍 Offset: %s\n", color.HiBlackString(fmt.Sprintf("0x%x (%d bytes into dump)", match.Offset, match.Offset)))

			// Get context before and after
			ctx := s.GetMatchContext(match.Offset, len(match.Data), searchContext, searchContext)
			if ctx != nil {
				fmt.Println()
				// Show context with highlighted match
				beforeStr := search.SanitizeBytes(ctx.Before)
				matchStr := search.SanitizeBytes(ctx.Match)
				afterStr := search.SanitizeBytes(ctx.After)

				// Print with colors: gray...RED MATCH...gray
				fmt.Print(color.HiBlackString(beforeStr))
				fmt.Print(color.New(color.FgRed, color.Bold).Sprint(matchStr))
				fmt.Println(color.HiBlackString(afterStr))
			} else {
				// Fallback to old method
				contextData := s.GetContext(match.Offset, searchContext)
				if searchAnimate {
					visualizer.AnimateCursorToMatch(contextData, pattern)
				} else {
					visualizer.ShowMatchContext(contextData, pattern)
				}
			}
		}
	}

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	return nil
}
