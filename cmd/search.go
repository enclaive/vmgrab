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
	searchCmd.Flags().IntVarP(&searchContext, "context", "C", 100, "Show N characters before match")
	searchCmd.Flags().BoolVarP(&searchAnimate, "animate", "a", true, "Show animated cursor moving to match")
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
	fmt.Printf("📏 Context:       %s\n", color.HiBlackString(fmt.Sprintf("%d characters before match", searchContext)))
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
		color.Green("✅ No matches found - Memory appears ENCRYPTED!")
		fmt.Println()
		color.HiBlack("This is expected for confidential VMs (cVM) with AMD SEV-SNP.")
		color.HiBlack("Memory encryption prevents attackers from reading sensitive data.")

		// Show random encrypted snippets
		fmt.Println()
		color.Cyan("📜 Random encrypted memory snippets:")
		fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

		snippets, _ := s.GetRandomSnippets(3, 120)
		for i, snippet := range snippets {
			fmt.Printf("\n%s\n", color.HiBlackString(fmt.Sprintf("Snippet %d (offset: %d):", i+1, snippet.Offset)))
			if searchAnimate {
				visualizer.AnimateEncryptedSnippet(snippet.Data, 50)
			} else {
				visualizer.ShowEncryptedSnippet(snippet.Data)
			}
		}
	} else {
		color.Red("⚠️  VULNERABLE - %d match(es) found!", len(matches))
		fmt.Println()
		color.HiBlack("This indicates the memory is NOT encrypted and sensitive data is exposed!")

		for i, match := range matches {
			fmt.Println()
			fmt.Printf("%s\n", color.RedString(fmt.Sprintf("══════════ Match %d/%d ══════════", i+1, len(matches))))
			fmt.Printf("📍 Offset: %s\n", color.HiBlackString(fmt.Sprintf("0x%x (%d)", match.Offset, match.Offset)))
			fmt.Println()

			// Get context
			contextData := s.GetContext(match.Offset, searchContext)

			// Animate cursor if enabled
			if searchAnimate {
				visualizer.AnimateCursorToMatch(contextData, pattern)
			} else {
				visualizer.ShowMatchContext(contextData, pattern)
			}
		}
	}

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	// Summary
	fmt.Println()
	if len(matches) == 0 {
		color.Green("🔒 CONCLUSION: Memory is PROTECTED by encryption")
	} else {
		color.Red("❌ CONCLUSION: Memory is VULNERABLE - data exposed!")
	}
	fmt.Println()

	return nil
}
