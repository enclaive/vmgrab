package cmd

import (
	"fmt"

	"github.com/enclaive/vmgrab/pkg/search"
	"github.com/spf13/cobra"
)

var searchContext int
var searchAnimate bool
var searchMaxMatch int
var searchCmd = &cobra.Command{
	Use: "search <dump-file> <pattern>", Short: "Search captured bytes for a regular expression",
	Args: cobra.ExactArgs(2), RunE: runSearch,
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().IntVarP(&searchContext, "context", "C", 100, "Bytes of context before and after each match")
	searchCmd.Flags().BoolVarP(&searchAnimate, "animate", "a", false, "Animate match display (retained for CLI compatibility)")
	searchCmd.Flags().IntVarP(&searchMaxMatch, "max", "m", 10, "Maximum matches to display")
}
func runSearch(cmd *cobra.Command, args []string) error {
	if searchContext < 0 {
		return fmt.Errorf("context must not be negative")
	}
	verbose, _ := cmd.Flags().GetBool("verbose")
	s := search.New(args[0], verbose)
	result, err := s.Analyze(args[1], searchMaxMatch)
	if err != nil {
		return err
	}
	printAnalysis(s, result, searchContext)
	return result.Check()
}

// Every memory-search command renders the same assessment, including when
// the input was acquired through a different backend or has no sidecar.
func printAnalysis(s *search.Searcher, a *search.Analysis, context int) {
	fmt.Printf("Dump: %s (%s)\n", s.FilePath, formatBytes(a.Scan.FileSize))
	if a.Meta != nil {
		fmt.Printf("Target: %s; backend=%s; kind=%s\n", a.Meta.Target, a.Meta.Backend, a.Meta.Kind)
		if a.Meta.Security != "" {
			fmt.Printf("Configured confidential computing: %s (recorded at capture time)\n", a.Meta.Security)
		}
		if c := a.Meta.Capture; c != nil {
			fmt.Printf("Capture scope: %s\n", c.Scope)
			fmt.Printf("Selected bytes: read=%d padded=%d complete=%v\n", c.BytesRead, c.BytesPadded, c.Complete)
			if c.GuestMemfd != nil && *c.GuestMemfd {
				fmt.Println("guest_memfd detected: this capture contains QEMU userspace mappings, not a capture of guest-private memory.")
			}
		} else {
			fmt.Println("Capture coverage was not recorded by this version of the producer.")
		}
	} else {
		fmt.Println("Capture origin and coverage are unknown (no metadata sidecar).")
	}
	fmt.Printf("%s: %d displayed match(es)\n", a.Status(), len(a.Scan.Matches))
	if a.Scan.Limited {
		fmt.Println("Additional matches exist; increase --max to display more.")
	}
	if len(a.Scan.Matches) > 0 {
		fmt.Println("The matched bytes are readable in this dump. Their presence alone does not establish whether guest-private memory was exposed.")
	} else {
		fmt.Println("The pattern was not found in the captured bytes. This does not establish encryption or absence from uncaptured memory.")
	}
	for _, problem := range a.Incomplete {
		fmt.Printf("INCOMPLETE: %s\n", problem)
	}
	for _, match := range a.Scan.Matches {
		fmt.Printf("Offset 0x%x (%d bytes), match length %d\n", match.Offset, match.Offset, len(match.Data))
		if a.Meta != nil {
			for _, container := range a.Meta.Containers {
				for _, process := range container.Processes {
					for _, region := range process.Regions {
						end := match.Offset + int64(len(match.Data))
						if match.Offset >= region.ByteStart && end <= region.ByteEnd {
							fmt.Printf("  container=%s pid=%d address=0x%x\n", container.Name, process.PID, region.Start+uint64(match.Offset-region.ByteStart))
						}
					}
				}
			}
		}
		ctx := s.GetMatchContext(match.Offset, len(match.Data), context, context)
		if ctx != nil {
			fmt.Println(search.SanitizeBytes(ctx.Before) + "[" + search.SanitizeBytes(ctx.Match) + "]" + search.SanitizeBytes(ctx.After))
		}
	}
}
