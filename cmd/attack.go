package cmd

import (
	"fmt"
	"github.com/enclaive/vmgrab/pkg/config"
	"github.com/enclaive/vmgrab/pkg/search"
	"github.com/spf13/cobra"
)

var attackCmd = &cobra.Command{
	Use:   "attack <target>",
	Short: "Capture and search a VM or pod",
	Long: `Capture and search one VM or pod (namespace/name). --backend selects the capture method.

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
	cfg, err := config.Load("")
	if err != nil {
		cfg = &config.Config{}
	}
	pattern := attackPattern
	if pattern == "" && len(cfg.Search) > 0 {
		pattern = cfg.Search[0].Pattern
	}
	if err := search.ValidatePattern(pattern, attackMaxMatches); err != nil {
		return err
	}
	if attackContext < 0 {
		return fmt.Errorf("context must not be negative")
	}
	verbose, _ := cmd.Flags().GetBool("verbose")
	b, err := targetBackend(args[0], verbose)
	if err != nil {
		return err
	}
	path, captureErr := b.Dump(args[0], attackOutput)
	if attackCleanup {
		defer cleanupCapture(path)
	}
	if path == "" {
		return captureErr
	}
	s := search.New(path, verbose)
	result, err := s.Analyze(pattern, attackMaxMatches)
	if err != nil {
		return err
	}
	printAnalysis(s, result, attackContext)
	if !attackCleanup {
		fmt.Printf("Dump retained: %s\n", path)
	}
	if captureErr != nil {
		return captureErr
	}
	return result.Check()
}
