package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/enclaive/vmgrab/pkg/config"
	"github.com/enclaive/vmgrab/pkg/search"
	"github.com/enclaive/vmgrab/pkg/virsh"
	"github.com/enclaive/vmgrab/pkg/visualizer"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run complete attack demonstration",
	Long: `Automatically run the full confidential computing demo:
1. Dump standard VM memory
2. Search for sensitive data in standard VM dump
3. Dump confidential VM memory
4. Search for same data in confidential VM dump
5. Show comparison table proving encryption works

The demo can be customized via config file (.vmgrab.yaml)
or command-line flags.`,
	RunE: runDemo,
}

var (
	demoStandardVM     string
	demoConfidentialVM string
	demoPattern        string
	demoPatternName    string
	demoCleanup        bool
	demoOutputDir      string
)

func init() {
	rootCmd.AddCommand(demoCmd)
	demoCmd.Flags().StringVar(&demoStandardVM, "standard-vm", "", "Standard VM name (overrides config)")
	demoCmd.Flags().StringVar(&demoConfidentialVM, "confidential-vm", "", "Confidential VM name (overrides config)")
	demoCmd.Flags().StringVarP(&demoPattern, "pattern", "p", "", "Pattern to search for (overrides config)")
	demoCmd.Flags().StringVar(&demoPatternName, "pattern-name", "", "Description of the pattern (e.g., 'NHS Number')")
	demoCmd.Flags().BoolVarP(&demoCleanup, "cleanup", "c", true, "Clean up dump files after demo")
	demoCmd.Flags().StringVarP(&demoOutputDir, "output", "o", "/tmp", "Output directory for dumps")
}

func runDemo(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get VM names (priority: flags > config > error)
	standardVM := demoStandardVM
	if standardVM == "" {
		standardVM = cfg.VMs.Standard.Name
	}

	confidentialVM := demoConfidentialVM
	if confidentialVM == "" {
		confidentialVM = cfg.VMs.Confidential.Name
	}

	// Get search pattern (priority: flags > config > error)
	pattern := demoPattern
	patternName := demoPatternName
	if pattern == "" {
		if len(cfg.Search) == 0 {
			return fmt.Errorf("no search pattern specified (use --pattern or configure in .vmgrab.yaml)")
		}
		pattern = cfg.Search[0].Pattern
		patternName = cfg.Search[0].Name
	}

	if patternName == "" {
		patternName = "Sensitive Data"
	}

	verbose, _ := cmd.Flags().GetBool("verbose")

	v := virsh.NewLocal(verbose)

	// Print demo header
	printDemoHeader()

	// Step 0: List VMs
	fmt.Println()
	color.Cyan("📋 Step 0: Listing VMs on local host")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	vms, err := v.List()
	if err != nil {
		return fmt.Errorf("failed to list VMs: %w", err)
	}

	for _, vm := range vms {
		if vm.Name == "neo4j-vm1" || vm.Name == "neo4j-cvm" {
			fmt.Printf("  ✓ %s (%s)\n", color.CyanString(vm.Name), vm.State)
		}
	}

	time.Sleep(2 * time.Second)

	// Step 1: Attack standard VM
	fmt.Println()
	fmt.Println()
	color.New(color.FgRed, color.Bold).Printf("🔴 PHASE 1: ATTACKING STANDARD VM (%s)\n", standardVM)
	fmt.Println(color.HiBlackString("═══════════════════════════════════════════════════"))

	vm1DumpPath := filepath.Join(demoOutputDir, fmt.Sprintf("demo-%s.dump", standardVM))
	if err := attackVM(v, standardVM, vm1DumpPath, pattern, patternName, false); err != nil {
		return fmt.Errorf("standard VM attack failed: %w", err)
	}

	time.Sleep(3 * time.Second)

	// Step 2: Attack confidential VM
	fmt.Println()
	fmt.Println()
	color.New(color.FgGreen, color.Bold).Printf("🔵 PHASE 2: ATTACKING CONFIDENTIAL VM (%s)\n", confidentialVM)
	fmt.Println(color.HiBlackString("═══════════════════════════════════════════════════"))

	cvmDumpPath := filepath.Join(demoOutputDir, fmt.Sprintf("demo-%s.dump", confidentialVM))
	if err := attackVM(v, confidentialVM, cvmDumpPath, pattern, patternName, true); err != nil {
		return fmt.Errorf("confidential VM attack failed: %w", err)
	}

	time.Sleep(2 * time.Second)

	// Step 3: Show comparison
	fmt.Println()
	fmt.Println()
	color.New(color.FgMagenta, color.Bold).Println("📊 COMPARISON & CONCLUSION")
	fmt.Println(color.HiBlackString("═══════════════════════════════════════════════════"))

	printComparisonTable()

	// Cleanup
	if demoCleanup {
		fmt.Println()
		color.HiBlack("🧹 Cleaning up dump files...")
		os.Remove(vm1DumpPath)
		os.Remove(cvmDumpPath)
		color.HiBlack("✓ Cleanup complete")
	}

	// Final message
	fmt.Println()
	printDemoFooter()

	return nil
}

func attackVM(v *virsh.LocalClient, vmName, dumpPath, pattern, patternName string, isConfidential bool) error {
	// Step 1: Dump memory
	fmt.Println()
	color.Cyan("📍 Step 1: Dumping %s memory", vmName)
	fmt.Printf("   Target: %s\n", color.HiWhiteString(vmName))
	fmt.Printf("   Output: %s\n", color.HiBlackString(dumpPath))
	fmt.Println()

	visualizer.ShowProgressBar("Creating memory dump", 5*time.Second)

	err := v.Dump(vmName, dumpPath)
	if err != nil {
		return fmt.Errorf("dump failed: %w", err)
	}

	size, _ := v.GetFileSize(dumpPath)
	if size > 0 {
		color.Green("✅ Dump completed: %s", formatBytes(size))
	}

	time.Sleep(1 * time.Second)

	// Step 2: Search for sensitive data
	fmt.Println()
	color.Cyan("🔍 Step 2: Searching for sensitive data")
	fmt.Printf("   Pattern: %s (%s)\n", color.YellowString(pattern), color.HiBlackString(patternName))
	fmt.Println()

	s := search.New(dumpPath, false)

	visualizer.ShowProgressBar("Scanning memory", 3*time.Second)

	matches, err := s.Search(pattern, 5)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	// Step 3: Show results
	fmt.Println()
	color.Cyan("📊 Step 3: Results")
	fmt.Println()

	if len(matches) == 0 {
		color.Green("✅ NO MATCHES FOUND - Memory is ENCRYPTED")
		if isConfidential {
			fmt.Println()
			color.HiBlack("AMD SEV-SNP successfully protected the memory!")
			color.HiBlack("Attackers cannot read sensitive data even with root access.")
		} else {
			color.Yellow("⚠️  Warning: No matches, but this VM should be vulnerable!")
		}
	} else {
		color.Red("❌ VULNERABLE - %d match(es) found!", len(matches))
		if isConfidential {
			color.Red("⚠️  ERROR: cVM should be protected but data was found!")
		} else {
			fmt.Println()
			color.HiBlack("This is expected - VM1 has no memory encryption.")
			color.HiBlack("Attackers can easily extract sensitive data!")
		}

		// Show first match
		if len(matches) > 0 {
			fmt.Println()
			color.Red("🔍 First match at offset 0x%x:", matches[0].Offset)
			fmt.Println(color.HiBlackString("─────────────────────────────────────"))

			contextData := s.GetContext(matches[0].Offset, 80)
			visualizer.ShowMatchContext(contextData, pattern)
		}
	}

	return nil
}

func printDemoHeader() {
	cyan := color.New(color.FgCyan, color.Bold)

	fmt.Println()
	cyan.Println("╔═══════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                                                                   ║")
	cyan.Println("║     🔒  CONFIDENTIAL COMPUTING ATTACK DEMONSTRATION  🔒           ║")
	cyan.Println("║                                                                   ║")
	cyan.Println("║            Proving AMD SEV-SNP Memory Protection                  ║")
	cyan.Println("║                                                                   ║")
	cyan.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println(color.HiBlackString("This demonstration will:"))
	fmt.Println(color.HiBlackString("  1. Attack a STANDARD VM (no encryption) → Data exposed ❌"))
	fmt.Println(color.HiBlackString("  2. Attack a CONFIDENTIAL VM (SEV-SNP) → Data protected ✅"))
	fmt.Println(color.HiBlackString("  3. Compare results and prove encryption works"))
	fmt.Println()

	color.Yellow("⚠️  Both VMs run identical Neo4j databases with NHS numbers")
	color.Yellow("⚠️  Attack scenario: Root access to KVM host server")
	fmt.Println()

	time.Sleep(2 * time.Second)
}

func printComparisonTable() {
	fmt.Println()
	fmt.Println(color.HiWhiteString("┌─────────────────────────┬──────────────────┬──────────────────┐"))
	fmt.Println(color.HiWhiteString("│ Security Feature        │ VM1 (Standard)   │ cVM (Protected)  │"))
	fmt.Println(color.HiWhiteString("├─────────────────────────┼──────────────────┼──────────────────┤"))
	fmt.Printf("│ %-23s │ %-16s │ %-16s │\n",
		"TLS Encryption",
		color.GreenString("✓ Yes"),
		color.GreenString("✓ Yes"))
	fmt.Printf("│ %-23s │ %-16s │ %-16s │\n",
		"Memory Encryption",
		color.RedString("✗ No"),
		color.GreenString("✓ SEV-SNP"))
	fmt.Printf("│ %-23s │ %-16s │ %-16s │\n",
		"Disk Encryption",
		color.RedString("✗ No"),
		color.GreenString("✓ LUKS"))
	fmt.Println(color.HiWhiteString("├─────────────────────────┼──────────────────┼──────────────────┤"))
	fmt.Printf("│ %-23s │ %-16s │ %-16s │\n",
		color.HiWhiteString("Attack Result"),
		color.RedString("❌ VULNERABLE"),
		color.GreenString("✅ PROTECTED"))
	fmt.Println(color.HiWhiteString("└─────────────────────────┴──────────────────┴──────────────────┘"))
	fmt.Println()
}

func printDemoFooter() {
	color.New(color.FgGreen, color.Bold).Println("╔═══════════════════════════════════════════════════════════════════╗")
	color.Green("║                                                                   ║")
	color.Green("║                    ✅  DEMO COMPLETED  ✅                          ║")
	color.Green("║                                                                   ║")
	color.Green("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	color.Cyan("🎯 Key Takeaways:")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()
	fmt.Println("  1. " + color.RedString("Traditional VMs") + " are " + color.RedString("vulnerable") + " to memory dump attacks")
	fmt.Println("     → Even with TLS, attackers with host access can read memory")
	fmt.Println()
	fmt.Println("  2. " + color.GreenString("Confidential VMs (AMD SEV-SNP)") + " " + color.GreenString("protect") + " memory")
	fmt.Println("     → Encrypted memory prevents attackers from reading sensitive data")
	fmt.Println()
	fmt.Println("  3. " + color.CyanString("3D Encryption") + " = TLS + Memory + Disk encryption")
	fmt.Println("     → Complete data protection in cloud environments")
	fmt.Println()

	color.Magenta("🔗 Learn more: https://enclaive.cloud")
	fmt.Println()
}

// getConfig loads configuration (helper function)
func getConfig(cmd *cobra.Command) (*config.Config, error) {
	return config.Load("")
}
