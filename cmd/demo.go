package cmd

import (
	"fmt"
	"github.com/enclaive/vmgrab/pkg/backend"
	"github.com/enclaive/vmgrab/pkg/config"
	"github.com/enclaive/vmgrab/pkg/search"
	"github.com/spf13/cobra"
)

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run complete attack demonstration",
	Long: `Automatically run the full confidential computing demo:
1. Dump standard target memory (runc pod or unprotected VM)
2. Search for sensitive data in the standard dump
3. Dump confidential target memory (Kata-SNP pod or SEV-SNP VM)
4. Search for the same data in the confidential dump
5. Compare observed results and check the positive control

Target type is selected via --target=vm (default) or --target=pod;
passing --standard-pod / --confidential-pod implies --target=pod.

The demo can be customized via config file (.vmgrab.yaml)
or command-line flags.`,
	RunE: runDemo,
}

var (
	demoStandardVM      string
	demoConfidentialVM  string
	demoStandardPod     string
	demoConfidentialPod string
	demoTarget          string
	demoPattern         string
	demoPatternName     string
	demoCleanup         bool
	demoOutputDir       string
)

func init() {
	rootCmd.AddCommand(demoCmd)
	demoCmd.Flags().StringVar(&demoStandardVM, "standard-vm", "", "Standard VM name (overrides config)")
	demoCmd.Flags().StringVar(&demoConfidentialVM, "confidential-vm", "", "Confidential VM name (overrides config)")
	demoCmd.Flags().StringVar(&demoStandardPod, "standard-pod", "", "Standard pod (ns/name). Implies --target=pod.")
	demoCmd.Flags().StringVar(&demoConfidentialPod, "confidential-pod", "", "Kata-SNP pod (ns/name). Implies --target=pod.")
	demoCmd.Flags().StringVar(&demoTarget, "target", "", "Target type: vm (default) or pod")
	demoCmd.Flags().StringVarP(&demoPattern, "pattern", "p", "", "Pattern to search for (overrides config)")
	demoCmd.Flags().StringVar(&demoPatternName, "pattern-name", "", "Description of the pattern (e.g., 'NHS Number')")
	demoCmd.Flags().BoolVarP(&demoCleanup, "cleanup", "c", true, "Clean up dump files after demo")
	demoCmd.Flags().StringVarP(&demoOutputDir, "output", "o", "/tmp", "Output directory for dumps")
}

// resolveDemoTarget decides whether this run targets VMs or pods.
// Priority: explicit --target flag, then any --*-pod flag, then
// config.Pods.Standard.Name, then default "vm".
func resolveDemoTarget(cfg *config.Config) string {
	if demoTarget != "" {
		return demoTarget
	}
	if demoStandardPod != "" || demoConfidentialPod != "" {
		return "pod"
	}
	if cfg.Pods.Standard.Name != "" {
		return "pod"
	}
	return "vm"
}

func runDemo(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	pattern := demoPattern
	if pattern == "" && len(cfg.Search) > 0 {
		pattern = cfg.Search[0].Pattern
	}
	if err := search.ValidatePattern(pattern, 5); err != nil {
		return err
	}
	verbose, _ := cmd.Flags().GetBool("verbose")
	target := resolveDemoTarget(cfg)
	standard, confidential := demoStandardVM, demoConfidentialVM
	if standard == "" {
		standard = cfg.VMs.Standard.Name
	}
	if confidential == "" {
		confidential = cfg.VMs.Confidential.Name
	}
	if target == "pod" {
		standard, confidential = demoStandardPod, demoConfidentialPod
		if standard == "" {
			standard = cfg.Pods.Standard.Ref()
		}
		if confidential == "" {
			confidential = cfg.Pods.Confidential.Ref()
		}
	} else if target != "vm" {
		return fmt.Errorf("unknown demo target %q", target)
	}
	if standard == "" || confidential == "" || standard == "/" || confidential == "/" {
		return fmt.Errorf("both standard and confidential targets are required")
	}
	if standard == confidential {
		return fmt.Errorf("standard and confidential targets must differ")
	}
	var phases [2]demoPhase
	for i, name := range []string{standard, confidential} {
		phases[i].Target = name
		fmt.Printf("\nPHASE %d: %s\n", i+1, name)
		var b backend.Backend
		if target == "pod" {
			b = backend.Get("pod", verbose)
			if b == nil || !b.Available() {
				phases[i].Err = fmt.Errorf("pod backend unavailable")
			}
		} else {
			b, phases[i].Err = targetBackend(name, verbose)
		}
		if phases[i].Err == nil {
			path, captureErr := b.Dump(name, demoOutputDir)
			if demoCleanup {
				defer cleanupCapture(path)
			}
			phases[i].Err = captureErr
			if path != "" {
				s := search.New(path, verbose)
				a, err := s.Analyze(pattern, 5)
				phases[i].Analysis = a
				if err != nil {
					phases[i].Err = err
				} else {
					printAnalysis(s, a, 60)
					if err := a.Check(); err != nil {
						phases[i].Err = err
					}
				}
			}
		}
		if phases[i].Err != nil {
			fmt.Printf("Phase failed: %v\n", phases[i].Err)
		}
	}
	printComparison(phases)
	if err := checkDemo(phases[0], phases[1]); err != nil {
		return err
	}
	fmt.Println("PASS: pattern observed in the standard capture and not observed in the confidential capture.")
	fmt.Println("This comparison describes the captured mappings; it does not attest the guest or prove encryption.")
	return nil
}

type demoPhase struct {
	Target   string
	Analysis *search.Analysis
	Err      error
}

func printComparison(phases [2]demoPhase) {
	fmt.Println("\nTarget | Pattern result | Configured CC | Capture")
	for _, p := range phases {
		status, security, coverage := "ERROR", "not recorded", "unknown"
		if a := p.Analysis; a != nil {
			status = a.Status()
			if a.Meta != nil {
				if a.Meta.Security != "" {
					security = a.Meta.Security
				}
				if a.Meta.Capture != nil {
					coverage = fmt.Sprintf("selected mappings complete=%v", a.Meta.Capture.Complete)
				}
			}
			if len(a.Incomplete) > 0 {
				coverage = "INCOMPLETE"
			}
		}
		if p.Err != nil {
			coverage = "ERROR/INCOMPLETE"
		}
		fmt.Printf("%s | %s | %s | %s\n", p.Target, status, security, coverage)
	}
}

func checkDemo(standard, confidential demoPhase) error {
	for _, p := range []demoPhase{standard, confidential} {
		if p.Err != nil {
			return fmt.Errorf("demo incomplete for %s: %w", p.Target, p.Err)
		}
		if p.Analysis == nil {
			return fmt.Errorf("demo has no result for %s", p.Target)
		}
		if err := p.Analysis.Check(); err != nil {
			return err
		}
	}
	if len(standard.Analysis.Scan.Matches) == 0 {
		return fmt.Errorf("demo invalid: positive control did not find the pattern in the standard capture")
	}
	if standard.Analysis.Meta != nil && standard.Analysis.Meta.Security != "" {
		return fmt.Errorf("demo invalid: standard target has confidential computing configured")
	}
	if len(confidential.Analysis.Scan.Matches) > 0 {
		return fmt.Errorf("demo expectation failed: requested data is readable in the confidential capture; this alone does not identify a private-memory leak")
	}
	if confidential.Analysis.Meta == nil || confidential.Analysis.Meta.Security == "" {
		return fmt.Errorf("demo inconclusive: confidential computing was not recorded for the confidential target")
	}
	if confidential.Analysis.Meta.Capture == nil {
		return fmt.Errorf("demo inconclusive: confidential capture coverage was not recorded")
	}
	return nil
}
