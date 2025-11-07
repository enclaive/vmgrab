package cmd

import (
	"fmt"

	"github.com/enclaive/vmgrab/pkg/virsh"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all VMs on the KVM host",
	Long:  "Execute 'virsh list --all' and display VMs in a formatted table",
	RunE:  runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")

	v := virsh.NewLocal(verbose)

	vms, err := v.List()
	if err != nil {
		return fmt.Errorf("failed to list VMs: %w", err)
	}

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\n🖥️  Virtual Machines (Local)")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	// Print table header
	fmt.Printf("%-5s %-20s %-12s %-20s\n", "ID", "NAME", "STATE", "SECURITY")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	// Print VMs
	for _, vm := range vms {
		var stateColor, securityLabel string

		// Color-code state
		if vm.State == "running" {
			stateColor = color.GreenString("● running")
		} else {
			stateColor = color.HiBlackString("○ " + vm.State)
		}

		// Detect SEV-SNP VMs
		if vm.Name == "neo4j-cvm" || vm.HasSEV {
			securityLabel = color.GreenString("🔒 SEV-SNP Protected")
		} else if vm.Name == "neo4j-vm1" {
			securityLabel = color.RedString("⚠️  Vulnerable (no encryption)")
		} else {
			securityLabel = color.HiBlackString("Unknown")
		}

		fmt.Printf("%-5s %-20s %-12s %-20s\n",
			vm.ID,
			color.CyanString(vm.Name),
			stateColor,
			securityLabel,
		)
	}

	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Printf("\n%s\n\n", color.HiBlackString(fmt.Sprintf("Total: %d VMs", len(vms))))

	return nil
}
