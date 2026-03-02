package cmd

import (
	"fmt"
	"strconv"

	"github.com/enclaive/vmgrab/pkg/backend"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all QEMU VMs on the host",
	Long:  "Scan running QEMU processes and display VMs with their security status",
	RunE:  runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Get VMs from all available backends
	vms, err := backend.ListAll(verbose)
	if err != nil {
		return fmt.Errorf("failed to list VMs: %w", err)
	}

	if len(vms) == 0 {
		fmt.Println("\nNo VMs found")
		return nil
	}

	// Calculate max name width
	nameWidth := 4 // minimum "NAME"
	for _, vm := range vms {
		if len(vm.Name) > nameWidth {
			nameWidth = len(vm.Name)
		}
	}
	// Add padding
	nameWidth += 2

	// Calculate total width for separator
	totalWidth := 8 + nameWidth + 12 + 18 // PID + NAME + STATE + SECURITY

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("\n🖥️  Virtual Machines\n")
	fmt.Println(color.HiBlackString(repeatStr("━", totalWidth)))

	// Print table header
	fmt.Printf("%-8s %-*s %-12s %s\n", "PID", nameWidth, "NAME", "STATE", "SECURITY")
	fmt.Println(color.HiBlackString(repeatStr("━", totalWidth)))

	// Print VMs
	for _, vm := range vms {
		// Format PID
		pid := fmt.Sprintf("%-8s", strconv.Itoa(vm.PID))

		// Format name with dynamic width
		namePadded := fmt.Sprintf("%-*s", nameWidth, vm.Name)

		// Format state
		var stateStr string
		if vm.State == "running" {
			stateStr = color.GreenString("●") + " running   "
		} else {
			stateStr = color.HiBlackString("○") + fmt.Sprintf(" %-9s", vm.State)
		}

		// Format security
		var securityLabel string
		if vm.Security != "" {
			securityLabel = color.GreenString("🔒 " + vm.Security)
		} else {
			securityLabel = color.RedString("⚠️  Unprotected")
		}

		fmt.Printf("%s %s %s %s\n",
			pid,
			color.CyanString(namePadded),
			stateStr,
			securityLabel,
		)
	}

	fmt.Println(color.HiBlackString(repeatStr("━", totalWidth)))
	fmt.Printf("\n%s\n\n", color.HiBlackString(fmt.Sprintf("Total: %d VMs", len(vms))))

	return nil
}

func repeatStr(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
