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

	podsHidden := backend.PodBackendBlockedByPerms()
	if podsHidden {
		color.New(color.FgYellow).Println(
			"\n⚠️  crictl detected but not accessible — Kubernetes pods are hidden.\n" +
				"   Re-run with sudo to list pod targets (runc + Kata).")
	}

	if len(vms) == 0 {
		if podsHidden {
			fmt.Println("\nNo targets found (pods hidden — see warning above).")
		} else {
			fmt.Println("\nNo targets found")
		}
		return nil
	}

	// Detect whether any target carries pod metadata; if so, render a KIND
	// column and prefix names with their namespace.
	hasPods := false
	for _, vm := range vms {
		if vm.Kind != "" {
			hasPods = true
			break
		}
	}

	displayName := func(vm backend.VM) string {
		if vm.Namespace != "" {
			return vm.Namespace + "/" + vm.Name
		}
		return vm.Name
	}

	// Calculate max name width
	nameWidth := 4 // minimum "NAME"
	for _, vm := range vms {
		if n := len(displayName(vm)); n > nameWidth {
			nameWidth = n
		}
	}
	// Add padding
	nameWidth += 2

	kindWidth := 0
	if hasPods {
		kindWidth = 10 // "pod-kata" + padding
	}

	// Calculate total width for separator
	totalWidth := 8 + nameWidth + 12 + kindWidth + 18

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	if hasPods {
		cyan.Printf("\n🖥️  Targets\n")
	} else {
		cyan.Printf("\n🖥️  Virtual Machines\n")
	}
	fmt.Println(color.HiBlackString(repeatStr("━", totalWidth)))

	// Print table header
	if hasPods {
		fmt.Printf("%-8s %-*s %-12s %-*s %s\n", "PID", nameWidth, "NAME", "STATE", kindWidth, "KIND", "SECURITY")
	} else {
		fmt.Printf("%-8s %-*s %-12s %s\n", "PID", nameWidth, "NAME", "STATE", "SECURITY")
	}
	fmt.Println(color.HiBlackString(repeatStr("━", totalWidth)))

	// Print VMs
	for _, vm := range vms {
		// Format PID
		pid := fmt.Sprintf("%-8s", strconv.Itoa(vm.PID))

		// Format name with dynamic width
		namePadded := fmt.Sprintf("%-*s", nameWidth, displayName(vm))

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

		if hasPods {
			kind := vm.Kind
			if kind == "" {
				kind = "vm"
			}
			fmt.Printf("%s %s %s %-*s %s\n",
				pid,
				color.CyanString(namePadded),
				stateStr,
				kindWidth, kind,
				securityLabel,
			)
		} else {
			fmt.Printf("%s %s %s %s\n",
				pid,
				color.CyanString(namePadded),
				stateStr,
				securityLabel,
			)
		}
	}

	fmt.Println(color.HiBlackString(repeatStr("━", totalWidth)))
	totalLabel := "VMs"
	if hasPods {
		totalLabel = "targets"
	}
	fmt.Printf("\n%s\n\n", color.HiBlackString(fmt.Sprintf("Total: %d %s", len(vms), totalLabel)))

	return nil
}

func repeatStr(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
