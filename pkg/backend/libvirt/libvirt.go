package libvirt

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/enclaive/vmgrab/pkg/backend"
)

func init() {
	backend.Register("libvirt", func(verbose bool) backend.Backend {
		return New(verbose)
	})
}

// Backend implements the libvirt backend using virsh commands
type Backend struct {
	Verbose bool
}

// New creates a new libvirt backend
func New(verbose bool) *Backend {
	return &Backend{Verbose: verbose}
}

// Name returns the backend name
func (b *Backend) Name() string {
	return "libvirt"
}

// Available checks if virsh is available
func (b *Backend) Available() bool {
	_, err := exec.LookPath("virsh")
	return err == nil
}

// List returns all VMs using virsh list
func (b *Backend) List() ([]backend.VM, error) {
	cmd := exec.Command("sudo", "virsh", "list", "--all")

	if b.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("virsh list failed: %w (output: %s)", err, string(output))
	}

	return b.parseVMList(string(output))
}

// parseVMList parses virsh list output and enriches with security info
func (b *Backend) parseVMList(output string) ([]backend.VM, error) {
	var vms []backend.VM

	// Match lines like: " 5    vm-name   running"
	re := regexp.MustCompile(`^\s*(\d+|-)\s+(\S+)\s+(\S.*)$`)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Id") || strings.HasPrefix(line, "--") || line == "" {
			continue // Skip header and separator
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 4 {
			name := matches[2]
			state := strings.TrimSpace(matches[3])

			// Get PID and security status from dumpxml
			pid, security := b.getVMDetails(name)

			vms = append(vms, backend.VM{
				Name:     name,
				PID:      pid,
				State:    state,
				Security: security,
			})
		}
	}

	return vms, nil
}

// getVMDetails gets PID and security type from virsh dumpxml
func (b *Backend) getVMDetails(vmName string) (int, string) {
	cmd := exec.Command("sudo", "virsh", "dumpxml", vmName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, ""
	}

	xml := string(output)
	pid := 0
	security := ""

	// Parse <launchSecurity type="...">
	if strings.Contains(xml, `type="sev-snp"`) || strings.Contains(xml, `type='sev-snp'`) {
		security = "SEV-SNP"
	} else if strings.Contains(xml, `type="sev"`) || strings.Contains(xml, `type='sev'`) {
		security = "SEV"
	} else if strings.Contains(xml, `type="tdx"`) || strings.Contains(xml, `type='tdx'`) {
		security = "TDX"
	}

	// Get PID from virsh dominfo or ps aux
	pidCmd := exec.Command("sudo", "virsh", "dominfo", vmName)
	pidOutput, err := pidCmd.CombinedOutput()
	if err == nil {
		// Parse "Persistent:     yes\nId:             61"
		lines := strings.Split(string(pidOutput), "\n")
		for _, line := range lines {
			// We can't get actual QEMU PID from virsh easily
			// Fall back to ps aux
			_ = line
		}
	}

	// Get QEMU PID from ps aux
	psCmd := exec.Command("bash", "-c", fmt.Sprintf("ps aux | grep 'qemu.*-name.*%s' | grep -v grep | awk '{print $2}'", vmName))
	psOutput, err := psCmd.CombinedOutput()
	if err == nil {
		pidStr := strings.TrimSpace(string(psOutput))
		if pidStr != "" {
			if p, err := strconv.Atoi(strings.Split(pidStr, "\n")[0]); err == nil {
				pid = p
			}
		}
	}

	return pid, security
}

// Dump creates a memory dump using virsh dump
func (b *Backend) Dump(vmName string, outputDir string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-%s.dump", vmName, timestamp))

	if b.Verbose {
		fmt.Printf("→ Dumping VM %s to %s\n", vmName, outputPath)
	}

	cmd := exec.Command("sudo", "virsh", "dump", vmName, outputPath, "--memory-only")

	if b.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("virsh dump failed: %w (output: %s)", err, string(output))
	}

	// Make dump file readable
	exec.Command("sudo", "chmod", "644", outputPath).Run()

	return outputPath, nil
}

// GetFileSize returns the size of a file
func (b *Backend) GetFileSize(path string) (int64, error) {
	cmd := exec.Command("sudo", "stat", "-c", "%s", path)

	if b.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("stat failed: %w", err)
	}

	var size int64
	_, err = fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &size)
	if err != nil {
		return 0, fmt.Errorf("failed to parse size: %w", err)
	}

	return size, nil
}
