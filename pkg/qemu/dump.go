package qemu

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Note: strconv is used by GetFileSize

// Dump creates a memory dump of a VM using virsh dump (guest memory)
// This is the default method as it properly dumps guest VM memory.
// gcore only dumps QEMU process memory which doesn't contain guest data.
func (c *Client) Dump(vmName string, outputDir string) (string, error) {
	// Check if virsh is available
	if _, err := exec.LookPath("virsh"); err != nil {
		return "", fmt.Errorf("virsh not available: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-%s.dump", vmName, timestamp))

	if c.Verbose {
		fmt.Printf("→ Dumping VM %s to %s\n", vmName, outputPath)
	}

	cmd := exec.Command("sudo", "virsh", "dump", vmName, outputPath, "--memory-only")

	if c.Verbose {
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

// DumpWithQMP creates a memory dump using QMP dump-guest-memory command
// This is an alternative to virsh dump, useful for direct QEMU access
func (c *Client) DumpWithQMP(vmName string, outputDir string) (string, error) {
	// Check if virsh is available (we use virsh qemu-monitor-command)
	if _, err := exec.LookPath("virsh"); err != nil {
		return "", fmt.Errorf("virsh not available for QMP access: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-%s.dump", vmName, timestamp))

	// Use QMP dump-guest-memory via virsh
	qmpCmd := fmt.Sprintf(`{"execute":"dump-guest-memory","arguments":{"paging":false,"protocol":"file:%s"}}`, outputPath)
	cmd := exec.Command("sudo", "virsh", "qemu-monitor-command", vmName, qmpCmd)

	if c.Verbose {
		fmt.Printf("→ Running QMP: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("QMP dump failed: %w (output: %s)", err, string(output))
	}

	// Make dump file readable
	exec.Command("sudo", "chmod", "644", outputPath).Run()

	return outputPath, nil
}

// GetFileSize returns the size of a file
func (c *Client) GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		// Try with sudo
		cmd := exec.Command("sudo", "stat", "-c", "%s", path)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("stat failed: %w", err)
		}

		size, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse size: %w", err)
		}
		return size, nil
	}
	return info.Size(), nil
}

// RemoveFile removes a file
func (c *Client) RemoveFile(path string) error {
	err := os.Remove(path)
	if err != nil {
		// Try with sudo
		cmd := exec.Command("sudo", "rm", "-f", path)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("rm failed: %w (output: %s)", err, string(output))
		}
	}
	return nil
}
