package virsh

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// VM represents a virtual machine
type VM struct {
	ID     string
	Name   string
	State  string
	HasSEV bool
}

// LocalClient for running virsh commands directly on the host
type LocalClient struct {
	Verbose bool
}

// NewLocal creates a new local virsh client
func NewLocal(verbose bool) *LocalClient {
	return &LocalClient{
		Verbose: verbose,
	}
}

// List returns all VMs on the local host
func (c *LocalClient) List() ([]VM, error) {
	cmd := exec.Command("sudo", "virsh", "list", "--all")

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("virsh list failed: %w (output: %s)", err, string(output))
	}

	return parseVMList(string(output)), nil
}

// Dump creates a memory dump of a VM
func (c *LocalClient) Dump(vmName, outputPath string) error {
	cmd := exec.Command("sudo", "virsh", "dump", vmName, outputPath, "--memory-only")

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("virsh dump failed: %w (output: %s)", err, string(output))
	}

	// Make dump file readable by current user
	chmodCmd := exec.Command("sudo", "chmod", "644", outputPath)
	chmodCmd.Run()

	return nil
}

// GetDiskPath returns the disk path for a VM
func (c *LocalClient) GetDiskPath(vmName string) (string, error) {
	cmd := exec.Command("sudo", "virsh", "domblklist", vmName)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("virsh domblklist failed: %w", err)
	}

	// Parse output to find disk path
	// Format: "vda    /path/to/disk.qcow2"
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "vda") || strings.HasPrefix(line, "sda") || strings.HasPrefix(line, "hda") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1], nil
			}
		}
	}

	return "", fmt.Errorf("no disk found for VM %s", vmName)
}

// GetFileSize returns size of a file
func (c *LocalClient) GetFileSize(path string) (int64, error) {
	cmd := exec.Command("sudo", "stat", "-c", "%s", path)

	if c.Verbose {
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

// RemoveFile removes a file
func (c *LocalClient) RemoveFile(path string) error {
	cmd := exec.Command("sudo", "rm", "-f", path)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rm failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// SearchDisk searches for pattern in disk file
func (c *LocalClient) SearchDisk(diskPath, pattern string, maxMatches int) ([]DiskMatch, error) {
	grepCmd := fmt.Sprintf("sudo grep -a -b --text '%s' '%s' 2>/dev/null | head -n %d",
		pattern, diskPath, maxMatches)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", grepCmd)
	}

	cmd := exec.Command("bash", "-c", grepCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// grep returns exit code 1 if no matches found
		if strings.Contains(string(output), "No such file") {
			return nil, fmt.Errorf("disk file not found: %s", diskPath)
		}
		// No matches is not an error for us
		return []DiskMatch{}, nil
	}

	return parseDiskMatches(string(output)), nil
}

// GetDiskContext retrieves context around offset in disk file
func (c *LocalClient) GetDiskContext(diskPath string, offset int64, contextSize int) ([]byte, error) {
	start := offset - int64(contextSize)
	if start < 0 {
		start = 0
		contextSize = int(offset)
	}

	ddCmd := fmt.Sprintf("sudo dd if='%s' bs=1 skip=%d count=%d 2>/dev/null",
		diskPath, start, contextSize)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", ddCmd)
	}

	cmd := exec.Command("bash", "-c", ddCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return output, nil
}

// DiskMatch represents a disk search match
type DiskMatch struct {
	Offset int64
	Data   []byte
}

// parseDiskMatches parses grep -b output
func parseDiskMatches(output string) []DiskMatch {
	var matches []DiskMatch

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse offset:text
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		var offset int64
		_, err := fmt.Sscanf(parts[0], "%d", &offset)
		if err != nil {
			continue
		}

		matches = append(matches, DiskMatch{
			Offset: offset,
			Data:   []byte(parts[1]),
		})
	}

	return matches
}

// parseVMList parses virsh list output
func parseVMList(output string) []VM {
	var vms []VM

	// Match lines like: " 5    neo4j-cvm   running"
	re := regexp.MustCompile(`^\s*(\d+|-)\s+(\S+)\s+(\S.*)$`)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Id") || strings.HasPrefix(line, "--") || line == "" {
			continue // Skip header and separator
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 4 {
			id := matches[1]
			name := matches[2]
			state := strings.TrimSpace(matches[3])

			// Detect SEV-SNP VMs by name
			hasSEV := strings.Contains(strings.ToLower(name), "cvm") ||
				strings.Contains(strings.ToLower(name), "sev") ||
				strings.Contains(strings.ToLower(name), "confidential")

			vms = append(vms, VM{
				ID:     id,
				Name:   name,
				State:  state,
				HasSEV: hasSEV,
			})
		}
	}

	return vms
}
