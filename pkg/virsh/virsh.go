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

// Client represents a virsh client for remote KVM host
type Client struct {
	Host    string
	User    string
	KeyPath string
	Verbose bool
}

// New creates a new virsh client
func New(host, user, keyPath string, verbose bool) *Client {
	return &Client{
		Host:    host,
		User:    user,
		KeyPath: keyPath,
		Verbose: verbose,
	}
}

// List returns all VMs on the host
func (c *Client) List() ([]VM, error) {
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'sudo virsh list --all' 2>&1 | grep -v Warning:",
		c.KeyPath, c.User, c.Host)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", sshCmd)
	}

	output, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("virsh list failed: %w (output: %s)", err, string(output))
	}

	return parseVMList(string(output)), nil
}

// Dump creates a memory dump of a VM
func (c *Client) Dump(vmName, outputPath string) error {
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'sudo virsh dump %s %s --memory-only' 2>&1 | grep -v Warning:",
		c.KeyPath, c.User, c.Host, vmName, outputPath)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", sshCmd)
	}

	cmd := exec.Command("bash", "-c", sshCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("virsh dump failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// FileInfo represents remote file information
type FileInfo struct {
	Path string
	Size int64
}

// GetFileInfo retrieves information about a remote file
func (c *Client) GetFileInfo(remotePath string) (*FileInfo, error) {
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'stat -c \"%%s\" %s' 2>&1 | grep -v Warning:",
		c.KeyPath, c.User, c.Host, remotePath)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", sshCmd)
	}

	output, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("stat failed: %w", err)
	}

	var size int64
	_, err = fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &size)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file size: %w", err)
	}

	return &FileInfo{
		Path: remotePath,
		Size: size,
	}, nil
}

// DownloadFile downloads a file from remote host with progress bar
func (c *Client) DownloadFile(remotePath, localPath string, progressBar interface{ Add64(int64) error }) error {
	// Use scp to download
	scpCmd := fmt.Sprintf("scp -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s:%s %s 2>&1 | grep -v Warning:",
		c.KeyPath, c.User, c.Host, remotePath, localPath)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", scpCmd)
	}

	// For simplicity, just execute scp without real-time progress
	// Real-time progress would require parsing scp output or using rsync
	cmd := exec.Command("bash", "-c", scpCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp failed: %w (output: %s)", err, string(output))
	}

	// Update progress bar to 100%
	if progressBar != nil {
		info, _ := c.GetFileInfo(remotePath)
		if info != nil {
			progressBar.Add64(info.Size)
		}
	}

	return nil
}

// RemoveFile removes a file from remote host
func (c *Client) RemoveFile(remotePath string) error {
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'sudo rm -f %s' 2>&1 | grep -v Warning:",
		c.KeyPath, c.User, c.Host, remotePath)

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", sshCmd)
	}

	output, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rm failed: %w (output: %s)", err, string(output))
	}

	return nil
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
