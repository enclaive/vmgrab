package qemu

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// VM represents a QEMU virtual machine process
type VM struct {
	PID     int
	Name    string
	State   string
	CmdLine string
}

// Client provides methods to interact with QEMU processes
type Client struct {
	Verbose bool
}

// NewClient creates a new QEMU process client
func NewClient(verbose bool) *Client {
	return &Client{
		Verbose: verbose,
	}
}

// List returns all running QEMU VMs by parsing process list
func (c *Client) List() ([]VM, error) {
	cmd := exec.Command("ps", "aux")

	if c.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ps aux failed: %w", err)
	}

	return c.parseProcessList(string(output)), nil
}

// parseProcessList extracts QEMU VMs from ps aux output
func (c *Client) parseProcessList(output string) []VM {
	var vms []VM

	// Match VM name from: -name guest=XXX or -name XXX
	nameRe := regexp.MustCompile(`-name\s+(?:guest=)?([^,\s]+)`)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Skip non-QEMU processes
		if !strings.Contains(line, "qemu-system") {
			continue
		}

		// Skip grep itself
		if strings.Contains(line, "grep") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// PID is the second field in ps aux output
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		// Extract VM name from command line
		name := "unknown"
		matches := nameRe.FindStringSubmatch(line)
		if len(matches) > 1 {
			name = matches[1]
		}

		vms = append(vms, VM{
			PID:     pid,
			Name:    name,
			State:   "running",
			CmdLine: line,
		})
	}

	return vms
}

// GetVMByName finds a VM by its name
func (c *Client) GetVMByName(name string) (*VM, error) {
	vms, err := c.List()
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.Name == name {
			return &vm, nil
		}
	}

	return nil, fmt.Errorf("VM not found: %s", name)
}

// GetCmdLine reads the full command line from /proc/PID/cmdline
func (c *Client) GetCmdLine(pid int) (string, error) {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)

	if c.Verbose {
		fmt.Printf("→ Reading: %s\n", path)
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read cmdline: %w", err)
	}

	// cmdline uses null bytes as separators
	return strings.ReplaceAll(string(data), "\x00", " "), nil
}

// DetectSEV checks if a VM has SEV/SEV-SNP enabled by examining its command line
func (c *Client) DetectSEV(pid int) (bool, string) {
	cmdline, err := c.GetCmdLine(pid)
	if err != nil {
		return false, ""
	}

	// Check for SEV-SNP
	if strings.Contains(cmdline, "sev-snp-guest") {
		return true, "SEV-SNP"
	}

	// Check for SEV (legacy)
	if strings.Contains(cmdline, "sev-guest") {
		return true, "SEV"
	}

	// Check for TDX (Intel)
	if strings.Contains(cmdline, "tdx-guest") {
		return true, "TDX"
	}

	return false, ""
}
