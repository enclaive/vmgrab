package qemu

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/enclaive/vmgrab/pkg/backend"
)

func init() {
	backend.Register("qemu", func(verbose bool) backend.Backend {
		return New(verbose)
	})
}

// Backend implements direct QEMU access via process parsing and QMP
type Backend struct {
	Verbose bool
}

// New creates a new QEMU backend
func New(verbose bool) *Backend {
	return &Backend{Verbose: verbose}
}

// Name returns the backend name
func (b *Backend) Name() string {
	return "qemu"
}

// Available checks if QEMU processes exist
func (b *Backend) Available() bool {
	cmd := exec.Command("pgrep", "-f", "qemu-system")
	err := cmd.Run()
	return err == nil
}

// List returns all QEMU VMs by parsing process list
func (b *Backend) List() ([]backend.VM, error) {
	cmd := exec.Command("ps", "aux")

	if b.Verbose {
		fmt.Printf("→ Running: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ps aux failed: %w", err)
	}

	return b.parseProcessList(string(output))
}

// parseProcessList extracts QEMU VMs from ps aux output
func (b *Backend) parseProcessList(output string) ([]backend.VM, error) {
	var vms []backend.VM

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

		// Detect security from cmdline
		security := b.detectSecurity(pid)

		// Find QMP socket path
		qmpSocket := b.findQMPSocket(pid)

		vm := backend.VM{
			Name:     name,
			PID:      pid,
			State:    "running",
			Security: security,
		}

		// Store QMP socket in extended info if needed
		_ = qmpSocket

		vms = append(vms, vm)
	}

	return vms, nil
}

// detectSecurity checks if a VM has SEV/TDX enabled from cmdline
func (b *Backend) detectSecurity(pid int) string {
	cmdline, err := b.getCmdLine(pid)
	if err != nil {
		return ""
	}

	// Check for SEV-SNP
	if strings.Contains(cmdline, "sev-snp-guest") {
		return "SEV-SNP"
	}

	// Check for SEV (legacy)
	if strings.Contains(cmdline, "sev-guest") {
		return "SEV"
	}

	// Check for TDX (Intel)
	if strings.Contains(cmdline, "tdx-guest") {
		return "TDX"
	}

	return ""
}

// getCmdLine reads the full command line from /proc/PID/cmdline
func (b *Backend) getCmdLine(pid int) (string, error) {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)

	if b.Verbose {
		fmt.Printf("→ Reading: %s\n", path)
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read cmdline: %w", err)
	}

	// cmdline uses null bytes as separators
	return strings.ReplaceAll(string(data), "\x00", " "), nil
}

// findQMPSocket finds the QMP socket path from cmdline
func (b *Backend) findQMPSocket(pid int) string {
	cmdline, err := b.getCmdLine(pid)
	if err != nil {
		return ""
	}

	// Look for -qmp unix:/path/to/socket
	re := regexp.MustCompile(`-qmp\s+unix:([^,\s]+)`)
	matches := re.FindStringSubmatch(cmdline)
	if len(matches) > 1 {
		return matches[1]
	}

	// Look for -chardev socket...path=
	re2 := regexp.MustCompile(`-chardev\s+socket[^-]*path=([^,\s]+)`)
	matches2 := re2.FindStringSubmatch(cmdline)
	if len(matches2) > 1 {
		return matches2[1]
	}

	return ""
}

// Dump creates a memory dump using QMP dump-guest-memory
// Falls back to virsh if QMP socket is not available
func (b *Backend) Dump(vmName string, outputDir string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-%s.dump", vmName, timestamp))

	// Find the VM to get its PID
	vms, err := b.List()
	if err != nil {
		return "", err
	}

	var vm *backend.VM
	for i := range vms {
		if vms[i].Name == vmName {
			vm = &vms[i]
			break
		}
	}

	if vm == nil {
		return "", fmt.Errorf("VM not found: %s", vmName)
	}

	// Try to find QMP socket
	qmpSocket := b.findQMPSocket(vm.PID)

	if qmpSocket != "" && b.canConnectQMP(qmpSocket) {
		// Use direct QMP
		if b.Verbose {
			fmt.Printf("→ Using QMP socket: %s\n", qmpSocket)
		}
		return b.dumpViaQMP(qmpSocket, outputPath)
	}

	// Fall back to virsh qemu-monitor-command (works when libvirt manages QMP)
	if b.Verbose {
		fmt.Printf("→ QMP socket not accessible, using virsh qemu-monitor-command\n")
	}
	return b.dumpViaVirsh(vmName, outputPath)
}

// canConnectQMP checks if we can connect to the QMP socket
func (b *Backend) canConnectQMP(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// dumpViaQMP performs memory dump using direct QMP connection
func (b *Backend) dumpViaQMP(socketPath string, outputPath string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("failed to connect to QMP socket: %w", err)
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// Read greeting
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read QMP greeting: %w", err)
	}

	if b.Verbose {
		fmt.Printf("→ QMP greeting: %s\n", string(buf[:n]))
	}

	// Send qmp_capabilities
	_, err = conn.Write([]byte(`{"execute":"qmp_capabilities"}` + "\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send qmp_capabilities: %w", err)
	}

	// Read response
	n, err = conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read qmp_capabilities response: %w", err)
	}

	if b.Verbose {
		fmt.Printf("→ QMP capabilities response: %s\n", string(buf[:n]))
	}

	// Send dump-guest-memory
	dumpCmd := fmt.Sprintf(`{"execute":"dump-guest-memory","arguments":{"paging":false,"protocol":"file:%s"}}`, outputPath)
	_, err = conn.Write([]byte(dumpCmd + "\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send dump-guest-memory: %w", err)
	}

	// Read response (may take a while for large dumps)
	conn.SetDeadline(time.Now().Add(10 * time.Minute))
	n, err = conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read dump response: %w", err)
	}

	response := string(buf[:n])
	if b.Verbose {
		fmt.Printf("→ QMP dump response: %s\n", response)
	}

	// Check for error
	var result map[string]interface{}
	if err := json.Unmarshal(buf[:n], &result); err == nil {
		if _, hasError := result["error"]; hasError {
			return "", fmt.Errorf("QMP dump failed: %s", response)
		}
	}

	// Make dump file readable
	exec.Command("sudo", "chmod", "644", outputPath).Run()

	return outputPath, nil
}

// dumpViaVirsh performs memory dump using virsh qemu-monitor-command
func (b *Backend) dumpViaVirsh(vmName string, outputPath string) (string, error) {
	// Use QMP dump-guest-memory via virsh
	qmpCmd := fmt.Sprintf(`{"execute":"dump-guest-memory","arguments":{"paging":false,"protocol":"file:%s"}}`, outputPath)
	cmd := exec.Command("sudo", "virsh", "qemu-monitor-command", vmName, qmpCmd)

	if b.Verbose {
		fmt.Printf("→ Running QMP via virsh: %s\n", cmd.String())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("QMP dump via virsh failed: %w (output: %s)", err, string(output))
	}

	// Make dump file readable
	exec.Command("sudo", "chmod", "644", outputPath).Run()

	return outputPath, nil
}

// GetFileSize returns the size of a file
func (b *Backend) GetFileSize(path string) (int64, error) {
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
