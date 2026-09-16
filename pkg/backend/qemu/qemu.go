package qemu

import (
	"bufio"
	"bytes"
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
	"github.com/enclaive/vmgrab/pkg/dumpmeta"
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

	var path string
	if qmpSocket != "" && b.canConnectQMP(qmpSocket) {
		// Use direct QMP
		if b.Verbose {
			fmt.Printf("→ Using QMP socket: %s\n", qmpSocket)
		}
		path, err = b.dumpViaQMP(qmpSocket, outputPath)
	} else {
		// Fall back to virsh qemu-monitor-command (works when libvirt manages QMP)
		if b.Verbose {
			fmt.Printf("→ QMP socket not accessible, using virsh qemu-monitor-command\n")
		}
		path, err = b.dumpViaVirsh(vmName, outputPath)
	}
	if err != nil {
		return "", err
	}

	b.writeMeta(path, vm)
	return path, nil
}

// writeMeta records what was dumped next to the dump file. The decisive field
// is Security: it carries the confidential-computing status detected from the
// QEMU command line at dump time. Without it, `search` cannot tell a protected
// guest from a VM whose kernel simply was not resident yet, since both look
// identical by content (no guest-kernel structures present). Failure to write
// the sidecar is not fatal: the dump itself is still valid.
func (b *Backend) writeMeta(dumpPath string, vm *backend.VM) {
	size := statSizeSudo(dumpPath)
	if size < 0 {
		size = 0
	}
	m := &dumpmeta.Meta{
		Backend:   "qemu",
		Target:    vm.Name,
		PID:       vm.PID,
		Security:  vm.Security,
		Size:      size,
		CreatedAt: time.Now().UTC(),
	}
	if err := m.Write(dumpPath); err != nil && b.Verbose {
		fmt.Printf("→ could not write %s sidecar: %v\n", dumpmeta.Suffix, err)
	}
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

// dumpViaQMP performs memory dump using direct QMP connection.
//
// QMP is asynchronous: the server interleaves unsolicited "event" messages
// (STOP, RESUME, DUMP_COMPLETED) with command replies. The previous
// implementation issued dump-guest-memory and then did a single conn.Read,
// treating whatever came back as the reply. In practice the first datagram was
// frequently an event (e.g. STOP, emitted as the VM pauses for the dump), so
// vmgrab reported success while QEMU was still writing the file. A search run
// immediately afterwards then scanned a partial dump (issue #8). We now
// correlate replies by command id, skip events, and wait for the dump file to
// stop growing before returning.
func (b *Backend) dumpViaQMP(socketPath string, outputPath string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("failed to connect to QMP socket: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Minute))
	reader := bufio.NewReader(conn)

	// Greeting: a single {"QMP": {...}} line.
	if _, err := reader.ReadBytes('\n'); err != nil {
		return "", fmt.Errorf("failed to read QMP greeting: %w", err)
	}

	// Negotiate capabilities.
	if err := b.qmpSend(conn, `{"execute":"qmp_capabilities","id":"caps"}`); err != nil {
		return "", err
	}
	if _, err := b.qmpAwaitReply(reader, "caps"); err != nil {
		return "", fmt.Errorf("qmp_capabilities failed: %w", err)
	}

	// dump-guest-memory is synchronous when detach is false: the reply arrives
	// only after guest memory has been fully written to the file.
	conn.SetDeadline(time.Now().Add(30 * time.Minute))
	dumpCmd := fmt.Sprintf(`{"execute":"dump-guest-memory","arguments":{"paging":false,"detach":false,"protocol":"file:%s"},"id":"dump"}`, outputPath)
	if err := b.qmpSend(conn, dumpCmd); err != nil {
		return "", err
	}
	if _, err := b.qmpAwaitReply(reader, "dump"); err != nil {
		return "", fmt.Errorf("QMP dump failed: %w", err)
	}

	// Belt-and-suspenders: even after the reply, wait until the file size is
	// stable so a downstream search never scans a still-flushing dump.
	if err := waitFileStable(outputPath, b.Verbose); err != nil && b.Verbose {
		fmt.Printf("→ file-stability check: %v\n", err)
	}

	// Make dump file readable
	exec.Command("sudo", "-n", "chmod", "644", outputPath).Run()

	return outputPath, nil
}

// qmpSend writes one QMP command line to conn.
func (b *Backend) qmpSend(conn net.Conn, cmd string) error {
	if b.Verbose {
		fmt.Printf("→ QMP send: %s\n", cmd)
	}
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return fmt.Errorf("failed to write QMP command: %w", err)
	}
	return nil
}

// qmpAwaitReply reads QMP messages line by line until it sees the reply whose
// "id" matches id. Asynchronous "event" messages and the greeting are skipped.
// A reply carrying an "error" object is returned as a Go error.
func (b *Backend) qmpAwaitReply(reader *bufio.Reader, id string) (map[string]interface{}, error) {
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read QMP reply: %w", err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(line, &msg); err != nil {
			continue // ignore non-JSON noise
		}
		if b.Verbose {
			fmt.Printf("→ QMP recv: %s\n", string(line))
		}
		if _, isEvent := msg["event"]; isEvent {
			continue
		}
		if _, isGreeting := msg["QMP"]; isGreeting {
			continue
		}
		if msgID, _ := msg["id"].(string); msgID != id {
			continue // reply for a different (or unlabeled) command
		}
		if errObj, hasErr := msg["error"]; hasErr {
			return nil, fmt.Errorf("%v", errObj)
		}
		return msg, nil
	}
}

// waitFileStable polls the dump file size until it stops changing across two
// consecutive samples, or a 30s timeout elapses. This guards against the file
// still being flushed after the QMP reply. The dump is created by QEMU with
// restrictive permissions, so size is read via sudo when os.Stat is denied.
func waitFileStable(path string, verbose bool) error {
	var last int64 = -1
	stable := 0
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		size := statSizeSudo(path)
		if size >= 0 && size == last {
			if stable++; stable >= 2 {
				if verbose {
					fmt.Printf("→ dump file stable at %d bytes\n", size)
				}
				return nil
			}
		} else {
			stable = 0
		}
		last = size
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("file size not stable after 30s (last=%d)", last)
}

// statSizeSudo returns the file size, falling back to `sudo stat` when the
// file is not yet world-readable. Returns -1 if the size cannot be read.
func statSizeSudo(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	out, err := exec.Command("sudo", "-n", "stat", "-c", "%s", path).Output()
	if err != nil {
		return -1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return -1
	}
	return n
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

	// virsh returns after the monitor command completes, but wait for the file
	// size to settle before returning, matching the direct-QMP path.
	if err := waitFileStable(outputPath, b.Verbose); err != nil && b.Verbose {
		fmt.Printf("→ file-stability check: %v\n", err)
	}

	// Make dump file readable
	exec.Command("sudo", "-n", "chmod", "644", outputPath).Run()

	return outputPath, nil
}

// GetFileSize returns the size of a file
func (b *Backend) GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		// Try with sudo
		cmd := exec.Command("sudo", "-n", "stat", "-c", "%s", path)
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
