package procmem

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/enclaive/vmgrab/pkg/backend"
	"github.com/enclaive/vmgrab/pkg/dumpmeta"
)

func init() {
	backend.Register("procmem", func(verbose bool) backend.Backend {
		return New(verbose)
	})
}

// Backend implements memory dump via /proc/pid/mem
type Backend struct {
	Verbose bool
}

// MemoryRegion represents a memory mapping from /proc/pid/maps
type MemoryRegion struct {
	Start uint64
	End   uint64
	Perms string
	Size  uint64
	Path  string // backing file/device, "" for anonymous mappings
}

// isDeviceBacked reports mappings backed by /dev or /sys, which are device
// MMIO and not guest RAM. A passed-through GPU aperture can be over 100 GiB.
func isDeviceBacked(path string) bool {
	return strings.HasPrefix(path, "/dev/") || strings.HasPrefix(path, "/sys/")
}

// New creates a new procmem backend
func New(verbose bool) *Backend {
	return &Backend{Verbose: verbose}
}

// Name returns the backend name
func (b *Backend) Name() string {
	return "procmem"
}

// Available checks if /proc filesystem is available and we have root access
func (b *Backend) Available() bool {
	// Check if /proc exists
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		return false
	}

	// Check if we can read /proc/self/maps (basic sanity check)
	if _, err := os.ReadFile("/proc/self/maps"); err != nil {
		return false
	}

	return true
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

// qemuBinaryRe matches any common QEMU binary name. Covers Debian/Ubuntu's
// qemu-system-x86_64 family AND RHEL/RHCOS/Fedora's qemu-kvm (which is where
// OpenShift Sandboxed Containers lives). Without the qemu-kvm alternative,
// procmem silently misses every Kata sandbox and every libvirt VM on RHEL.
var qemuBinaryRe = regexp.MustCompile(`qemu-(?:system|kvm)`)

// parseProcessList extracts QEMU VMs from ps aux output
func (b *Backend) parseProcessList(output string) ([]backend.VM, error) {
	var vms []backend.VM

	// Match VM name from: -name guest=XXX or -name XXX
	nameRe := regexp.MustCompile(`-name\s+(?:guest=)?([^,\s]+)`)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Skip non-QEMU processes
		if !qemuBinaryRe.MatchString(line) {
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
		security := b.DetectSecurity(pid)

		vms = append(vms, backend.VM{
			Name:     name,
			PID:      pid,
			State:    "running",
			Security: security,
		})
	}

	return vms, nil
}

// DetectSecurity checks if a process has SEV/TDX enabled from cmdline.
// Exported so other backends (e.g. pod) can classify Kata QEMU sandboxes.
func (b *Backend) DetectSecurity(pid int) string {
	cmdline, err := b.GetCmdLine(pid)
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

// GetCmdLine reads the full command line from /proc/PID/cmdline.
func (b *Backend) GetCmdLine(pid int) (string, error) {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read cmdline: %w", err)
	}
	// cmdline uses null bytes as separators
	return strings.ReplaceAll(string(data), "\x00", " "), nil
}

// Dump creates a memory dump using /proc/pid/mem
func (b *Backend) Dump(vmName string, outputDir string) (string, error) {
	// Find the VM
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

	if b.Verbose {
		fmt.Printf("→ Found VM %s with PID %d\n", vmName, vm.PID)
	}

	// Find guest RAM region in /proc/pid/maps
	regions, err := b.ParseMemoryMaps(vm.PID)
	if err != nil {
		return "", fmt.Errorf("failed to parse memory maps: %w", err)
	}

	if len(regions) == 0 {
		return "", fmt.Errorf("no memory regions found for PID %d", vm.PID)
	}

	// Find the largest rw- region (guest RAM)
	// For standard VMs: rw-p (private)
	// For SEV-SNP VMs: rw-s (shared memory for encrypted pages)
	// Device-backed mappings (e.g. a passed-through GPU's /dev/vfio BAR) are
	// excluded — they are MMIO, not guest RAM, and can be far larger than RAM.
	var guestRAM *MemoryRegion
	for i := range regions {
		perms := regions[i].Perms
		if !strings.HasPrefix(perms, "rw-") || isDeviceBacked(regions[i].Path) {
			continue
		}
		if guestRAM == nil || regions[i].Size > guestRAM.Size {
			guestRAM = &regions[i]
		}
	}

	if guestRAM == nil {
		return "", fmt.Errorf("no rw- memory region found for PID %d", vm.PID)
	}

	if b.Verbose {
		fmt.Printf("→ Guest RAM region: 0x%x - 0x%x (%.2f GB)\n",
			guestRAM.Start, guestRAM.End, float64(guestRAM.Size)/(1024*1024*1024))
	}

	// Create output file
	timestamp := time.Now().Format("20060102-150405")
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-%s.dump", vmName, timestamp))

	// Dump memory via /proc/pid/mem
	err = b.DumpMemoryRegion(vm.PID, guestRAM, outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to dump memory: %w", err)
	}

	// Record what was dumped, above all the detected confidential-computing
	// status: a raw guest-RAM dump of a protected guest is indistinguishable
	// by content from one of an unbooted unprotected guest.
	if err := dumpmeta.WriteVM(outputPath, "procmem", vm.Name, vm.PID, vm.Security); err != nil && b.Verbose {
		fmt.Printf("→ could not write %s sidecar: %v\n", dumpmeta.Suffix, err)
	}

	return outputPath, nil
}

// ParseMemoryMaps parses /proc/pid/maps to find memory regions.
// Exported for reuse by other backends (e.g. pod) that dump by PID.
func (b *Backend) ParseMemoryMaps(pid int) ([]MemoryRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)

	// Try direct read first, fall back to sudo
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		// Try with sudo cat
		cmd := exec.Command("sudo", "cat", mapsPath)
		data, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", mapsPath, err)
		}
	}

	var regions []MemoryRegion

	// Parse lines like:
	//   7f1234000000-7f1244000000 rw-p 00000000 00:00 0
	//   78dc80000000-78fc80000000 rw-s 00000000 00:06 1234  /dev/vfio/devices/vfio2
	// Fields: range, perms, offset, dev, inode, [path]
	re := regexp.MustCompile(`^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)`)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) < 4 {
			continue
		}

		start, err := strconv.ParseUint(matches[1], 16, 64)
		if err != nil {
			continue
		}

		end, err := strconv.ParseUint(matches[2], 16, 64)
		if err != nil {
			continue
		}

		perms := matches[3]
		size := end - start

		// The backing path, if any, is the 6th whitespace field onward.
		path := ""
		if fields := strings.Fields(line); len(fields) >= 6 {
			path = strings.Join(fields[5:], " ")
		}

		regions = append(regions, MemoryRegion{
			Start: start,
			End:   end,
			Perms: perms,
			Size:  size,
			Path:  path,
		})
	}

	// Sort by size descending
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].Size > regions[j].Size
	})

	if b.Verbose {
		fmt.Printf("→ Found %d memory regions\n", len(regions))
		if len(regions) > 0 {
			fmt.Printf("→ Largest regions:\n")
			for i := 0; i < 5 && i < len(regions); i++ {
				r := regions[i]
				fmt.Printf("   %s: 0x%x-0x%x (%.2f GB)\n",
					r.Perms, r.Start, r.End, float64(r.Size)/(1024*1024*1024))
			}
		}
	}

	return regions, nil
}

// PartialReadError records unread bytes even when padding preserves the layout.
type PartialReadError struct {
	Read, Expected int64
	Cause          error
}

func (e *PartialReadError) Error() string {
	return fmt.Sprintf("read %d of %d bytes; remainder padded: %v", e.Read, e.Expected, e.Cause)
}
func (e *PartialReadError) Unwrap() error { return e.Cause }

// StreamMemoryRegion copies a selected mapping. Short reads are padded to
// preserve offsets but ALWAYS return PartialReadError. Output errors are fatal.
func (b *Backend) StreamMemoryRegion(pid int, region *MemoryRegion, w io.Writer) (int64, error) {
	if region == nil || region.End < region.Start || region.Size != region.End-region.Start || region.Size > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("invalid memory region")
	}
	expected := int64(region.Size)
	args := []string{fmt.Sprintf("if=/proc/%d/mem", pid), "bs=4M", fmt.Sprintf("skip=%d", region.Start), fmt.Sprintf("count=%d", region.Size), "iflag=skip_bytes,count_bytes,fullblock", "status=none"}
	cmd := exec.Command("dd", args...)
	if os.Geteuid() != 0 {
		cmd = exec.Command("sudo", append([]string{"dd"}, args...)...)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return 0, fmt.Errorf("start memory read: %w", err)
	}
	n, copyErr := io.Copy(w, stdout)
	if copyErr != nil {
		_ = stdout.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return n, fmt.Errorf("write memory dump: %w", copyErr)
	}
	waitErr := cmd.Wait()
	read := n
	if n < expected {
		padded, padErr := writeZeros(w, expected-n)
		n += padded
		if padErr != nil {
			return n, fmt.Errorf("pad memory dump: %w", padErr)
		}
	}
	if waitErr != nil || read != expected {
		cause := waitErr
		if cause == nil {
			cause = io.ErrUnexpectedEOF
		}
		return n, &PartialReadError{Read: read, Expected: expected, Cause: fmt.Errorf("%w: %s", cause, strings.TrimSpace(stderr.String()))}
	}
	return n, nil
}

// writeZeros writes exactly n zero bytes to w in 4 MiB chunks.
func writeZeros(w io.Writer, n int64) (int64, error) {
	const chunk = 4 * 1024 * 1024
	buf := make([]byte, chunk)
	var total int64
	for total < n {
		want := n - total
		if want > chunk {
			want = chunk
		}
		written, err := w.Write(buf[:want])
		total += int64(written)
		if err != nil {
			return total, err
		}
		if int64(written) != want {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// humanBytes formats a byte count for verbose-mode log lines.
func humanBytes(n uint64) string {
	const unit = 1024.0
	f := float64(n)
	switch {
	case f >= unit*unit*unit:
		return fmt.Sprintf("%.2f GB", f/(unit*unit*unit))
	case f >= unit*unit:
		return fmt.Sprintf("%.2f MB", f/(unit*unit))
	case f >= unit:
		return fmt.Sprintf("%.2f KB", f/unit)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// DumpMemoryRegion writes one region to a new file at outputPath. Use
// StreamMemoryRegion to write several regions into one file.
func (b *Backend) DumpMemoryRegion(pid int, region *MemoryRegion, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	if _, err := b.StreamMemoryRegion(pid, region, outFile); err != nil {
		outFile.Close()
		_ = os.Remove(outputPath)
		return err
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	os.Chmod(outputPath, 0644)
	return nil
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

// DumpLive reads memory directly without saving to file (for live search)
func (b *Backend) DumpLive(vmName string, handler func(data []byte, offset uint64) error) error {
	// Find the VM
	vms, err := b.List()
	if err != nil {
		return err
	}

	var vm *backend.VM
	for i := range vms {
		if vms[i].Name == vmName {
			vm = &vms[i]
			break
		}
	}

	if vm == nil {
		return fmt.Errorf("VM not found: %s", vmName)
	}

	// Find guest RAM region
	regions, err := b.ParseMemoryMaps(vm.PID)
	if err != nil {
		return err
	}

	var guestRAM *MemoryRegion
	for i := range regions {
		if regions[i].Perms == "rw-p" && !isDeviceBacked(regions[i].Path) {
			if guestRAM == nil || regions[i].Size > guestRAM.Size {
				guestRAM = &regions[i]
			}
		}
	}

	if guestRAM == nil {
		return fmt.Errorf("no rw-p memory region found")
	}

	// Stream memory through handler
	memPath := fmt.Sprintf("/proc/%d/mem", vm.PID)
	memFile, err := os.Open(memPath)
	if err != nil {
		return err
	}
	defer memFile.Close()

	chunkSize := 64 * 1024 * 1024 // 64MB
	buf := make([]byte, chunkSize)
	offset := guestRAM.Start

	for offset < guestRAM.End {
		_, err := memFile.Seek(int64(offset), io.SeekStart)
		if err != nil {
			offset += uint64(chunkSize)
			continue
		}

		n, err := memFile.Read(buf)
		if err != nil && err != io.EOF {
			offset += uint64(chunkSize)
			continue
		}

		if n > 0 {
			if err := handler(buf[:n], offset); err != nil {
				return err
			}
		}

		offset += uint64(n)
	}

	return nil
}
