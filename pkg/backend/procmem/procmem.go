package procmem

import (
	"bufio"
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

		vms = append(vms, backend.VM{
			Name:     name,
			PID:      pid,
			State:    "running",
			Security: security,
		})
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
	regions, err := b.parseMemoryMaps(vm.PID)
	if err != nil {
		return "", fmt.Errorf("failed to parse memory maps: %w", err)
	}

	if len(regions) == 0 {
		return "", fmt.Errorf("no memory regions found for PID %d", vm.PID)
	}

	// Find the largest rw- region (guest RAM)
	// For standard VMs: rw-p (private)
	// For SEV-SNP VMs: rw-s (shared memory for encrypted pages)
	var guestRAM *MemoryRegion
	for i := range regions {
		perms := regions[i].Perms
		// Accept rw-p (private) or rw-s (shared) - both can be guest RAM
		if strings.HasPrefix(perms, "rw-") {
			if guestRAM == nil || regions[i].Size > guestRAM.Size {
				guestRAM = &regions[i]
			}
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
	err = b.dumpMemoryRegion(vm.PID, guestRAM, outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to dump memory: %w", err)
	}

	return outputPath, nil
}

// parseMemoryMaps parses /proc/pid/maps to find memory regions
func (b *Backend) parseMemoryMaps(pid int) ([]MemoryRegion, error) {
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

	// Parse lines like: 7f1234000000-7f1244000000 rw-p 00000000 00:00 0
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

		regions = append(regions, MemoryRegion{
			Start: start,
			End:   end,
			Perms: perms,
			Size:  size,
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

// dumpMemoryRegion reads memory from /proc/pid/mem and writes to file
func (b *Backend) dumpMemoryRegion(pid int, region *MemoryRegion, outputPath string) error {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)

	// Open output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Open /proc/pid/mem with sudo dd (more reliable for large reads)
	// Using dd with skip and count for chunked reading
	chunkSize := uint64(64 * 1024 * 1024) // 64MB chunks
	totalSize := region.Size
	offset := region.Start

	if b.Verbose {
		fmt.Printf("→ Dumping %.2f GB in %d chunks...\n",
			float64(totalSize)/(1024*1024*1024),
			(totalSize+chunkSize-1)/chunkSize)
	}

	// Use sudo dd for reading /proc/pid/mem
	for offset < region.End {
		remaining := region.End - offset
		readSize := chunkSize
		if remaining < readSize {
			readSize = remaining
		}

		// dd if=/proc/PID/mem bs=1M count=64 skip=OFFSET iflag=skip_bytes
		cmd := exec.Command("sudo", "dd",
			fmt.Sprintf("if=%s", memPath),
			fmt.Sprintf("bs=%d", readSize),
			"count=1",
			fmt.Sprintf("skip=%d", offset),
			"iflag=skip_bytes",
			"status=none",
		)

		data, err := cmd.Output()
		if err != nil {
			// For SEV-SNP VMs, reading encrypted memory may fail or return zeros
			// This is expected behavior - write zeros and continue
			if b.Verbose {
				fmt.Printf("→ Read error at offset 0x%x (may be encrypted): %v\n", offset, err)
			}
			// Write zeros for this chunk
			zeros := make([]byte, readSize)
			outFile.Write(zeros)
		} else {
			_, err = outFile.Write(data)
			if err != nil {
				return fmt.Errorf("failed to write to output file: %w", err)
			}
		}

		offset += readSize
	}

	// Make file readable
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
	regions, err := b.parseMemoryMaps(vm.PID)
	if err != nil {
		return err
	}

	var guestRAM *MemoryRegion
	for i := range regions {
		if regions[i].Perms == "rw-p" {
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
