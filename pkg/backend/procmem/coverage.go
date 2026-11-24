package procmem

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CapturableRegion excludes MMIO and kernel-only pseudo mappings. Read-only
// application data and /dev/shm are included, not just writable heaps/stacks.
func CapturableRegion(r MemoryRegion) bool {
	if !strings.HasPrefix(r.Perms, "r") || r.Size == 0 {
		return false
	}
	if strings.HasPrefix(r.Path, "[vvar") || r.Path == "[vsyscall]" {
		return false
	}
	if strings.HasPrefix(r.Path, "/dev/shm/") || strings.HasPrefix(r.Path, "/dev/zero") {
		return true
	}
	return !isDeviceBacked(r.Path)
}

func DetectGuestMemfd(root string, pid int) (bool, error) {
	dir := filepath.Join(root, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("inspect guest_memfd: %w", err)
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if isGuestMemfdLink(target) {
			return true, nil
		}
	}
	return false, nil
}

// The descriptor's link name depends on the kernel: older kernels expose
// guest_memfd as "anon_inode:[kvm-gmem]", newer ones back it with its own
// filesystem and show "/[kvm-gmem] (deleted)".
func isGuestMemfdLink(target string) bool {
	return strings.Contains(target, "[kvm-gmem]") || strings.Contains(target, "kvm_guest_memfd")
}
