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
		if target == "anon_inode:[kvm-gmem]" || strings.Contains(target, "kvm_guest_memfd") {
			return true, nil
		}
	}
	return false, nil
}
