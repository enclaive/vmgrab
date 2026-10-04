package pod

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func isQEMUExecutable(path string) bool {
	name := filepath.Base(strings.TrimSuffix(path, " (deleted)"))
	return name == "qemu-kvm" || strings.HasPrefix(name, "qemu-system-")
}

// An executable identity, rather than arbitrary command-line text or a
// user-chosen RuntimeClass name, establishes whether a process is QEMU.
func processExe(root string, pid int) (string, error) {
	return os.Readlink(filepath.Join(root, strconv.Itoa(pid), "exe"))
}

type sandboxInventory struct {
	qemu       map[string][]int
	vmRuntimes map[string]bool
}

func inventory(procRoot string) sandboxInventory {
	inv := sandboxInventory{qemu: map[string][]int{}, vmRuntimes: map[string]bool{}}
	entries, _ := os.ReadDir(procRoot)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		exe, err := processExe(procRoot, pid)
		if err != nil || !isQEMUExecutable(exe) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(data), "\x00")
		for i, arg := range args {
			if arg != "-name" || i+1 >= len(args) {
				continue
			}
			name := strings.Split(strings.TrimPrefix(args[i+1], "guest="), ",")[0]
			if strings.HasPrefix(name, "sandbox-") {
				id := strings.TrimPrefix(name, "sandbox-")
				inv.qemu[id] = append(inv.qemu[id], pid)
			}
		}
	}
	// Read the running CRI-O configuration, not defaults from `crio config`.
	// Other CRI runtimes need no CRI-O executable and still use process evidence.
	if _, err := exec.LookPath("crio"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if data, err := exec.CommandContext(ctx, "crio", "status", "config").Output(); err == nil {
			inv.vmRuntimes = parseVMRuntimes(string(data))
		}
	}
	return inv
}

func parseVMRuntimes(config string) map[string]bool {
	result := map[string]bool{}
	handler := ""
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			handler = ""
			const prefix = "[crio.runtime.runtimes."
			if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, "]") {
				handler = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, prefix), "]"), "\"'")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && handler != "" && strings.TrimSpace(key) == "runtime_type" {
			value = strings.TrimSpace(strings.Split(value, "#")[0])
			result[handler] = strings.Trim(value, "\"'") == "vm"
		}
	}
	return result
}

func (b *Backend) classify(p podListItem, pi *podInspect, inv sandboxInventory) (string, int, error) {
	if pi.Info.PID > 0 {
		exe, err := processExe(b.procRoot, pi.Info.PID)
		if err != nil {
			return "", 0, fmt.Errorf("inspect sandbox pid %d: %w", pi.Info.PID, err)
		}
		if isQEMUExecutable(exe) {
			return "pod-kata", pi.Info.PID, nil
		}
	}
	ids := []string{p.ID, pi.sandboxHint(p.ID)}
	seen := map[int]bool{}
	for _, id := range ids {
		for _, pid := range inv.qemu[id] {
			seen[pid] = true
		}
	}
	if len(seen) > 1 {
		return "", 0, fmt.Errorf("multiple QEMU processes for sandbox %s", p.ID)
	}
	for pid := range seen {
		return "pod-kata", pid, nil
	}
	handler := pi.runtimeHandler()
	if handler == "" {
		handler = p.RuntimeHandler
	}
	if inv.vmRuntimes[handler] {
		return "", 0, fmt.Errorf("runtime %q is configured as vm but its QEMU process was not found", handler)
	}
	if pi.Info.PID > 0 {
		exe, _ := processExe(b.procRoot, pi.Info.PID)
		if strings.Contains(filepath.Base(exe), "shim-kata") || strings.Contains(filepath.Base(exe), "cloud-hypervisor") {
			return "", 0, fmt.Errorf("VM sandbox process %s has no supported QEMU target", exe)
		}
	}
	containers, err := allRunningContainers(p.ID)
	if err != nil {
		return "", 0, err
	}
	if len(containers) == 0 {
		return "", 0, fmt.Errorf("sandbox has no running containers")
	}
	var first int
	for _, c := range containers {
		pid, err := containerPID(c.ID)
		if err != nil {
			return "", 0, err
		}
		exe, err := processExe(b.procRoot, pid)
		if err != nil {
			return "", 0, err
		}
		if isQEMUExecutable(exe) {
			return "pod-kata", pid, nil
		}
		// The reported PID must actually belong to this container, not an
		// unresolved VM shim or a different workload.
		if _, err := containerCgroup(b.procRoot, c.ID, pid); err != nil {
			return "", 0, err
		}
		if first == 0 {
			first = pid
		}
	}
	return "pod-runc", first, nil
}
