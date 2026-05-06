package pod

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// qemuBinaryRe matches both qemu-system-* (Debian/Ubuntu) and qemu-kvm
// (RHEL/RHCOS/Fedora — this is what OpenShift Sandboxed Containers uses).
var qemuBinaryRe = regexp.MustCompile(`qemu-(?:system|kvm)`)

// isKataHandler returns true if the CRI runtimeHandler / annotation value
// corresponds to a Kata-based RuntimeClass. Covers upstream ("kata"),
// OpenShift Sandboxed Containers ("kata-qemu", "kata-cc"), and vendor flavors
// including Enclaive's SEV-SNP variant ("kata-enclaive", "kata-qemu-snp", ...).
func isKataHandler(handler string) bool {
	h := strings.ToLower(handler)
	return strings.Contains(h, "kata")
}

// isQEMUCmdline reports whether the given /proc/PID/cmdline content belongs
// to a QEMU process (covers qemu-system-* and qemu-kvm).
func isQEMUCmdline(cmdline string) bool {
	return qemuBinaryRe.MatchString(cmdline)
}

// readProcCmdline returns /proc/PID/cmdline with NUL separators replaced by
// spaces. Empty string on read error.
func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(data), "\x00", " ")
}

// resolveKataQEMUPID scans /proc/*/cmdline for the QEMU sandbox backing a
// Kata pod. The `hint` is a string that must be present in the QEMU cmdline
// to uniquely identify the target sandbox. For Enclaive Kata the hint is the
// CRI pod ID (embedded as `-name sandbox-<podID>`); some other Kata flavors
// expose a separate `io.katacontainers.pkg.oci.sandbox_id` annotation —
// either works because we just do substring match.
//
// Returns the first matching PID. Empty hint is a programmer error and
// yields an error so callers never silently match the wrong process.
func resolveKataQEMUPID(hint string) (int, error) {
	if hint == "" {
		return 0, fmt.Errorf("resolveKataQEMUPID: empty hint")
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		cmd := strings.ReplaceAll(string(data), "\x00", " ")

		if !isQEMUCmdline(cmd) {
			continue
		}
		if !strings.Contains(cmd, hint) {
			continue
		}
		return pid, nil
	}
	return 0, fmt.Errorf("no QEMU process found for Kata sandbox hint %q", hint)
}
