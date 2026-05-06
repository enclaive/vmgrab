// Package pod implements a vmgrab backend that discovers Kubernetes pods
// via CRI-O (crictl) and dumps their memory by reusing the procmem backend.
//
// Two pod kinds are supported:
//
//   - pod-runc: the container's main host process is dumped directly. The PID
//     comes from `crictl inspect <container> -o json` -> .info.pid.
//   - pod-kata: the QEMU sandbox backing the pod is dumped. The sandbox id
//     comes from `crictl inspectp <pod> -o json` and is resolved to a QEMU
//     PID via /proc/*/cmdline scan. This yields the same ciphertext view
//     that procmem already produces for confidential-computing VMs.
//
// This backend is only Available() on an OpenShift / CRI-O worker node; on
// any other host it self-disables so existing VM-dump flows are unaffected.
package pod

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/enclaive/vmgrab/pkg/backend"
	"github.com/enclaive/vmgrab/pkg/backend/procmem"
)

func init() {
	backend.Register("pod", func(verbose bool) backend.Backend {
		return New(verbose)
	})
}

// Backend discovers pods via crictl and dumps their memory via procmem.
type Backend struct {
	Verbose bool
	// procmem is reused verbatim — parse maps + dd /proc/pid/mem. Keeping it
	// as a field (vs. a fresh call each time) preserves its Verbose setting.
	procmem *procmem.Backend
}

// New creates a pod backend.
func New(verbose bool) *Backend {
	return &Backend{
		Verbose: verbose,
		procmem: procmem.New(verbose),
	}
}

// Name returns the backend name.
func (b *Backend) Name() string { return "pod" }

// Available reports whether this host has a usable CRI socket reachable
// via crictl. We probe by running `crictl info` — the universal check that
// succeeds on both CRI-O (OpenShift) and containerd (vanilla k8s / GKE /
// EKS) without us needing to hardcode a runtime or a socket path. Any
// non-zero exit (no binary, no config, no reachable socket) disables the
// backend cleanly.
func (b *Backend) Available() bool {
	if _, err := exec.LookPath("crictl"); err != nil {
		return false
	}
	if err := exec.Command("crictl", "info").Run(); err != nil {
		return false
	}
	return true
}

// List enumerates ready pods and classifies each as pod-runc or pod-kata.
// We inspect every sandbox individually because `crictl pods -o json` on
// CRI-O (OCP) leaves the top-level runtimeHandler empty — the real value
// lives in inspectp output.
func (b *Backend) List() ([]backend.VM, error) {
	pods, err := listPods()
	if err != nil {
		return nil, err
	}

	var out []backend.VM
	for _, p := range pods {
		pi, err := inspectPod(p.ID)
		if err != nil {
			if b.Verbose {
				fmt.Printf("→ skip %s/%s: inspectp: %v\n", p.Metadata.Namespace, p.Metadata.Name, err)
			}
			continue
		}

		kind := "pod-runc"
		if isKataHandler(pi.runtimeHandler()) {
			kind = "pod-kata"
		}

		pid, security, err := b.resolvePIDAndSecurity(p.ID, kind, pi)
		if err != nil {
			if b.Verbose {
				fmt.Printf("→ skip %s/%s: %v\n", p.Metadata.Namespace, p.Metadata.Name, err)
			}
			continue
		}

		out = append(out, backend.VM{
			Name:      p.Metadata.Name,
			Namespace: p.Metadata.Namespace,
			PID:       pid,
			State:     "running",
			Security:  security,
			Kind:      kind,
		})
	}
	return out, nil
}

// resolvePIDAndSecurity finds the host PID to dump and its security label.
// For runc pods, PID is the main container process and security is always "".
// For Kata pods, PID is the QEMU sandbox process and security is derived from
// its QEMU cmdline — the same regex procmem uses for VMs.
func (b *Backend) resolvePIDAndSecurity(podID, kind string, pi *podInspect) (int, string, error) {
	switch kind {
	case "pod-kata":
		// Primary: trust inspectp.info.pid if it's actually a QEMU process.
		// On OCP + Enclaive Kata (CRI-O 1.33, RHCOS 9.6) this is already the
		// qemu-kvm PID. On other Kata flavors info.pid may point at the shim
		// — fall through to the /proc scan in that case.
		if pi.Info.PID > 0 {
			if isQEMUCmdline(readProcCmdline(pi.Info.PID)) {
				return pi.Info.PID, b.procmem.DetectSecurity(pi.Info.PID), nil
			}
		}
		// Fallback: scan /proc for qemu-(system|kvm) whose cmdline contains
		// the sandbox hint (Kata sandbox_id if set, else CRI pod ID).
		hint := pi.sandboxHint(podID)
		pid, err := resolveKataQEMUPID(hint)
		if err != nil {
			return 0, "", err
		}
		return pid, b.procmem.DetectSecurity(pid), nil

	default: // pod-runc
		first, running, err := firstRunningContainer(podID)
		if err != nil {
			return 0, "", err
		}
		if first == nil {
			return 0, "", fmt.Errorf("no running container in pod %s", podID)
		}
		if running > 1 && b.Verbose {
			fmt.Printf("→ pod %s has %d running containers; dumping first (%s)\n",
				podID, running, first.Metadata.Name)
		}
		pid, err := containerPID(first.ID)
		if err != nil {
			return 0, "", err
		}
		return pid, "", nil
	}
}

// Dump creates a memory dump for the named pod. Accepts either "pod-name" or
// "namespace/pod-name". The heavy lifting (parse maps, chunked /proc/pid/mem
// read) is delegated to procmem unchanged.
func (b *Backend) Dump(target, outputDir string) (string, error) {
	vms, err := b.List()
	if err != nil {
		return "", err
	}

	vm := findByNsName(vms, target)
	if vm == nil {
		return "", fmt.Errorf("pod not found: %s", target)
	}

	if b.Verbose {
		fmt.Printf("→ Dumping %s/%s (kind=%s, pid=%d)\n",
			vm.Namespace, vm.Name, vm.Kind, vm.PID)
	}

	regions, err := b.procmem.ParseMemoryMaps(vm.PID)
	if err != nil {
		return "", fmt.Errorf("parse maps for pid %d: %w", vm.PID, err)
	}
	if len(regions) == 0 {
		return "", fmt.Errorf("no memory regions for pid %d", vm.PID)
	}

	timestamp := time.Now().Format("20060102-150405")
	base := fmt.Sprintf("%s-%s-%s.dump", vm.Namespace, vm.Name, timestamp)
	outputPath := filepath.Join(outputDir, base)

	switch vm.Kind {
	case "pod-kata":
		// Kata sandbox == QEMU: the largest rw- region is guest RAM. Same
		// selection policy as procmem.Backend.Dump — one pass, one region.
		r := largestRW(regions)
		if r == nil {
			return "", fmt.Errorf("no rw- region for kata sandbox pid %d", vm.PID)
		}
		if err := b.procmem.DumpMemoryRegion(vm.PID, r, outputPath); err != nil {
			return "", err
		}
	default: // pod-runc
		// runc containers have no single "guest RAM" region; walk every rw-
		// region and concatenate. DumpMemoryRegion creates the file; for
		// subsequent regions we append via a temp per-region file + cat. To
		// keep the diff minimal we emit one region at a time and append by
		// reopening in WRONLY|APPEND.
		if err := dumpAllRW(b.procmem, vm.PID, regions, outputPath); err != nil {
			return "", err
		}
	}
	return outputPath, nil
}

// GetFileSize delegates to procmem (identical implementation — stat + sudo fallback).
func (b *Backend) GetFileSize(path string) (int64, error) {
	return b.procmem.GetFileSize(path)
}

// findByNsName matches either "pod-name" (unique by name) or "namespace/pod-name".
func findByNsName(vms []backend.VM, target string) *backend.VM {
	nsName := strings.Contains(target, "/")
	for i := range vms {
		if nsName {
			if vms[i].Namespace+"/"+vms[i].Name == target {
				return &vms[i]
			}
		} else if vms[i].Name == target {
			return &vms[i]
		}
	}
	return nil
}

// largestRW returns the largest rw- (rw-p or rw-s) region, or nil.
func largestRW(regions []procmem.MemoryRegion) *procmem.MemoryRegion {
	var best *procmem.MemoryRegion
	for i := range regions {
		if !strings.HasPrefix(regions[i].Perms, "rw-") {
			continue
		}
		if best == nil || regions[i].Size > best.Size {
			best = &regions[i]
		}
	}
	return best
}

// dumpAllRW dumps every rw- region of pid into outputPath as a concatenation.
// procmem.DumpMemoryRegion writes to the path it receives with os.Create —
// we reuse it for the first region, then append subsequent regions via a
// tempfile + plain append. This keeps procmem untouched.
func dumpAllRW(pm *procmem.Backend, pid int, regions []procmem.MemoryRegion, outputPath string) error {
	var rws []procmem.MemoryRegion
	for _, r := range regions {
		if strings.HasPrefix(r.Perms, "rw-") {
			rws = append(rws, r)
		}
	}
	if len(rws) == 0 {
		return fmt.Errorf("no rw- regions for pid %d", pid)
	}

	// First region: let procmem create the file.
	if err := pm.DumpMemoryRegion(pid, &rws[0], outputPath); err != nil {
		return err
	}
	if len(rws) == 1 {
		return nil
	}

	// Subsequent regions: dump each to a temp file, then append.
	out, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	for i := 1; i < len(rws); i++ {
		tmp, err := os.CreateTemp(filepath.Dir(outputPath), ".vmgrab-region-*")
		if err != nil {
			return err
		}
		tmpPath := tmp.Name()
		tmp.Close()

		if err := pm.DumpMemoryRegion(pid, &rws[i], tmpPath); err != nil {
			os.Remove(tmpPath)
			return err
		}
		if err := appendFile(out, tmpPath); err != nil {
			os.Remove(tmpPath)
			return err
		}
		os.Remove(tmpPath)
	}
	return nil
}

func appendFile(dst *os.File, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	_, err = io.Copy(dst, src)
	return err
}
