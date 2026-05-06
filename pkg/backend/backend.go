package backend

import (
	"os"
	"os/exec"
	"strings"
)

// VM represents a virtual machine or pod target.
// The zero values for Kind and Namespace preserve legacy VM behavior.
type VM struct {
	Name      string // VM name, or pod name (for Kind != "")
	PID       int    // host process PID (QEMU for VMs / Kata sandboxes, main container process for runc pods)
	State     string // running, paused, etc.
	Security  string // SEV-SNP, SEV, TDX, or empty for unprotected
	Backend   string // which backend found this target (libvirt, qemu, procmem, pod)
	Kind      string // "" for legacy VM, "pod-runc" or "pod-kata" for pods
	Namespace string // k8s namespace for pods, empty otherwise
}

// Backend is the interface for VM management backends
type Backend interface {
	// Name returns the backend name (e.g., "libvirt", "qemu")
	Name() string

	// Available checks if this backend can be used on the current system
	Available() bool

	// List returns all VMs managed by this backend
	List() ([]VM, error)

	// Dump creates a memory dump of the specified VM
	// Returns the path to the dump file
	Dump(vmName string, outputDir string) (string, error)

	// GetFileSize returns the size of a file in bytes
	GetFileSize(path string) (int64, error)
}

// Registry holds available backends
var registry = make(map[string]func(verbose bool) Backend)

// Register adds a backend to the registry
func Register(name string, factory func(verbose bool) Backend) {
	registry[name] = factory
}

// Get returns a backend by name
func Get(name string, verbose bool) Backend {
	if factory, ok := registry[name]; ok {
		return factory(verbose)
	}
	return nil
}

// List returns all registered backend names
func List() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// AutoSelect automatically selects the best available backend
func AutoSelect(verbose bool) Backend {
	// procmem is the primary backend - universal, works everywhere
	if b := Get("procmem", verbose); b != nil && b.Available() {
		return b
	}
	// Fall back to libvirt if procmem not available
	if b := Get("libvirt", verbose); b != nil && b.Available() {
		return b
	}
	// Last resort: direct QEMU
	if b := Get("qemu", verbose); b != nil && b.Available() {
		return b
	}
	return nil
}

// ListAll returns VMs from all available backends, merged by PID.
//
// Order matters: `pod` runs first because it carries the richest metadata
// (namespace, pod name, Kind=pod-runc / pod-kata). procmem comes next and
// only adds PIDs the pod backend didn't claim — typically non-k8s QEMU VMs.
// libvirt and qemu backends add legacy VMs not visible via /proc.
//
// Without sudo `crictl info` fails and the pod backend self-disables; in
// that case pod targets simply aren't returned. Callers that want to surface
// that to the user should also call PodBackendBlockedByPerms().
func ListAll(verbose bool) ([]VM, error) {
	seen := make(map[int]bool)
	var allVMs []VM

	backendOrder := []string{"pod", "procmem", "libvirt", "qemu"}

	for _, name := range backendOrder {
		b := Get(name, verbose)
		if b == nil || !b.Available() {
			continue
		}

		vms, err := b.List()
		if err != nil {
			continue
		}

		for _, vm := range vms {
			if vm.PID == 0 {
				continue // skip VMs without PID
			}
			if !seen[vm.PID] {
				seen[vm.PID] = true
				vm.Backend = name
				allVMs = append(allVMs, vm)
			}
		}
	}

	return allVMs, nil
}

// PodBackendBlockedByPerms reports whether the pod backend probe ran but
// failed in a way consistent with insufficient privileges (crictl present
// on PATH, but `crictl info` exits non-zero AND we're not root). Callers
// can use this to print an actionable warning ("run under sudo") instead
// of silently omitting Kubernetes pods from the list.
func PodBackendBlockedByPerms() bool {
	if _, err := exec.LookPath("crictl"); err != nil {
		return false
	}
	if err := exec.Command("crictl", "info").Run(); err == nil {
		return false
	}
	return os.Geteuid() != 0
}

// FindVM finds a VM or pod by name across all backends.
// Returns the backend that can manage it and the VM info.
// Order matches ListAll: pod first so a "namespace/pod" target hits the
// backend that knows how to dump it (and produces pod-aware metadata) even
// when procmem also sees the underlying QEMU/runc PID.
// If name contains "/", it is treated as "namespace/pod" and matched against
// pod targets (vm.Namespace+"/"+vm.Name); otherwise it matches vm.Name.
func FindVM(name string, verbose bool) (Backend, *VM) {
	backendOrder := []string{"pod", "procmem", "libvirt", "qemu"}
	nsName := strings.Contains(name, "/")

	for _, bName := range backendOrder {
		b := Get(bName, verbose)
		if b == nil || !b.Available() {
			continue
		}

		vms, err := b.List()
		if err != nil {
			continue
		}

		for i := range vms {
			var match bool
			if nsName {
				match = vms[i].Namespace != "" &&
					vms[i].Namespace+"/"+vms[i].Name == name
			} else {
				match = vms[i].Name == name
			}
			if match {
				vms[i].Backend = bName
				return b, &vms[i]
			}
		}
	}
	return nil, nil
}
