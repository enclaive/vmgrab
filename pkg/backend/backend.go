package backend

// VM represents a virtual machine
type VM struct {
	Name     string // VM name
	PID      int    // QEMU process PID
	State    string // running, paused, etc.
	Security string // SEV-SNP, SEV, TDX, or empty for unprotected
	Backend  string // which backend found this VM (libvirt, qemu, etc.)
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

// ListAll returns VMs from all available backends, deduplicated by PID
// Priority: procmem (universal), then libvirt (richer info for non-running VMs)
func ListAll(verbose bool) ([]VM, error) {
	seen := make(map[int]bool)
	var allVMs []VM

	// procmem is primary - detects all QEMU processes including Kata
	backendOrder := []string{"procmem", "libvirt", "qemu"}

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

// FindVM finds a VM by name across all backends
// Returns the backend that can manage it and the VM info
// Priority: procmem first (universal dump method)
func FindVM(name string, verbose bool) (Backend, *VM) {
	backendOrder := []string{"procmem", "libvirt", "qemu"}

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
			if vms[i].Name == name {
				vms[i].Backend = bName
				return b, &vms[i]
			}
		}
	}
	return nil, nil
}
