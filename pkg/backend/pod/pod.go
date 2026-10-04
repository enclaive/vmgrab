// Package pod discovers CRI sandboxes and captures host-readable process
// mappings. QEMU userspace memory is not equivalent to private guest memory.
package pod

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/enclaive/vmgrab/pkg/backend"
	"github.com/enclaive/vmgrab/pkg/backend/procmem"
	"github.com/enclaive/vmgrab/pkg/dumpmeta"
)

func init() { backend.Register("pod", func(verbose bool) backend.Backend { return New(verbose) }) }

type memorySource interface {
	ParseMemoryMaps(int) ([]procmem.MemoryRegion, error)
	StreamMemoryRegion(int, *procmem.MemoryRegion, io.Writer) (int64, error)
	DetectSecurity(int) string
	GetFileSize(string) (int64, error)
}

type Backend struct {
	Verbose  bool
	procmem  memorySource
	procRoot string
}

func New(verbose bool) *Backend {
	return &Backend{Verbose: verbose, procmem: procmem.New(verbose), procRoot: "/proc"}
}
func (b *Backend) Name() string { return "pod" }
func (b *Backend) Available() bool {
	if _, err := exec.LookPath("crictl"); err != nil {
		return false
	}
	return exec.Command("crictl", "info").Run() == nil
}

func (b *Backend) List() ([]backend.VM, error) {
	pods, err := listPods()
	if err != nil {
		return nil, err
	}
	inv := inventory(b.procRoot)
	var result []backend.VM
	for _, p := range pods {
		vm := backend.VM{Name: p.Metadata.Name, Namespace: p.Metadata.Namespace, State: "running"}
		pi, err := inspectPod(p.ID)
		if err == nil {
			vm.Kind, vm.PID, err = b.classify(p, pi, inv)
		}
		if err != nil {
			vm.Kind = "pod-unknown"
			vm.State = "unresolved"
			fmt.Fprintf(os.Stderr, "Warning: %s/%s: %v\n", vm.Namespace, vm.Name, err)
		} else if vm.Kind == "pod-kata" {
			vm.Security = b.procmem.DetectSecurity(vm.PID)
		}
		result = append(result, vm)
	}
	return result, nil
}

func selectPod(pods []podListItem, target string) (*podListItem, error) {
	var found *podListItem
	for i := range pods {
		p := &pods[i]
		if target != p.Metadata.Name && target != p.Metadata.Namespace+"/"+p.Metadata.Name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ambiguous pod %q; use namespace/name", target)
		}
		found = p
	}
	if found == nil {
		return nil, fmt.Errorf("pod not found: %s", target)
	}
	return found, nil
}

// Dump resolves only the requested sandbox, then snapshots the selected
// processes and mappings. A changing live workload is not an atomic snapshot.
// Partial artifacts retain metadata and return BOTH their path and an error.
func (b *Backend) Dump(target, outputDir string) (string, error) {
	pods, err := listPods()
	if err != nil {
		return "", err
	}
	pod, err := selectPod(pods, target)
	if err != nil {
		return "", err
	}
	pi, err := inspectPod(pod.ID)
	if err != nil {
		return "", err
	}
	kind, pid, err := b.classify(*pod, pi, inventory(b.procRoot))
	if err != nil {
		return "", err
	}
	out, err := os.CreateTemp(outputDir, pod.Metadata.Namespace+"-"+pod.Metadata.Name+"-*.dump")
	if err != nil {
		return "", err
	}
	path := out.Name()
	capture := &dumpmeta.Capture{Scope: "readable non-device mappings of the selected live container processes", Complete: true}
	meta := &dumpmeta.Meta{Backend: "pod", Kind: kind, Target: pod.Metadata.Namespace + "/" + pod.Metadata.Name, Capture: capture}
	var captureErr error
	if kind == "pod-kata" {
		meta.PID = pid
		meta.Security = b.procmem.DetectSecurity(pid)
		capture.Scope = "readable non-device QEMU userspace mappings; guest-private memory is not acquired through guest_memfd"
		detected, detectErr := procmem.DetectGuestMemfd(b.procRoot, pid)
		if detectErr != nil {
			capture.Errors = append(capture.Errors, detectErr.Error())
			capture.Complete = false
		} else {
			capture.GuestMemfd = &detected
		}
		pd, err := b.dumpProcess(pid, out, 0, capture)
		captureErr = err
		meta.Containers = []dumpmeta.ContainerDump{{Name: "sandbox", ID: pod.ID, PID: pid, ByteStart: 0, ByteEnd: pd.ByteEnd, Processes: []dumpmeta.ProcessDump{pd}}}
	} else {
		containers, err := allRunningContainers(pod.ID)
		if err != nil {
			captureErr = err
		} else {
			meta.Containers, captureErr = b.dumpContainers(containers, out, capture)
		}
	}
	if captureErr != nil {
		capture.Complete = false
		capture.Errors = append(capture.Errors, captureErr.Error())
	}
	if err := out.Close(); err != nil {
		capture.Complete = false
		capture.Errors = append(capture.Errors, err.Error())
	}
	info, err := os.Stat(path)
	if err != nil {
		return path, err
	}
	meta.Size = info.Size()
	if capture.BytesRead == 0 {
		capture.Complete = false
		capture.Errors = append(capture.Errors, "no memory bytes were read")
	}
	if err := meta.Write(path); err != nil {
		return path, err
	}
	if !capture.Complete {
		return path, fmt.Errorf("incomplete capture saved to %s: %s", path, strings.Join(capture.Errors, "; "))
	}
	return path, nil
}

func (b *Backend) dumpContainers(containers []containerItem, out *os.File, capture *dumpmeta.Capture) ([]dumpmeta.ContainerDump, error) {
	sort.Slice(containers, func(i, j int) bool { return containers[i].Metadata.Name < containers[j].Metadata.Name })
	var result []dumpmeta.ContainerDump
	var cursor int64
	for _, c := range containers {
		root, err := containerPID(c.ID)
		if err != nil {
			capture.Complete = false
			capture.Errors = append(capture.Errors, err.Error())
			continue
		}
		pids, err := containerPIDs(b.procRoot, c.ID, root)
		if err != nil {
			capture.Complete = false
			capture.Errors = append(capture.Errors, err.Error())
			continue
		}
		cd := dumpmeta.ContainerDump{Name: c.Metadata.Name, ID: c.ID, PID: root, ByteStart: cursor}
		if b.Verbose {
			fmt.Printf("Container %s: capturing %d processes from its cgroup\n", c.Metadata.Name, len(pids))
		}
		for _, pid := range pids {
			// Revalidate membership before reading. Do not follow a reused/moved PID.
			if _, err := containerCgroup(b.procRoot, c.ID, pid); err != nil {
				capture.Complete = false
				capture.Errors = append(capture.Errors, err.Error())
				continue
			}
			pd, err := b.dumpProcess(pid, out, cursor, capture)
			cursor = pd.ByteEnd
			cd.Processes = append(cd.Processes, pd)
			if err != nil {
				cd.ByteEnd = cursor
				return append(result, cd), err
			}
		}
		cd.ByteEnd = cursor
		result = append(result, cd)
	}
	return result, nil
}

func (b *Backend) dumpProcess(pid int, out *os.File, start int64, capture *dumpmeta.Capture) (dumpmeta.ProcessDump, error) {
	pd := dumpmeta.ProcessDump{PID: pid, ByteStart: start, ByteEnd: start}
	before, err := processStartTime(b.procRoot, pid)
	if err != nil {
		capture.Complete = false
		capture.Errors = append(capture.Errors, fmt.Sprintf("pid %d: %v", pid, err))
		return pd, nil
	}
	pd.StartTime = before
	if comm, err := os.ReadFile(filepath.Join(b.procRoot, fmt.Sprint(pid), "comm")); err == nil {
		pd.Comm = strings.TrimSpace(string(comm))
	}
	regions, err := b.procmem.ParseMemoryMaps(pid)
	if err != nil {
		capture.Complete = false
		capture.Errors = append(capture.Errors, err.Error())
		return pd, nil
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].Start < regions[j].Start })
	for _, r := range regions {
		if !procmem.CapturableRegion(r) {
			continue
		}
		rg := dumpmeta.RegionDump{Start: r.Start, End: r.End, Perms: r.Perms, Path: r.Path, ByteStart: pd.ByteEnd}
		n, err := b.procmem.StreamMemoryRegion(pid, &r, out)
		pd.ByteEnd += n
		rg.ByteEnd = pd.ByteEnd
		rg.BytesRead = n
		if err != nil {
			capture.Complete = false
			rg.Error = err.Error()
			capture.Errors = append(capture.Errors, fmt.Sprintf("pid %d region 0x%x: %v", pid, r.Start, err))
			var partial *procmem.PartialReadError
			if !errors.As(err, &partial) {
				capture.BytesRead += n
				pd.Regions = append(pd.Regions, rg)
				return pd, err
			}
			rg.BytesRead = partial.Read
			capture.BytesPadded += n - partial.Read
		}
		capture.BytesRead += rg.BytesRead
		pd.Regions = append(pd.Regions, rg)
	}
	after, err := processStartTime(b.procRoot, pid)
	if err != nil || before != after {
		capture.Complete = false
		capture.Errors = append(capture.Errors, fmt.Sprintf("pid %d exited or changed identity during capture", pid))
	}
	if len(pd.Regions) == 0 {
		capture.Complete = false
		capture.Errors = append(capture.Errors, fmt.Sprintf("pid %d has no selected readable mappings", pid))
	}
	return pd, nil
}

func (b *Backend) GetFileSize(path string) (int64, error) { return b.procmem.GetFileSize(path) }
