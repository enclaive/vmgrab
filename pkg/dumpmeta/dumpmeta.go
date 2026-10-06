// Package dumpmeta defines the JSON sidecar that backends write next to a
// memory dump and that downstream consumers (search, demo) read to get a
// backend-aware verdict instead of guessing from byte contents.
//
// The sidecar lives at "<dump-path>.meta.json". Its absence is not an error
// — callers fall back to content heuristics for legacy dumps.
package dumpmeta

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// SchemaVersion is incremented when fields are added or change meaning.
//
// v1 (initial): single-process dumps, Meta.PID identifies the dumped process.
// v2: multi-container pod dumps. Containers describes the byte slice each
//     container's memory occupies in the dump file.
// v3: per-process layout inside each container. ContainerDump.Processes
//     enumerates every PID in the container's process tree (entrypoint +
//     descendants). crictl's container.info.pid is often a wrapper script
//     (e.g. docker-entrypoint.py spawning mongod); dumping only the wrapper
//     misses the service's address space entirely. Each ProcessDump records
//     its own byte slice and per-region layout.
const SchemaVersion = 3

// Suffix is appended to the dump file path to form the sidecar path.
const Suffix = ".meta.json"

// Meta describes how a dump was produced. Fields with unknown values are left
// empty rather than guessed; consumers must treat empty fields as "unknown".
type Meta struct {
	Version    int             `json:"version"`
	Backend    string          `json:"backend"`            // "pod", "procmem", "libvirt", "qemu"
	Kind       string          `json:"kind,omitempty"`     // "pod-runc", "pod-kata", "" for VMs
	Target     string          `json:"target"`             // "ns/pod" for pods, vm name otherwise
	PID        int             `json:"pid,omitempty"`      // host PID for single-process dumps; 0 for multi-container pod dumps
	Security   string          `json:"security,omitempty"` // "SEV-SNP", "TDX", "" if not detected
	Size       int64           `json:"size"`               // dump file size at write time
	CreatedAt  time.Time       `json:"createdAt"`
	Containers []ContainerDump `json:"containers,omitempty"` // per-container layout for pod-runc full-pod dumps; nil otherwise
}

// ContainerDump records one container's slice of the dump file. A container
// may host multiple host processes (entrypoint wrapper + the real service it
// fork-execs); Processes enumerates each PID we captured with its own byte
// slice. Downstream tools (search, demo, forensics) use this layout to
// attribute a match at dump-offset X back to a specific container, process,
// and VMA without re-deriving from raw bytes.
type ContainerDump struct {
	Name      string        `json:"name"`      // CRI container name (e.g. "mongodb", "linkerd-proxy")
	PID       int           `json:"pid"`       // entrypoint host PID (crictl inspect .info.pid)
	ByteStart int64         `json:"byteStart"` // first byte of this container's memory in the dump file
	ByteEnd   int64         `json:"byteEnd"`   // first byte AFTER this container in the dump file
	Processes []ProcessDump `json:"processes"` // every PID in the container's process tree, in capture order
}

// ProcessDump records one host process's slice within a container. Comm is
// /proc/PID/comm at capture time (truncated to 16 chars by the kernel) — used
// only for human-readable verdicts, never as an identifier.
type ProcessDump struct {
	PID       int          `json:"pid"`
	Comm      string       `json:"comm,omitempty"`
	ByteStart int64        `json:"byteStart"`
	ByteEnd   int64        `json:"byteEnd"`
	Regions   []RegionDump `json:"regions"`
}

// RegionDump locates one /proc/PID/maps rw- region within the dump file.
// Start/End are the original process virtual addresses; ByteStart/ByteEnd are
// the corresponding offsets inside the dump file (relative to file start, not
// to the process's slice).
type RegionDump struct {
	Start     uint64 `json:"start"`     // process VA: first byte of region
	End       uint64 `json:"end"`       // process VA: first byte AFTER region
	Perms     string `json:"perms"`     // /proc/PID/maps perms column (e.g. "rw-p")
	ByteStart int64  `json:"byteStart"` // offset in dump file where region begins
	ByteEnd   int64  `json:"byteEnd"`   // offset in dump file where region ends
}

// PathFor returns the sidecar path for the given dump file path.
func PathFor(dumpPath string) string { return dumpPath + Suffix }

// Write serialises m to "<dumpPath>.meta.json".
func (m *Meta) Write(dumpPath string) error {
	if m.Version == 0 {
		m.Version = SchemaVersion
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	if err := os.WriteFile(PathFor(dumpPath), data, 0o644); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	return nil
}

// Read loads the sidecar for dumpPath. Returns (nil, nil) when the sidecar
// does not exist — callers should treat that as "no metadata available" and
// fall back to content heuristics.
func Read(dumpPath string) (*Meta, error) {
	data, err := os.ReadFile(PathFor(dumpPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read meta: %w", err)
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse meta: %w", err)
	}
	return &m, nil
}

// Remove deletes the sidecar, if present. Missing file is not an error.
func Remove(dumpPath string) error {
	err := os.Remove(PathFor(dumpPath))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// WriteVM writes a sidecar for a whole-VM memory dump (qemu, libvirt or
// procmem backends). The decisive field is security: it records the
// confidential-computing technology detected on the QEMU command line at dump
// time. Without it a reader cannot tell a protected guest from one whose
// kernel was simply not resident yet, because both produce a dump with no
// guest-kernel structures in it. Errors are returned but are not fatal to the
// caller: the dump itself is still valid without a sidecar.
func WriteVM(dumpPath, backendName, target string, pid int, security string) error {
	size := int64(0)
	if fi, err := os.Stat(dumpPath); err == nil {
		size = fi.Size()
	}
	m := &Meta{
		Backend:   backendName,
		Target:    target,
		PID:       pid,
		Security:  security,
		Size:      size,
		CreatedAt: time.Now().UTC(),
	}
	return m.Write(dumpPath)
}
