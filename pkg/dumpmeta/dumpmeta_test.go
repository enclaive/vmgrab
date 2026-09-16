package dumpmeta

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRoundtrip(t *testing.T) {
	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "x.dump")
	if err := os.WriteFile(dumpPath, []byte("body"), 0o600); err != nil {
		t.Fatalf("write dump: %v", err)
	}

	in := &Meta{
		Backend:  "pod",
		Kind:     "pod-runc",
		Target:   "ns/foo",
		PID:      1234,
		Security: "",
		Size:     4,
	}
	if err := in.Write(dumpPath); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if in.Version != SchemaVersion {
		t.Errorf("Version not stamped: got %d want %d", in.Version, SchemaVersion)
	}
	if in.CreatedAt.IsZero() {
		t.Errorf("CreatedAt not stamped")
	}

	out, err := Read(dumpPath)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out == nil {
		t.Fatalf("Read returned nil meta")
	}
	if out.Backend != "pod" || out.Kind != "pod-runc" || out.Target != "ns/foo" || out.PID != 1234 || out.Size != 4 {
		t.Errorf("roundtrip mismatch: %+v", out)
	}
	if out.Version != SchemaVersion {
		t.Errorf("Version not roundtripped: got %d want %d", out.Version, SchemaVersion)
	}
	if time.Since(out.CreatedAt) > 5*time.Second {
		t.Errorf("CreatedAt too far in past: %v", out.CreatedAt)
	}
}

func TestReadMissingReturnsNil(t *testing.T) {
	dir := t.TempDir()
	out, err := Read(filepath.Join(dir, "absent.dump"))
	if err != nil {
		t.Fatalf("Read missing: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil meta for missing sidecar, got %+v", out)
	}
}

func TestRoundtripV3MultiProcess(t *testing.T) {
	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "pod.dump")
	if err := os.WriteFile(dumpPath, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write dump: %v", err)
	}

	in := &Meta{
		Backend: "pod",
		Kind:    "pod-runc",
		Target:  "ns/mongodb-x",
		Size:    32,
		Containers: []ContainerDump{
			{
				Name: "mongodb", PID: 4242, ByteStart: 0, ByteEnd: 24,
				Processes: []ProcessDump{
					{
						PID: 4242, Comm: "python3", ByteStart: 0, ByteEnd: 8,
						Regions: []RegionDump{
							{Start: 0x7f0000000000, End: 0x7f0000008000, Perms: "rw-p", ByteStart: 0, ByteEnd: 8},
						},
					},
					{
						PID: 4250, Comm: "mongod", ByteStart: 8, ByteEnd: 24,
						Regions: []RegionDump{
							{Start: 0x7f0010000000, End: 0x7f0010010000, Perms: "rw-p", ByteStart: 8, ByteEnd: 24},
						},
					},
				},
			},
			{
				Name: "linkerd-proxy", PID: 4243, ByteStart: 24, ByteEnd: 32,
				Processes: []ProcessDump{
					{
						PID: 4243, Comm: "linkerd2-proxy", ByteStart: 24, ByteEnd: 32,
						Regions: []RegionDump{
							{Start: 0x7f1000000000, End: 0x7f1000008000, Perms: "rw-p", ByteStart: 24, ByteEnd: 32},
						},
					},
				},
			},
		},
	}
	if err := in.Write(dumpPath); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := Read(dumpPath)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.Version != 3 {
		t.Errorf("Version: got %d want 3", out.Version)
	}
	if len(out.Containers) != 2 {
		t.Fatalf("Containers: got %d want 2", len(out.Containers))
	}
	if len(out.Containers[0].Processes) != 2 {
		t.Fatalf("Processes in mongodb: got %d want 2", len(out.Containers[0].Processes))
	}
	if out.Containers[0].Processes[1].Comm != "mongod" || out.Containers[0].Processes[1].PID != 4250 {
		t.Errorf("Process[1]: %+v", out.Containers[0].Processes[1])
	}
	if out.Containers[0].Processes[1].ByteStart != 8 || out.Containers[0].Processes[1].ByteEnd != 24 {
		t.Errorf("Process[1] slice: %d..%d", out.Containers[0].Processes[1].ByteStart, out.Containers[0].Processes[1].ByteEnd)
	}
	if len(out.Containers[0].Processes[1].Regions) != 1 || out.Containers[0].Processes[1].Regions[0].Perms != "rw-p" {
		t.Errorf("Region roundtrip: %+v", out.Containers[0].Processes[1].Regions)
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "x.dump")
	m := &Meta{Backend: "pod", Target: "ns/foo", Size: 0}
	if err := m.Write(dumpPath); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Remove(dumpPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(PathFor(dumpPath)); !os.IsNotExist(err) {
		t.Errorf("sidecar still exists after Remove: %v", err)
	}
	if err := Remove(dumpPath); err != nil {
		t.Errorf("Remove on absent file should be nil, got %v", err)
	}
}
