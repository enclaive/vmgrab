package pod

import (
	"io"
	"os"
	"testing"

	"github.com/enclaive/vmgrab/pkg/backend/procmem"
	"github.com/enclaive/vmgrab/pkg/dumpmeta"
)

type fixtureMemory struct{ partial bool }

func (f fixtureMemory) ParseMemoryMaps(int) ([]procmem.MemoryRegion, error) {
	return []procmem.MemoryRegion{{Start: 4096, End: 4104, Size: 8, Perms: "r--p"}}, nil
}
func (f fixtureMemory) StreamMemoryRegion(_ int, _ *procmem.MemoryRegion, w io.Writer) (int64, error) {
	if f.partial {
		n, err := w.Write([]byte{'a', 'b', 0, 0, 0, 0, 0, 0})
		if err != nil {
			return int64(n), err
		}
		return int64(n), &procmem.PartialReadError{Read: 2, Expected: 8, Cause: io.ErrUnexpectedEOF}
	}
	n, err := w.Write([]byte("abcdefgh"))
	return int64(n), err
}
func (f fixtureMemory) DetectSecurity(int) string { return "" }
func (f fixtureMemory) GetFileSize(path string) (int64, error) {
	s, e := os.Stat(path)
	if e != nil {
		return 0, e
	}
	return s.Size(), nil
}

func TestCapturePersistsCoverageAndFailsOnPartialRead(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[partial], func(t *testing.T) {
			root := t.TempDir()
			fakeProcess(t, root, 42, "/bin/app", "0::/kubepods/crio-cid.scope\n")
			fakeCRI(t, 0, 42, "arbitrary")
			b := New(false)
			b.procRoot = root
			b.procmem = fixtureMemory{partial: partial}
			path, err := b.Dump("ns/app", t.TempDir())
			if (err != nil) != partial {
				t.Fatalf("partial=%v error=%v", partial, err)
			}
			meta, e := dumpmeta.Read(path)
			if e != nil {
				t.Fatal(e)
			}
			if meta.Capture.Complete == partial {
				t.Fatal("wrong completeness")
			}
			wantRead, wantPadded := int64(8), int64(0)
			if partial {
				wantRead, wantPadded = 2, 6
			}
			if meta.Capture.BytesRead != wantRead || meta.Capture.BytesPadded != wantPadded {
				t.Fatalf("capture=%+v", meta.Capture)
			}
			if meta.Containers[0].Processes[0].Regions[0].BytesRead != wantRead {
				t.Fatal("missing per-region coverage")
			}
		})
	}
}
