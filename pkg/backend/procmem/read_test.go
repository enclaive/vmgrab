package procmem

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func fakeDD(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	for name, script := range map[string]string{"dd": "#!/bin/sh\n" + body, "sudo": `#!/bin/sh
exec "$@"
`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}
func TestStreamReadFailuresAreNotSuccess(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		read         int64
	}{{"failed", "exit 1\n", 0}, {"short", "printf abc\n", 3}, {"partial error", "printf abc; exit 1\n", 3}} {
		t.Run(tc.name, func(t *testing.T) {
			fakeDD(t, tc.script)
			var out bytes.Buffer
			n, err := New(false).StreamMemoryRegion(123, &MemoryRegion{Start: 4096, End: 4104, Size: 8}, &out)
			var partial *PartialReadError
			if !errors.As(err, &partial) || partial.Read != tc.read || partial.Expected != 8 || n != 8 {
				t.Fatalf("n=%d partial=%+v err=%v", n, partial, err)
			}
			if len(out.Bytes()) != 8 {
				t.Fatal("padding did not preserve layout")
			}
		})
	}
}
func TestStreamSuccessfulRead(t *testing.T) {
	fakeDD(t, "printf abcdefgh\n")
	var out bytes.Buffer
	n, err := New(false).StreamMemoryRegion(123, &MemoryRegion{Start: 0, End: 8, Size: 8}, &out)
	if err != nil || n != 8 || out.String() != "abcdefgh" {
		t.Fatalf("n=%d err=%v data=%q", n, err, out.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestStreamWriteError(t *testing.T) {
	fakeDD(t, "printf abcdefgh\n")
	if _, err := New(false).StreamMemoryRegion(123, &MemoryRegion{Start: 0, End: 8, Size: 8}, failingWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("err=%v", err)
	}
}
