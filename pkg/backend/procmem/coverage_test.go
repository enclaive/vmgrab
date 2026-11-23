package procmem

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectGuestMemfd(t *testing.T) {
	cases := []struct {
		name  string
		links []string
		want  bool
	}{
		{"anonymous inode", []string{"/dev/null", "anon_inode:[kvm-gmem]"}, true},
		{"dedicated filesystem", []string{"anon_inode:kvm-vcpu:0", "/[kvm-gmem] (deleted)"}, true},
		{"no guest_memfd", []string{"/dev/kvm", "anon_inode:[eventfd]", "/memfd:qemu (deleted)"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "42", "fd")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			for i, target := range tc.links {
				if err := os.Symlink(target, filepath.Join(dir, string(rune('0'+i)))); err != nil {
					t.Fatal(err)
				}
			}
			got, err := DetectGuestMemfd(root, 42)
			if err != nil || got != tc.want {
				t.Fatalf("DetectGuestMemfd = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	if _, err := DetectGuestMemfd(t.TempDir(), 42); err == nil {
		t.Fatal("a missing fd directory must be an error, not a negative result")
	}
}
