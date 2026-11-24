package search

import (
	"bytes"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

func TestSearchMatchesWholeFileRegexp(t *testing.T) {
	const block = 1024 * 1024
	for _, tc := range []struct {
		name, pattern string
		data          []byte
	}{
		{"cross boundary", "BOUNDARY_MARKER_123", append(append(make([]byte, block-5), []byte("BOUNDARY_MARKER_123")...), make([]byte, block)...)},
		{"second tail", "BOUNDARY_MARKER_123", append(make([]byte, 2*block-100), []byte("BOUNDARY_MARKER_123")...)},
		{"long match", "STARTx+END", append(append([]byte("START"), bytes.Repeat([]byte("x"), 2*block)...), []byte("END")...)},
		{"anchors", "(?m)^TOKEN$", append(append(make([]byte, block-2), []byte("\nTOKEN\n")...), []byte("TOKEN")...)},
		{"binary", "TOKEN[^!]+!", append([]byte{0xff, 0}, []byte("TOKEN\xff\x00!")...)},
		{"empty matches", "a*", []byte("baab")},
		{"empty file", "a*", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.dump")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, limit := range []int{1, 20} {
				got, err := New(path, false).Scan(tc.pattern, limit)
				if err != nil {
					t.Fatal(err)
				}
				all := regexp.MustCompile(tc.pattern).FindAllIndex(tc.data, -1)
				want := all
				if len(want) > limit {
					want = want[:limit]
				}
				var offsets, expected []int64
				for _, idx := range want {
					expected = append(expected, int64(idx[0]))
				}
				for _, m := range got.Matches {
					offsets = append(offsets, m.Offset)
					if !bytes.Equal(m.Data, tc.data[m.Offset:m.Offset+int64(len(m.Data))]) {
						t.Fatal("match data does not match file offset")
					}
				}
				if !reflect.DeepEqual(offsets, expected) {
					t.Fatalf("offsets=%v want=%v", offsets, expected)
				}
				if got.Limited != (len(all) > limit) {
					t.Fatalf("limited=%v matches=%d limit=%d", got.Limited, len(all), limit)
				}
			}
		})
	}
}

func TestSearchRejectsNonPositiveLimit(t *testing.T) {
	p := writeFixture(t, "input", []byte("marker"))
	for _, limit := range []int{0, -1} {
		if _, err := New(p, false).Search("marker", limit); err == nil {
			t.Fatalf("accepted limit %d", limit)
		}
	}
}

func TestSearchTruncatedMappingReturnsError(t *testing.T) {
	p := writeFixture(t, "input", bytes.Repeat([]byte("x"), 8192))
	f, err := os.OpenFile(p, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := unix.Mmap(int(f.Fd()), 0, 8192, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(data)
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scanMapped(data, regexp.MustCompile("marker"), 1); err == nil {
		t.Fatal("invalidated mapping reported success")
	}
}
