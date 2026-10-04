package search

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"

	"golang.org/x/sys/unix"
)

// ScanResult distinguishes a complete search from a limited result listing.
type ScanResult struct {
	Matches  []Match
	Limited  bool
	FileSize int64
}

// Scan applies Go regexp semantics to the complete file, including binary data,
// anchors and arbitrarily long matches. A read-only mapping avoids copying the
// entire dump into Go's heap and avoids artificial chunk boundaries. Returned
// match bytes are copied before the mapping is released.
func (s *Searcher) Scan(pattern string, maxMatches int) (ScanResult, error) {
	return s.scanRanges(pattern, maxMatches, nil)
}

func (s *Searcher) scanRanges(pattern string, maxMatches int, ranges []byteRange) (ScanResult, error) {
	var result ScanResult
	if maxMatches <= 0 || maxMatches == int(^uint(0)>>1) {
		return result, fmt.Errorf("maximum matches must be a positive integer below MaxInt")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return result, fmt.Errorf("invalid regex pattern: %w", err)
	}
	f, err := os.Open(s.FilePath)
	if err != nil {
		return result, fmt.Errorf("open dump: %w", err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return result, err
	}
	if !before.Mode().IsRegular() {
		return result, fmt.Errorf("dump must be a regular file")
	}
	result.FileSize = before.Size()
	if before.Size() > int64(int(^uint(0)>>1)) {
		return result, fmt.Errorf("dump is too large for this architecture")
	}
	var data []byte
	if before.Size() > 0 {
		data, err = unix.Mmap(int(f.Fd()), 0, int(before.Size()), unix.PROT_READ, unix.MAP_PRIVATE)
		if err != nil {
			return result, fmt.Errorf("map dump: %w", err)
		}
		defer unix.Munmap(data)
	}
	if ranges == nil {
		ranges = []byteRange{{offset: 0, length: before.Size()}}
	}
	for _, rg := range ranges {
		if rg.offset < 0 || rg.length < 0 || rg.offset > before.Size() || rg.length > before.Size()-rg.offset {
			return ScanResult{}, fmt.Errorf("capture range exceeds dump file")
		}
		remaining := maxMatches - len(result.Matches)
		matches, limited, scanErr := scanMapped(data[rg.offset:rg.offset+rg.length], re, remaining)
		if scanErr != nil {
			return ScanResult{}, scanErr
		}
		for _, m := range matches {
			m.Offset += rg.offset
			result.Matches = append(result.Matches, m)
		}
		if limited {
			result.Limited = true
			break
		}
	}
	after, err := f.Stat()
	if err != nil {
		return ScanResult{}, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return ScanResult{}, fmt.Errorf("dump changed during search; wait for capture to finish and retry")
	}
	return result, nil
}

func scanMapped(data []byte, re *regexp.Regexp, limit int) (matches []Match, limited bool, err error) {
	// An external truncation can invalidate mmap pages. Turn that fault into an
	// operational error in this goroutine instead of crashing the entire CLI.
	previous := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(previous)
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(runtime.Error); !ok {
				panic(p)
			}
			matches = nil
			limited = false
			err = fmt.Errorf("dump became unreadable during search: %v", p)
		}
	}()
	indices := re.FindAllIndex(data, limit+1)
	limited = len(indices) > limit
	if limited {
		indices = indices[:limit]
	}
	for _, idx := range indices {
		matches = append(matches, Match{Offset: int64(idx[0]), Data: append([]byte(nil), data[idx[0]:idx[1]]...)})
	}
	return matches, limited, nil
}
