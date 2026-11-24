package search

import (
	"fmt"
	"os"
	"regexp"

	"github.com/enclaive/vmgrab/pkg/dumpmeta"
)

// Analysis separates observed bytes from capture coverage and configured CC.
// Neither missing patterns nor kernel fingerprints establish encryption.
type Analysis struct {
	Scan       ScanResult
	Meta       *dumpmeta.Meta
	Incomplete []string
}

func (a *Analysis) Status() string {
	if len(a.Scan.Matches) > 0 {
		return "MATCH_FOUND"
	}
	if len(a.Incomplete) > 0 {
		return "INCONCLUSIVE"
	}
	return "NOT_FOUND"
}

func (a *Analysis) Check() error {
	if len(a.Incomplete) > 0 {
		return fmt.Errorf("incomplete capture: %s", a.Incomplete[0])
	}
	return nil
}

func ValidatePattern(pattern string, max int) error {
	if max <= 0 || max == int(^uint(0)>>1) {
		return fmt.Errorf("maximum matches must be positive and below MaxInt")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}
	if re.MatchString("") {
		return fmt.Errorf("pattern must match non-empty data")
	}
	return nil
}

func (s *Searcher) Analyze(pattern string, max int) (*Analysis, error) {
	if err := ValidatePattern(pattern, max); err != nil {
		return nil, err
	}
	meta, err := dumpmeta.Read(s.FilePath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(s.FilePath)
	if err != nil {
		return nil, err
	}
	ranges, err := captureRanges(meta, info.Size())
	if err != nil {
		return nil, err
	}
	scan, err := s.scanRanges(pattern, max, ranges)
	if err != nil {
		return nil, err
	}
	a := &Analysis{Scan: scan, Meta: meta}
	if scan.FileSize == 0 {
		a.Incomplete = append(a.Incomplete, "empty dump")
	}
	if meta != nil {
		if meta.Size != scan.FileSize {
			a.Incomplete = append(a.Incomplete, fmt.Sprintf("metadata size %d differs from file size %d", meta.Size, scan.FileSize))
		}
		if c := meta.Capture; c != nil {
			if !c.Complete {
				a.Incomplete = append(a.Incomplete, "not all selected memory was captured")
			}
			a.Incomplete = append(a.Incomplete, c.Errors...)
			if c.BytesPadded > 0 {
				a.Incomplete = append(a.Incomplete, fmt.Sprintf("%d unread bytes were replaced with padding", c.BytesPadded))
			}
			if c.BytesRead < 0 || c.BytesPadded < 0 || c.BytesRead > scan.FileSize || c.BytesPadded != scan.FileSize-c.BytesRead {
				a.Incomplete = append(a.Incomplete, "capture byte accounting does not match file size")
			}
		}
	}
	if isELF, ranges := s.elfCoreLoadRanges(); isELF {
		for _, rg := range ranges {
			if rg.offset < 0 || rg.length < 0 || rg.offset > scan.FileSize || rg.length > scan.FileSize-rg.offset {
				a.Incomplete = append(a.Incomplete, "ELF declares memory beyond the end of this truncated dump")
				break
			}
		}
	}
	return a, nil
}

// A concatenated dump can join unrelated addresses and contain synthetic
// padding. Search only recorded bytes, merging adjacent virtual addresses from
// the same process. Legacy files without a region layout use the whole file.
func captureRanges(meta *dumpmeta.Meta, size int64) ([]byteRange, error) {
	if meta == nil || meta.Version < 3 || len(meta.Containers) == 0 {
		return nil, nil
	}
	ranges := make([]byteRange, 0)
	var previousEnd, readTotal int64
	for _, c := range meta.Containers {
		for _, p := range c.Processes {
			var virtualEnd uint64
			merge := false
			for _, r := range p.Regions {
				length := r.ByteEnd - r.ByteStart
				if r.ByteStart != previousEnd || length < 0 || r.ByteStart < 0 || r.ByteEnd > size || r.End < r.Start || uint64(length) > r.End-r.Start {
					return nil, fmt.Errorf("invalid or truncated capture region layout")
				}
				previousEnd = r.ByteEnd
				read := length
				if meta.Version >= 4 {
					read = r.BytesRead
				}
				if read < 0 || read > length {
					return nil, fmt.Errorf("invalid captured byte count")
				}
				readTotal += read
				if read > 0 {
					if merge && r.Start == virtualEnd && len(ranges) > 0 && ranges[len(ranges)-1].offset+ranges[len(ranges)-1].length == r.ByteStart {
						ranges[len(ranges)-1].length += read
					} else {
						ranges = append(ranges, byteRange{offset: r.ByteStart, length: read})
					}
				}
				virtualEnd = r.End
				merge = read == length && read > 0
			}
		}
	}
	if previousEnd != size {
		return nil, fmt.Errorf("capture region layout does not cover the dump file")
	}
	if meta.Capture != nil && meta.Version >= 4 && readTotal != meta.Capture.BytesRead {
		return nil, fmt.Errorf("per-region reads disagree with capture accounting")
	}
	return ranges, nil
}
