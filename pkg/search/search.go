package search

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"regexp"
)

// Match represents a search result
type Match struct {
	Offset int64
	Data   []byte
}

// Snippet represents a random memory snippet
type Snippet struct {
	Offset int64
	Data   []byte
}

// Searcher searches memory dumps
type Searcher struct {
	FilePath string
	Verbose  bool
}

// New creates a new searcher
func New(filePath string, verbose bool) *Searcher {
	return &Searcher{
		FilePath: filePath,
		Verbose:  verbose,
	}
}

// Search finds all occurrences of pattern in the dump file
func (s *Searcher) Search(pattern string, maxMatches int) ([]Match, error) {
	// Validate regex pattern before compiling
	_, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	file, err := os.Open(s.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var matches []Match
	re := regexp.MustCompile(pattern)

	// Read file in chunks
	const chunkSize = 1024 * 1024 // 1MB chunks
	buffer := make([]byte, chunkSize)
	overlap := make([]byte, 0)
	offset := int64(0)

	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read error: %w", err)
		}
		if n == 0 {
			break
		}

		// Combine overlap from previous chunk with current chunk
		searchData := append(overlap, buffer[:n]...)

		// Find all matches in this chunk
		indices := re.FindAllIndex(searchData, -1)
		for _, idx := range indices {
			matchOffset := offset - int64(len(overlap)) + int64(idx[0])
			matchData := searchData[idx[0]:idx[1]]

			matches = append(matches, Match{
				Offset: matchOffset,
				Data:   matchData,
			})

			if len(matches) >= maxMatches {
				return matches, nil
			}
		}

		// Keep last 8KB as overlap for next chunk (in case match spans chunks)
		// Increased from 1KB to 8KB to prevent missing matches at chunk boundaries
		overlapSize := 8192
		if n < overlapSize {
			overlapSize = n
		}
		overlap = buffer[n-overlapSize : n]
		offset += int64(n)

		if err == io.EOF {
			break
		}
	}

	return matches, nil
}

// GetContext retrieves n bytes before the given offset (legacy, for compatibility)
func (s *Searcher) GetContext(offset int64, contextSize int) []byte {
	file, err := os.Open(s.FilePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Calculate start position
	start := offset - int64(contextSize)
	if start < 0 {
		start = 0
		contextSize = int(offset)
	}

	// Seek and read
	_, err = file.Seek(start, io.SeekStart)
	if err != nil {
		return nil
	}

	buffer := make([]byte, contextSize)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return nil
	}

	return buffer[:n]
}

// MatchContext holds context before and after a match
type MatchContext struct {
	Before      []byte
	Match       []byte
	After       []byte
	MatchOffset int64
}

// GetMatchContext retrieves bytes before and after the match
func (s *Searcher) GetMatchContext(offset int64, matchLen int, contextBefore, contextAfter int) *MatchContext {
	file, err := os.Open(s.FilePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Get file size
	info, err := file.Stat()
	if err != nil {
		return nil
	}
	fileSize := info.Size()

	// Calculate positions
	beforeStart := offset - int64(contextBefore)
	if beforeStart < 0 {
		contextBefore = int(offset)
		beforeStart = 0
	}

	afterEnd := offset + int64(matchLen) + int64(contextAfter)
	if afterEnd > fileSize {
		afterEnd = fileSize
	}

	// Read before context
	_, err = file.Seek(beforeStart, io.SeekStart)
	if err != nil {
		return nil
	}

	beforeBuf := make([]byte, contextBefore)
	nBefore, _ := file.Read(beforeBuf)

	// Read match
	matchBuf := make([]byte, matchLen)
	nMatch, _ := file.Read(matchBuf)

	// Read after context
	afterBuf := make([]byte, contextAfter)
	nAfter, _ := file.Read(afterBuf)

	return &MatchContext{
		Before:      beforeBuf[:nBefore],
		Match:       matchBuf[:nMatch],
		After:       afterBuf[:nAfter],
		MatchOffset: offset,
	}
}

// GetRandomSnippets returns random memory snippets from guest VM memory
// Samples from middle 80% of dump to avoid QEMU structures at edges
func (s *Searcher) GetRandomSnippets(count, size int) ([]Snippet, error) {
	file, err := os.Open(s.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	fileSize := info.Size()
	var snippets []Snippet

	// Sample from middle 80% of file (skip first/last 10% where QEMU structures live)
	startRange := fileSize / 10         // 10% from start
	endRange := fileSize - fileSize/10  // 10% from end
	rangeSize := endRange - startRange

	if rangeSize < int64(size*count) {
		// File too small, use whole file
		startRange = 0
		rangeSize = fileSize - int64(size)
	}

	for len(snippets) < count {
		// Random offset within guest memory range
		offset := startRange + rand.Int63n(rangeSize)

		_, err := file.Seek(offset, io.SeekStart)
		if err != nil {
			continue
		}

		buffer := make([]byte, size)
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			continue
		}

		snippets = append(snippets, Snippet{
			Offset: offset,
			Data:   buffer[:n],
		})
	}

	return snippets, nil
}

// isAllZeros checks if a byte slice contains only zeros
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// looksEncrypted checks if data looks like encrypted/random bytes
// (not readable ASCII text, not all zeros)
func looksEncrypted(data []byte) bool {
	if len(data) == 0 || isAllZeros(data) {
		return false
	}

	// Count printable ASCII characters
	printableCount := 0
	for _, b := range data {
		if IsPrintable(b) {
			printableCount++
		}
	}

	// If more than 30% is printable ASCII, it's probably readable text (QEMU buffers)
	printableRatio := float64(printableCount) / float64(len(data))
	return printableRatio < 0.3
}

// IsPrintable checks if byte is printable ASCII
func IsPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

// SanitizeBytes converts non-printable bytes to dots
func SanitizeBytes(data []byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		if IsPrintable(b) {
			result[i] = b
		} else {
			result[i] = '.'
		}
	}
	return string(result)
}

// HighlightPattern highlights the pattern in data
func HighlightPattern(data []byte, pattern string) string {
	text := SanitizeBytes(data)
	re := regexp.MustCompile(pattern)

	// Find pattern position
	loc := re.FindStringIndex(text)
	if loc == nil {
		return text
	}

	// Return with ANSI color codes
	before := text[:loc[0]]
	match := text[loc[0]:loc[1]]
	after := text[loc[1]:]

	return fmt.Sprintf("%s\033[1;31m%s\033[0m%s", before, match, after)
}

// IsLikelyEncrypted checks if data looks encrypted (high entropy)
func IsLikelyEncrypted(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Count unique bytes
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy (simplified)
	entropy := 0.0
	dataLen := float64(len(data))
	for _, count := range freq {
		p := float64(count) / dataLen
		if p > 0 {
			entropy -= p * (float64(log2(p)))
		}
	}

	// Encrypted data typically has entropy > 7.0
	return entropy > 7.0
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Approximation of log2
	return 1.4426950408889634 * float64(len(fmt.Sprintf("%b", int(x))))
}

// ContainsPattern checks if data contains the pattern
func ContainsPattern(data []byte, pattern string) bool {
	re := regexp.MustCompile(pattern)
	return re.Match(data)
}

// FingerprintResult is the outcome of searching for a single fingerprint pattern.
type FingerprintResult struct {
	Pattern string
	Found   bool
	Offset  int64
}

// SearchPatterns runs Search(pattern, 1) for each pattern and returns one
// FingerprintResult per input pattern, in the same order. Patterns are
// regex (same syntax as Search). Used by the demo path to probe for
// guest-kernel strings that must live only in encrypted private memory.
func (s *Searcher) SearchPatterns(patterns []string) ([]FingerprintResult, error) {
	results := make([]FingerprintResult, len(patterns))
	for i, p := range patterns {
		results[i].Pattern = p
		matches, err := s.Search(p, 1)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p, err)
		}
		if len(matches) > 0 {
			results[i].Found = true
			results[i].Offset = matches[0].Offset
		}
	}
	return results, nil
}

// vsockHeaderSize is the size of struct virtio_vsock_hdr (LE):
//
//	src_cid u64, dst_cid u64, src_port u32, dst_port u32,
//	len u32, type u16, op u16, flags u32, buf_alloc u32, fwd_cnt u32
const vsockHeaderSize = 44

// LooksLikeVsockSharedBuffer applies a heuristic to decide whether the bytes
// immediately preceding matchOffset look like a virtio-vsock packet header —
// i.e., the match landed inside the kata-agent stdout/vsock shared ring
// buffer rather than in private guest RAM. Returns (true, hexPrefix) when
// the heuristic fires, where hexPrefix is the hex dump of the first 16 bytes
// of the candidate header (for narrative output).
//
// Heuristic (mild on purpose — false positives in the demo are far worse
// than false negatives because they would falsely flag SEV-SNP as broken):
//   - both src_cid and dst_cid are small (<= 16) — vsock CIDs in practice are
//     2 (host), 3+ (guests); kata's CID is well below 16
//   - type == 1 (VIRTIO_VSOCK_TYPE_STREAM)
//   - 0 < len < 1 MiB
func (s *Searcher) LooksLikeVsockSharedBuffer(matchOffset int64) (bool, string) {
	if matchOffset < int64(vsockHeaderSize) {
		return false, ""
	}
	ctx := s.GetMatchContext(matchOffset, 0, vsockHeaderSize, 0)
	if ctx == nil || len(ctx.Before) < vsockHeaderSize {
		return false, ""
	}
	h := ctx.Before
	srcCID := binary.LittleEndian.Uint64(h[0:8])
	dstCID := binary.LittleEndian.Uint64(h[8:16])
	msgLen := binary.LittleEndian.Uint32(h[24:28])
	msgType := binary.LittleEndian.Uint16(h[28:30])

	if srcCID > 16 || dstCID > 16 {
		return false, ""
	}
	if msgType != 1 {
		return false, ""
	}
	if msgLen == 0 || msgLen >= 1<<20 {
		return false, ""
	}

	return true, FormatHex(h[:16], 16)
}

// CheckLinuxBanner searches for Linux kernel banner as a baseline encryption check
// Returns true if Linux banner is found (memory is NOT encrypted)
// Returns false if Linux banner is NOT found (memory is likely encrypted)
func (s *Searcher) CheckLinuxBanner() (bool, error) {
	pattern := `Linux version [0-9]+\.[0-9]+\.[0-9]+`

	matches, err := s.Search(pattern, 1)
	if err != nil {
		return false, fmt.Errorf("baseline check failed: %w", err)
	}

	return len(matches) > 0, nil
}

// DumpVerdict is the result of ClassifyDump.
type DumpVerdict string

const (
	// VerdictEncrypted: dump contents look consistent with confidential-VM
	// private memory as seen from the host (almost entirely zero pages, no
	// kernel banner, no significant printable content).
	VerdictEncrypted DumpVerdict = "encrypted"
	// VerdictUnencryptedVM: a Linux kernel banner is present, so this is an
	// unencrypted VM RAM dump.
	VerdictUnencryptedVM DumpVerdict = "unencrypted-vm"
	// VerdictUnencryptedProcess: no kernel banner but the dump contains
	// substantial printable content (process heap / anon pages of a runc
	// container or any /proc/PID/mem dump).
	VerdictUnencryptedProcess DumpVerdict = "unencrypted-process"
	// VerdictAmbiguous: too little signal to decide (very small dump, or a
	// mix of zeros and random bytes without a clear majority class).
	VerdictAmbiguous DumpVerdict = "ambiguous"
	// VerdictVMCoreNoBanner: the dump is a QEMU ELF core of a VM and no guest
	// kernel banner is present. Readable bytes in such a dump do NOT imply the
	// guest is unencrypted: a SEV-SNP guest keeps private memory encrypted but
	// its shared I/O buffers (virtio/DMA rings, firmware tables) are plaintext
	// by design, and the ELF/core metadata is always readable. Deciding
	// protected vs vulnerable requires the guest-kernel fingerprint probe, so
	// this verdict defers to the caller instead of guessing from byte ratios.
	// See issue #8: counting printable runs over such a dump produced a false
	// "READABLE DUMP — encryption is not active here" on a protected guest.
	VerdictVMCoreNoBanner DumpVerdict = "vm-core-no-banner"
)

// DumpClassification summarises a content-based heuristic over the dump file.
type DumpClassification struct {
	Verdict        DumpVerdict
	HasLinuxBanner bool
	ZeroRatio      float64 // fraction of scanned bytes equal to 0x00
	PrintableRatio float64 // fraction of scanned bytes that are printable ASCII
	SampledBytes   int     // total scanned bytes used for the ratios
	ReadableRuns   int     // count of printable-ASCII runs >= classifyReadableRunLen
	FileSize       int64
	// IsELFCore is true when the dump is an ELF core file (QEMU
	// dump-guest-memory output). When set, the ratios and ReadableRuns above
	// are computed ONLY over PT_LOAD segment bytes (the guest memory), not the
	// ELF headers / PT_NOTE metadata, which are always readable.
	IsELFCore        bool
	LoadSegmentBytes int64 // sum of PT_LOAD Filesz (bytes of guest memory in the file)
	// Truncated is set when the ELF program headers declare segments that
	// extend past the end of the file. That means the dump was cut short,
	// which is exactly what a dump interrupted mid-write looks like, and any
	// "not found" result on such a file is unreliable.
	Truncated        bool
	DeclaredBytes    int64 // highest end offset declared by the program headers
}

// Thresholds for ClassifyDump. Tuned against real dumps:
//   - SEV-SNP dump from the host: the guest's private pages read back as
//     0x00, so the file is ~100% zeros with NO printable-ASCII strings at all.
//   - Any unencrypted VM / process dump always carries readable ASCII strings
//     (kernel/GRUB text, configs, JSON, env vars), even when the resident set
//     is tiny relative to the allocated region and the file is mostly zeros.
//
// The decisive signal is therefore the presence of real ASCII strings (runs of
// printable bytes), counted over the WHOLE file, not the zero ratio. Counting
// strings rather than sampling byte ratios is what fixes the false "ENCRYPTED"
// verdict on sparse plain-VM dumps: a 4 GB guest-RAM dump whose ~40 MB resident
// data sits in the low addresses is ~99% zeros, so any middle-of-file sample
// reads all zeros and wrongly looks encrypted.
const (
	classifyZeroEncryptedMin = 0.95
	classifyMinScanBytes     = 4096
	// A printable-ASCII run of at least this length counts as a "string".
	classifyReadableRunLen = 10
	// At least this many strings means the dump carries readable content and
	// is not an encrypted-from-host image (which has none).
	classifyReadableRunsMin = 16
)

// ClassifyDump runs a content-based heuristic over the dump file and returns
// a verdict plus the raw signals it used. It streams the WHOLE file once and
// combines three signals:
//
//  1. Linux kernel banner search (the original baseline).
//  2. Count of printable-ASCII strings (runs >= classifyReadableRunLen).
//  3. Ratio of zero bytes across the file.
//
// The string count is the decisive signal. An encrypted-from-host image is all
// zeros and contains no strings; any unencrypted VM or process dump always
// carries readable strings even when the file is mostly zeros (sparse resident
// set). See the threshold block above for why this replaces middle-of-file
// sampling, which produced false "ENCRYPTED" verdicts on sparse plain-VM dumps.
//
// Decision order:
//
//   - Banner present -> UnencryptedVM.
//   - ReadableRuns >= classifyReadableRunsMin -> UnencryptedProcess.
//   - ZeroRatio >= classifyZeroEncryptedMin -> Encrypted.
//   - Otherwise -> Ambiguous.
func (s *Searcher) ClassifyDump() (*DumpClassification, error) {
	info, err := os.Stat(s.FilePath)
	if err != nil {
		return nil, fmt.Errorf("stat dump: %w", err)
	}

	// A QEMU dump-guest-memory output is an ELF core file whose guest RAM lives
	// in PT_LOAD segments; the ELF headers and PT_NOTE metadata are always
	// readable ASCII. On an SEV-SNP guest the PT_LOAD bytes read back as zeros,
	// but the readable metadata would trip the string-count heuristic and yield
	// a false "READABLE" verdict (issue #8). When the dump is an ELF core we
	// therefore restrict the content scan to the PT_LOAD ranges only.
	isELF, loadRanges := s.elfCoreLoadRanges()

	// Detect a dump that was cut short: program headers describing bytes that
	// are not in the file. Searching such a dump produces false negatives.
	var declaredEnd int64
	for _, r := range loadRanges {
		if end := r.offset + r.length; end > declaredEnd {
			declaredEnd = end
		}
	}

	scanRanges := loadRanges
	if !isELF || len(loadRanges) == 0 {
		scanRanges = []byteRange{{0, info.Size()}}
	} else {
		scanRanges = clampRanges(loadRanges, info.Size())
	}

	var loadBytes int64
	for _, r := range scanRanges {
		loadBytes += r.length
	}

	banner, err := s.CheckLinuxBanner()
	if err != nil {
		return nil, err
	}

	zeroRatio, printableRatio, scanned, runs, err := s.scanContent(scanRanges)
	if err != nil {
		return nil, err
	}

	c := &DumpClassification{
		HasLinuxBanner: banner,
		ZeroRatio:      zeroRatio,
		PrintableRatio: printableRatio,
		SampledBytes:   scanned,
		ReadableRuns:   runs,
		FileSize:       info.Size(),
		IsELFCore:      isELF,
		DeclaredBytes:  declaredEnd,
		Truncated:      isELF && declaredEnd > info.Size(),
	}
	if isELF && len(loadRanges) > 0 {
		c.LoadSegmentBytes = loadBytes
	}

	switch {
	case banner:
		c.Verdict = VerdictUnencryptedVM
	case scanned < classifyMinScanBytes:
		c.Verdict = VerdictAmbiguous
	case isELF:
		// A VM core dump with no kernel banner. Readable content here is
		// expected even on a protected guest (shared I/O buffers, firmware
		// tables, ELF metadata), so the printable-run count below must not be
		// allowed to declare it unencrypted. The caller confirms with the
		// guest-kernel fingerprint probe.
		c.Verdict = VerdictVMCoreNoBanner
	case runs >= classifyReadableRunsMin:
		c.Verdict = VerdictUnencryptedProcess
	case zeroRatio >= classifyZeroEncryptedMin:
		c.Verdict = VerdictEncrypted
	default:
		c.Verdict = VerdictAmbiguous
	}

	return c, nil
}

// clampRanges trims ranges to the actual end of the file, so a truncated dump
// is scanned over what it really contains instead of erroring on a short read.
func clampRanges(ranges []byteRange, size int64) []byteRange {
	out := make([]byteRange, 0, len(ranges))
	for _, r := range ranges {
		if r.offset >= size {
			continue
		}
		if r.offset+r.length > size {
			r.length = size - r.offset
		}
		if r.length > 0 {
			out = append(out, r)
		}
	}
	return out
}

// byteRange is a half-open [offset, offset+length) span in the dump file.
type byteRange struct {
	offset int64
	length int64
}

// elfCoreLoadRanges reports whether the dump is an ELF core file and, if so,
// returns the file byte ranges of its PT_LOAD segments (guest memory). It
// returns (false, nil) for non-ELF dumps (procmem / raw VM RAM) and on any
// parse error, so the caller falls back to a whole-file scan.
func (s *Searcher) elfCoreLoadRanges() (bool, []byteRange) {
	f, err := os.Open(s.FilePath)
	if err != nil {
		return false, nil
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false, nil
	}
	if !bytes.Equal(magic, []byte("\x7fELF")) {
		return false, nil
	}

	ef, err := elf.NewFile(f)
	if err != nil {
		return false, nil
	}
	defer ef.Close()

	var ranges []byteRange
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			ranges = append(ranges, byteRange{offset: int64(p.Off), length: int64(p.Filesz)})
		}
	}
	return true, ranges
}

// scanContent streams the given byte ranges of the dump file once and reports
// (zeroRatio, printableRatio, totalScanned, readableRuns) over just those
// ranges. For a raw dump the caller passes the whole file; for an ELF core it
// passes only the PT_LOAD ranges so ELF metadata does not skew the signals.
//
// readableRuns counts maximal runs of printable ASCII at least
// classifyReadableRunLen bytes long, tracked across read-buffer boundaries but
// reset at each range boundary. It stops counting (but keeps reading for the
// ratios) once the threshold is comfortably exceeded, so a plain dump never
// pays for counting millions of strings while an encrypted (all-zero) dump is
// still scanned in full and correctly reports zero strings.
func (s *Searcher) scanContent(ranges []byteRange) (float64, float64, int, int, error) {
	f, err := os.Open(s.FilePath)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("open dump: %w", err)
	}
	defer f.Close()

	const bufSize = 4 * 1024 * 1024
	buf := make([]byte, bufSize)

	var zeros, printable, total int
	var runs int
	const runStop = classifyReadableRunsMin * 4

	for _, rg := range ranges {
		if _, err := f.Seek(rg.offset, io.SeekStart); err != nil {
			return 0, 0, 0, 0, fmt.Errorf("seek dump: %w", err)
		}
		remaining := rg.length
		curRun := 0 // runs do not span range boundaries
		for remaining > 0 {
			toRead := int64(bufSize)
			if remaining < toRead {
				toRead = remaining
			}
			n, readErr := f.Read(buf[:toRead])
			for _, b := range buf[:n] {
				if b == 0 {
					zeros++
				} else if IsPrintable(b) {
					printable++
				}
				if IsPrintable(b) {
					curRun++
					if curRun == classifyReadableRunLen && runs < runStop {
						runs++
					}
				} else {
					curRun = 0
				}
			}
			total += n
			remaining -= int64(n)
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return 0, 0, 0, 0, fmt.Errorf("read dump: %w", readErr)
			}
		}
	}

	if total == 0 {
		return 0, 0, 0, 0, nil
	}
	return float64(zeros) / float64(total), float64(printable) / float64(total), total, runs, nil
}

// FormatHex formats bytes as hex dump
func FormatHex(data []byte, bytesPerLine int) string {
	var result bytes.Buffer
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		// Hex part
		result.WriteString(fmt.Sprintf("%08x  ", i))
		for j := i; j < end; j++ {
			result.WriteString(fmt.Sprintf("%02x ", data[j]))
		}

		// Padding
		for j := end; j < i+bytesPerLine; j++ {
			result.WriteString("   ")
		}

		// ASCII part
		result.WriteString(" |")
		for j := i; j < end; j++ {
			if IsPrintable(data[j]) {
				result.WriteByte(data[j])
			} else {
				result.WriteByte('.')
			}
		}
		result.WriteString("|\n")
	}

	return result.String()
}
