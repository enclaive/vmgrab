package search

import (
	"bytes"
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

// CheckLinuxBanner searches for Linux kernel banner as a baseline encryption check
// Returns true if Linux banner is found (memory is NOT encrypted)
// Returns false if Linux banner is NOT found (memory is likely encrypted)
func (s *Searcher) CheckLinuxBanner() (bool, error) {
	// Linux kernel banner pattern - this is a static string in the kernel
	// that should always be present in unencrypted memory dumps
	// Reference: https://blogs.oracle.com/linux/live-kernel-debugging-2
	pattern := `Linux version [0-9]+\.[0-9]+\.[0-9]+`

	matches, err := s.Search(pattern, 1)
	if err != nil {
		return false, fmt.Errorf("baseline check failed: %w", err)
	}

	// If we found the Linux banner, memory is NOT encrypted
	return len(matches) > 0, nil
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
