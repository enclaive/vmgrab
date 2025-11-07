package disk

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// DiskInfo represents VM disk information
type DiskInfo struct {
	Path   string
	Size   int64
	Format string // qcow2, raw, etc
}

// Match represents a disk search match
type Match struct {
	Offset int64
	Data   []byte
}

// GetDiskPath returns disk path for VM via virsh
func GetDiskPath(host, user, keyPath, vmName string) (*DiskInfo, error) {
	// Execute: virsh domblklist <vm-name>
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'sudo virsh domblklist %s' 2>&1 | grep -v Warning:",
		keyPath, user, host, vmName)

	output, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("virsh domblklist failed: %w (output: %s)", err, string(output))
	}

	// Parse output to find disk path
	// Format: "vda    /path/to/disk.qcow2"
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "vda") || strings.HasPrefix(line, "sda") || strings.HasPrefix(line, "hda") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				diskPath := fields[1]

				// Get disk info
				info, err := getDiskInfo(host, user, keyPath, diskPath)
				if err != nil {
					return &DiskInfo{Path: diskPath}, nil // Return path even if stat fails
				}

				return info, nil
			}
		}
	}

	return nil, fmt.Errorf("no disk found for VM %s", vmName)
}

// getDiskInfo gets size and format info for disk
func getDiskInfo(host, user, keyPath, diskPath string) (*DiskInfo, error) {
	// Get file size
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'sudo stat -c \"%%s\" %s' 2>&1 | grep -v Warning:",
		keyPath, user, host, diskPath)

	output, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("stat failed: %w", err)
	}

	size, _ := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)

	// Detect format from extension
	format := "unknown"
	if strings.HasSuffix(diskPath, ".qcow2") {
		format = "qcow2"
	} else if strings.HasSuffix(diskPath, ".raw") {
		format = "raw"
	} else if strings.HasSuffix(diskPath, ".img") {
		format = "img"
	}

	return &DiskInfo{
		Path:   diskPath,
		Size:   size,
		Format: format,
	}, nil
}

// SearchDisk searches for pattern in disk file on remote host
func SearchDisk(host, user, keyPath, diskPath, pattern string, maxMatches int) ([]Match, error) {
	// Execute: sudo grep -a -b --text "pattern" /path/to/disk | head -n <maxMatches>
	grepCmd := fmt.Sprintf("sudo grep -a -b --text '%s' %s 2>/dev/null | head -n %d",
		pattern, diskPath, maxMatches)

	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s '%s' 2>&1 | grep -v Warning:",
		keyPath, user, host, grepCmd)

	output, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	if err != nil {
		// grep returns exit code 1 if no matches found
		if strings.Contains(string(output), "No such file") {
			return nil, fmt.Errorf("disk file not found: %s", diskPath)
		}
		// No matches is not an error for us
		return []Match{}, nil
	}

	return parseGrepOutput(string(output), pattern), nil
}

// parseGrepOutput parses grep -b output
// Format: "1234:match text here"
func parseGrepOutput(output, pattern string) []Match {
	var matches []Match

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse offset:text
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		offset, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}

		matches = append(matches, Match{
			Offset: offset,
			Data:   []byte(parts[1]),
		})
	}

	return matches
}

// GetContext retrieves context around offset in disk file
func GetContext(host, user, keyPath, diskPath string, offset int64, contextSize int) []byte {
	// Calculate start position
	start := offset - int64(contextSize)
	if start < 0 {
		start = 0
		contextSize = int(offset)
	}

	// Use dd to extract bytes
	ddCmd := fmt.Sprintf("sudo dd if=%s bs=1 skip=%d count=%d 2>/dev/null",
		diskPath, start, contextSize)

	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s '%s' 2>&1 | grep -v Warning:",
		keyPath, user, host, ddCmd)

	output, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	if err != nil {
		return nil
	}

	return output
}

// IsEncrypted checks if disk appears to be encrypted (high entropy)
func IsEncrypted(matches []Match, diskPath string) bool {
	// Heuristics:
	// 1. No matches found + disk is .raw = likely LUKS
	// 2. Disk path contains "luks" or "crypt"
	// 3. Very few matches relative to disk size

	if len(matches) == 0 {
		// Check path indicators
		pathLower := strings.ToLower(diskPath)
		if strings.Contains(pathLower, "luks") ||
			strings.Contains(pathLower, "crypt") ||
			strings.Contains(pathLower, "encrypted") ||
			strings.Contains(pathLower, "sev") ||
			strings.Contains(pathLower, "cvm") {
			return true
		}

		// No matches + raw format often means encrypted
		if strings.HasSuffix(diskPath, ".raw") {
			return true
		}
	}

	return false
}

// SanitizeBytes converts non-printable bytes to dots
func SanitizeBytes(data []byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			result[i] = b
		} else {
			result[i] = '.'
		}
	}
	return string(result)
}

// HighlightPattern highlights pattern in data
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
