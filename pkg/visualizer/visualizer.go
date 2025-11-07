package visualizer

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// AnimateCursorToMatch shows cursor moving through context data toward the match
func AnimateCursorToMatch(contextData []byte, pattern string) {
	if len(contextData) == 0 {
		return
	}

	// Sanitize data
	text := sanitize(contextData)

	// Find pattern position in sanitized text
	patternPos := strings.Index(text, pattern)
	if patternPos == -1 {
		// Pattern not in sanitized form, just show context
		ShowMatchContext(contextData, pattern)
		return
	}

	// Show context line by line with cursor animation
	charsPerLine := 80
	lines := splitIntoLines(text, charsPerLine)

	targetPos := patternPos

	for lineNum, line := range lines {
		lineStart := lineNum * charsPerLine
		lineEnd := lineStart + len(line)

		// Check if pattern is in this line
		if targetPos >= lineStart && targetPos < lineEnd {
			// Show context before animating
			fmt.Printf("%s\n", color.HiBlackString(line))
			fmt.Println()
			color.Cyan("🔍 Scanning for pattern...")
			fmt.Println()

			// Animate cursor to pattern in this line
			relativePos := targetPos - lineStart
			for i := 0; i <= relativePos; i++ {
				// Clear line and reprint with cursor
				fmt.Printf("\r%s", strings.Repeat(" ", charsPerLine+10))
				fmt.Printf("\r")

				before := line[:i]
				cursor := color.YellowString("▶")
				after := ""
				if i < len(line) {
					after = color.HiBlackString(line[i:])
				}

				fmt.Printf("%s%s%s", color.HiWhiteString(before), cursor, after)
				time.Sleep(30 * time.Millisecond) // Slower animation
			}
			fmt.Println() // New line after animation

			// Highlight the match
			fmt.Printf("\r%s", strings.Repeat(" ", charsPerLine+10))
			fmt.Printf("\r")

			before := line[:relativePos]
			matchText := ""
			if relativePos+len(pattern) <= len(line) {
				matchText = line[relativePos : relativePos+len(pattern)]
			} else {
				matchText = line[relativePos:]
			}
			after := ""
			if relativePos+len(pattern) < len(line) {
				after = line[relativePos+len(pattern):]
			}

			fmt.Printf("%s%s%s\n",
				color.HiWhiteString(before),
				color.New(color.FgRed, color.Bold).Sprint(matchText),
				color.HiWhiteString(after))

			// Show remaining lines
			for j := lineNum + 1; j < len(lines); j++ {
				fmt.Println(color.HiWhiteString(lines[j]))
			}

			return
		} else {
			// Print line normally (already passed)
			fmt.Println(color.HiBlackString(line))
		}
	}
}

// ShowMatchContext displays context with highlighted pattern (no animation)
func ShowMatchContext(contextData []byte, pattern string) {
	text := sanitize(contextData)

	// Highlight pattern
	patternPos := strings.Index(text, pattern)
	if patternPos == -1 {
		fmt.Println(color.HiWhiteString(text))
		return
	}

	before := text[:patternPos]
	match := text[patternPos : patternPos+len(pattern)]
	after := ""
	if patternPos+len(pattern) < len(text) {
		after = text[patternPos+len(pattern):]
	}

	// Print with highlighting
	fmt.Printf("%s%s%s\n",
		color.HiWhiteString(before),
		color.New(color.FgRed, color.Bold).Sprint(match),
		color.HiWhiteString(after))
}

// AnimateEncryptedSnippet shows encrypted memory with animation
func AnimateEncryptedSnippet(data []byte, speedMs int) {
	if len(data) == 0 {
		return
	}

	const bytesPerLine = 16
	lines := (len(data) + bytesPerLine - 1) / bytesPerLine

	for line := 0; line < lines; line++ {
		start := line * bytesPerLine
		end := start + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		// Hex part
		fmt.Print(color.HiBlackString(fmt.Sprintf("%08x  ", start)))

		for i := start; i < end; i++ {
			// Animated hex bytes with random colors
			colors := []color.Attribute{
				color.FgHiBlack,
				color.FgBlack,
			}
			c := color.New(colors[i%len(colors)])
			c.Printf("%02x ", data[i])
			time.Sleep(time.Duration(speedMs/bytesPerLine) * time.Millisecond)
		}

		// Padding
		for i := end; i < start+bytesPerLine; i++ {
			fmt.Print("   ")
		}

		// ASCII part (all dots for encrypted)
		fmt.Print(color.HiBlackString(" |"))
		for i := start; i < end; i++ {
			if isPrintable(data[i]) {
				fmt.Print(color.HiBlackString(string(data[i])))
			} else {
				fmt.Print(color.HiBlackString("."))
			}
		}
		fmt.Println(color.HiBlackString("|"))
	}
}

// ShowEncryptedSnippet shows encrypted memory without animation
func ShowEncryptedSnippet(data []byte) {
	const bytesPerLine = 16
	lines := (len(data) + bytesPerLine - 1) / bytesPerLine

	for line := 0; line < lines; line++ {
		start := line * bytesPerLine
		end := start + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		// Hex part
		fmt.Print(color.HiBlackString(fmt.Sprintf("%08x  ", start)))

		for i := start; i < end; i++ {
			fmt.Print(color.HiBlackString(fmt.Sprintf("%02x ", data[i])))
		}

		// Padding
		for i := end; i < start+bytesPerLine; i++ {
			fmt.Print("   ")
		}

		// ASCII part
		fmt.Print(color.HiBlackString(" |"))
		for i := start; i < end; i++ {
			if isPrintable(data[i]) {
				fmt.Print(color.HiBlackString(string(data[i])))
			} else {
				fmt.Print(color.HiBlackString("."))
			}
		}
		fmt.Println(color.HiBlackString("|"))
	}
}

// sanitize converts non-printable bytes to dots
func sanitize(data []byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		if isPrintable(b) {
			result[i] = b
		} else {
			result[i] = '.'
		}
	}
	return string(result)
}

// isPrintable checks if byte is printable ASCII
func isPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

// splitIntoLines splits text into lines of given length
func splitIntoLines(text string, lineLen int) []string {
	var lines []string
	for i := 0; i < len(text); i += lineLen {
		end := i + lineLen
		if end > len(text) {
			end = len(text)
		}
		lines = append(lines, text[i:end])
	}
	return lines
}

// ShowProgressBar shows a simple progress bar animation
func ShowProgressBar(label string, duration time.Duration) {
	const width = 40
	steps := 50

	for i := 0; i <= steps; i++ {
		progress := float64(i) / float64(steps)
		filled := int(progress * float64(width))

		bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

		fmt.Printf("\r%s [%s] %3.0f%%",
			color.CyanString(label),
			bar,
			progress*100)

		time.Sleep(duration / time.Duration(steps))
	}

	fmt.Println()
}
