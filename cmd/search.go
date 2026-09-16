package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/enclaive/vmgrab/pkg/dumpmeta"
	"github.com/enclaive/vmgrab/pkg/search"
	"github.com/enclaive/vmgrab/pkg/visualizer"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var searchCmd = &cobra.Command{
	Use:   "search <dump-file> <pattern>",
	Short: "Search for patterns in memory dump",
	Long:  "Search memory dump for sensitive data patterns with visual effects",
	Args:  cobra.ExactArgs(2),
	RunE:  runSearch,
}

var (
	searchContext  int
	searchAnimate  bool
	searchMaxMatch int
)

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().IntVarP(&searchContext, "context", "C", 100, "Show N characters before and after match")
	searchCmd.Flags().BoolVarP(&searchAnimate, "animate", "a", false, "Show animated cursor moving to match")
	searchCmd.Flags().IntVarP(&searchMaxMatch, "max", "m", 10, "Maximum number of matches to display")
}

// sizeAfter returns the file size after waiting d. It is used to detect a dump
// file that is still being written. Returns -1 if the size cannot be read.
func sizeAfter(path string, d time.Duration) int64 {
	time.Sleep(d)
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func runSearch(cmd *cobra.Command, args []string) error {
	dumpFile := args[0]
	pattern := args[1]

	verbose, _ := cmd.Flags().GetBool("verbose")

	// Check if file exists
	info, err := os.Stat(dumpFile)
	if err != nil {
		return fmt.Errorf("cannot access dump file: %w", err)
	}

	// Guard against scanning a dump that is still being written. A partial dump
	// silently produces false negatives (issue #8): the marker may sit in a
	// region not yet flushed to disk. Sample the size twice; if it grew, warn.
	if size2 := sizeAfter(dumpFile, 400*time.Millisecond); size2 > info.Size() {
		color.Yellow("⚠️  Dump file is still growing (%s → %s) — it may be an in-progress dump.",
			formatBytes(info.Size()), formatBytes(size2))
		color.HiBlack("   Wait for `vmgrab dump` to finish, then re-run search to avoid a partial scan.")
		fmt.Println()
		if info, err = os.Stat(dumpFile); err != nil {
			return fmt.Errorf("cannot access dump file: %w", err)
		}
	}

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("\n🔍 Searching Memory Dump\n")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	fmt.Printf("📂 Dump file:     %s\n", color.CyanString(dumpFile))
	fmt.Printf("📊 File size:     %s\n", color.HiBlackString(formatBytes(info.Size())))
	fmt.Printf("🔎 Pattern:       %s\n", color.YellowString(pattern))
	fmt.Printf("📏 Context:       %s\n", color.HiBlackString(fmt.Sprintf("%d chars before/after match", searchContext)))
	fmt.Println()

	// Create searcher
	s := search.New(dumpFile, verbose)

	// Search for pattern
	color.Cyan("⏳ Scanning memory dump...")
	matches, err := s.Search(pattern, searchMaxMatch)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	// Display results
	if len(matches) == 0 {
		color.Yellow("No matches found for pattern: %s", pattern)
		fmt.Println()

		meta, metaErr := dumpmeta.Read(dumpFile)
		if metaErr != nil && verbose {
			color.HiBlack("Could not read sidecar metadata: %v", metaErr)
		}

		classification, classErr := s.ClassifyDump()
		if classErr != nil && verbose {
			color.HiBlack("Could not classify dump contents: %v", classErr)
		}

		printNoMatchVerdict(s, pattern, meta, classification)
	} else {
		color.Red("⚠️  VULNERABLE - %d match(es) found!", len(matches))
		fmt.Println()
		color.HiBlack("This indicates the memory is NOT encrypted and sensitive data is exposed!")

		for i, match := range matches {
			fmt.Println()
			fmt.Printf("%s\n", color.RedString(fmt.Sprintf("══════════ Match %d/%d ══════════", i+1, len(matches))))
			fmt.Printf("📍 Offset: %s\n", color.HiBlackString(fmt.Sprintf("0x%x (%d bytes into dump)", match.Offset, match.Offset)))

			// Get context before and after
			ctx := s.GetMatchContext(match.Offset, len(match.Data), searchContext, searchContext)
			if ctx != nil {
				fmt.Println()
				// Show context with highlighted match
				beforeStr := search.SanitizeBytes(ctx.Before)
				matchStr := search.SanitizeBytes(ctx.Match)
				afterStr := search.SanitizeBytes(ctx.After)

				// Print with colors: gray...RED MATCH...gray
				fmt.Print(color.HiBlackString(beforeStr))
				fmt.Print(color.New(color.FgRed, color.Bold).Sprint(matchStr))
				fmt.Println(color.HiBlackString(afterStr))
			} else {
				// Fallback to old method
				contextData := s.GetContext(match.Offset, searchContext)
				if searchAnimate {
					visualizer.AnimateCursorToMatch(contextData, pattern)
				} else {
					visualizer.ShowMatchContext(contextData, pattern)
				}
			}
		}
	}

	fmt.Println()
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	return nil
}

// printNoMatchVerdict explains why no matches were found and, where possible,
// classifies the dump. Two information sources are combined:
//
//   - dumpmeta sidecar (if present): tells which backend produced the dump and
//     what kind of artifact it is (pod-runc process dump vs pod-kata VM dump).
//     This selects the verdict branch.
//   - ClassifyDump heuristic over the bytes (zeros / printable / banner):
//     used as a cross-check against meta and as the fallback when meta is
//     absent (legacy dumps).
//
// Sidecar metadata is unsigned, so meta and content can disagree (file moved
// between dumps, manual edit). Disagreement surfaces as a warning instead of
// silently overriding either signal.
func printNoMatchVerdict(s *search.Searcher, pattern string, meta *dumpmeta.Meta, c *search.DumpClassification) {
	if c != nil {
		scope := "whole file"
		if c.IsELFCore {
			scope = fmt.Sprintf("ELF core, %s of guest LOAD segments", formatBytes(c.LoadSegmentBytes))
		}
		color.HiBlack("Content profile: size=%s zeros=%.0f%% printable=%.0f%% strings=%d banner=%v (%s)",
			formatBytes(c.FileSize), c.ZeroRatio*100, c.PrintableRatio*100, c.ReadableRuns, c.HasLinuxBanner, scope)
		fmt.Println()
	}

	if c != nil && c.Truncated {
		color.Red("⚠️  TRUNCATED DUMP — this file is shorter than it claims to be")
		fmt.Println()
		color.HiBlack("Program headers declare %s of guest memory but the file holds %s.",
			formatBytes(c.DeclaredBytes), formatBytes(c.FileSize))
		color.HiBlack("A dump interrupted mid-write looks exactly like this, and a")
		color.HiBlack("\"not found\" result on it means nothing: the data may be in the")
		color.HiBlack("missing tail. Re-run `vmgrab dump` and let it finish before searching.")
		fmt.Println()
	}

	if meta != nil {
		color.HiBlack("Dump origin (from %s sidecar): backend=%s kind=%s target=%s pid=%d",
			dumpmeta.Suffix, meta.Backend, displayKind(meta), meta.Target, meta.PID)
		fmt.Println()

		switch meta.Kind {
		case "pod-runc":
			printPodRuncVerdict(meta, pattern)
			warnMetaContentMismatch(meta, c)
			return
		case "pod-kata":
			printPodKataVerdict(s)
			warnMetaContentMismatch(meta, c)
			return
		}

		// Any whole-VM dump, whatever the on-disk format. The qemu backend
		// writes an ELF core while procmem and libvirt write raw guest RAM,
		// but the same guest produces the same evidence either way, so the
		// verdict must not depend on the container format (issue #8).
		if isVMDump(meta) {
			if c != nil && c.HasLinuxBanner {
				printBannerVulnerable(pattern)
			} else {
				printVMCoreVerdict(s, pattern, c, meta)
			}
			return
		}
	}

	printContentVerdict(s, pattern, c, meta)
}

// isVMDump reports whether the sidecar describes a whole-VM memory dump as
// opposed to a container process dump. Pod kinds are handled separately.
func isVMDump(m *dumpmeta.Meta) bool {
	if m.Kind != "" {
		return false
	}
	switch m.Backend {
	case "qemu", "libvirt", "procmem":
		return true
	}
	return false
}

// printBannerVulnerable is the unambiguous case: the guest kernel banner is
// readable from the host, so guest memory is not protected.
func printBannerVulnerable(pattern string) {
	color.Red("❌ NOT ENCRYPTED — guest kernel banner is readable from the host")
	fmt.Println()
	color.HiBlack("Guest memory is exposed; memory encryption is not protecting this VM.")
	color.HiBlack("Pattern '%s' was not found; try different patterns.", pattern)
}

// guestBytesScanned reports how much guest memory the content scan covered.
// For an ELF core that is the PT_LOAD total; for a raw dump it is everything.
func guestBytesScanned(c *search.DumpClassification) string {
	if c == nil {
		return "0 B"
	}
	if c.IsELFCore && c.LoadSegmentBytes > 0 {
		return formatBytes(c.LoadSegmentBytes)
	}
	return formatBytes(c.FileSize)
}

func displayKind(m *dumpmeta.Meta) string {
	if m.Kind == "" {
		return "(vm)"
	}
	return m.Kind
}

// printPodRuncVerdict states the structural fact: a runc container memory
// dump cannot be "SEV-SNP encrypted" — memory encryption protects VMs, not
// host processes. Also calls out a common gotcha that produces a false
// "ENCRYPTED" verdict: markers written via `kubectl exec ... > /tmp/...` land
// in the container filesystem, not in the target process address space.
func printPodRuncVerdict(meta *dumpmeta.Meta, pattern string) {
	color.Cyan("📄 PROCESS MEMORY DUMP — memory encryption does not apply")
	fmt.Println()
	color.HiBlack("This is a /proc/%d/mem dump of a runc container.", meta.PID)
	color.HiBlack("SEV-SNP / TDX protect guest VMs, not host processes — the right")
	color.HiBlack("comparison is whether the runc pod's secrets are visible to host")
	color.HiBlack("root (they are), not whether the dump is 'encrypted'.")
	fmt.Println()
	color.HiBlack("Pattern '%s' was not found in this process's address space.", pattern)
	color.HiBlack("If you injected the marker via a file (e.g. `kubectl exec ... > /tmp/x`),")
	color.HiBlack("it lives in the container filesystem, not in the dumped process.")
	color.HiBlack("To land it in memory, feed it through the target process (e.g.")
	color.HiBlack("`mongosh --eval 'db.t.insertOne({s:\"...\"})'` for mongodb).")
}

// printPodKataVerdict runs the kernel-fingerprint probe used by the demo
// path: in a real SEV-SNP guest these strings live in encrypted private
// memory, so the host must see none of them.
func printPodKataVerdict(s *search.Searcher) {
	color.Cyan("🔬 Probing for guest-kernel fingerprints")
	color.HiBlack("These strings live in the guest kernel; if SEV-SNP is encrypting")
	color.HiBlack("private memory, the host must see none of them.")
	fmt.Println()

	fps, err := s.SearchPatterns(kernelFingerprintPatterns)
	if err != nil {
		color.Yellow("Kernel-fingerprint probe failed: %v", err)
		return
	}

	hits := 0
	for _, r := range fps {
		if r.Found {
			hits++
			fmt.Printf("   %-40s %s\n", r.Pattern, color.RedString("✗ FOUND at 0x%x", r.Offset))
		} else {
			fmt.Printf("   %-40s %s\n", r.Pattern, color.GreenString("✓ not found"))
		}
	}

	fmt.Println()
	if hits == 0 {
		color.Green("✅ PROTECTED — guest private memory is encrypted")
		showEncryptedSnippets(s)
	} else {
		color.Red("❌ VULNERABLE — %d kernel fingerprint(s) visible from host", hits)
	}
}

// printContentVerdict is the meta-less path: decide from byte stats alone.
func printContentVerdict(s *search.Searcher, pattern string, c *search.DumpClassification, meta *dumpmeta.Meta) {
	if c == nil {
		color.Yellow("Could not analyze dump contents")
		return
	}

	switch c.Verdict {
	case search.VerdictUnencryptedVM:
		color.Red("❌ NOT ENCRYPTED — Linux kernel banner found in dump")
		fmt.Println()
		color.HiBlack("This VM does NOT have memory encryption enabled.")
		color.HiBlack("Pattern '%s' was not found; try different patterns.", pattern)
	case search.VerdictUnencryptedProcess:
		color.Cyan("📄 READABLE DUMP — process memory or unencrypted VM")
		fmt.Println()
		color.HiBlack("Substantial printable content found; encryption is not active here.")
		color.HiBlack("Pattern '%s' was not found; try different patterns.", pattern)
	case search.VerdictVMCoreNoBanner:
		printVMCoreVerdict(s, pattern, c, meta)
	case search.VerdictEncrypted:
		if c.IsELFCore {
			// QEMU dump-guest-memory of an SEV-SNP guest: the ELF/core metadata
			// is readable, but the PT_LOAD guest-memory segments read back as
			// zeros. Report both facts explicitly so the readable metadata is
			// not mistaken for readable guest memory (issue #8).
			color.Green("✅ SEV-SNP PROTECTED — guest memory in this QEMU core dump is not readable")
			fmt.Println()
			color.HiBlack("ELF/core metadata is readable (as expected for any core file).")
			color.HiBlack("Guest memory LOAD segments are zeroed/unreadable from the host.")
			color.HiBlack("No guest strings found in the %s of guest memory scanned.", formatBytes(c.LoadSegmentBytes))
			color.HiBlack("Pattern '%s' was not found.", pattern)
		} else {
			color.Green("✅ ENCRYPTED — content consistent with SEV-SNP-protected guest memory")
			fmt.Println()
			color.HiBlack("Almost-all-zero pages with no kernel banner; this matches the")
			color.HiBlack("host-side view of a confidential VM whose private memory is encrypted.")
		}
		showEncryptedSnippets(s)
	case search.VerdictAmbiguous:
		color.Yellow("⚠️  AMBIGUOUS — too little signal to classify")
		fmt.Println()
		color.HiBlack("The dump is small or has mixed content. Without a metadata sidecar")
		color.HiBlack("the encryption status cannot be determined from byte contents alone.")
	default:
		color.Yellow("Unclassified dump")
	}
}

// printVMCoreVerdict decides a QEMU VM core dump that carries no guest kernel
// banner. Byte ratios alone cannot settle this case: a SEV-SNP guest keeps its
// private memory encrypted, yet the same dump legitimately contains readable
// shared I/O buffers (virtio/DMA rings), firmware tables and ELF/core metadata.
// Counting those as "readable" is what produced the false "encryption is not
// active here" verdict reported in issue #8. The authoritative evidence is
// whether guest-kernel structures are visible, so we run the fingerprint probe.
func printVMCoreVerdict(s *search.Searcher, pattern string, c *search.DumpClassification, meta *dumpmeta.Meta) {
	color.Cyan("🔬 VM memory dump — probing for guest-kernel fingerprints")
	color.HiBlack("These strings live in guest kernel memory. If the guest's private")
	color.HiBlack("memory is encrypted, the host must not see any of them.")
	fmt.Println()

	fps, err := s.SearchPatterns(kernelFingerprintPatterns)
	if err != nil {
		color.Yellow("Kernel-fingerprint probe failed: %v", err)
		return
	}

	hits := 0
	for _, r := range fps {
		if r.Found {
			hits++
			fmt.Printf("   %-40s %s\n", r.Pattern, color.RedString("✗ FOUND at 0x%x", r.Offset))
		} else {
			fmt.Printf("   %-40s %s\n", r.Pattern, color.GreenString("✓ not found"))
		}
	}
	fmt.Println()

	if hits > 0 {
		color.Red("❌ VULNERABLE — %d guest-kernel fingerprint(s) visible from the host", hits)
		fmt.Println()
		color.HiBlack("Guest memory is readable; memory encryption is not protecting this VM.")
		color.HiBlack("Pattern '%s' was not found, but other guest data is exposed.", pattern)
		return
	}

	// Absence of guest-kernel structures has two possible causes: the guest's
	// memory really is protected, or the guest kernel was simply not resident
	// yet (VM sitting in firmware or a bootloader, or just started). Content
	// alone cannot tell them apart, so only claim protection when the dump's
	// sidecar records a confidential-computing technology detected at dump time.
	tech := ""
	if meta != nil {
		tech = meta.Security
	}

	if tech == "" {
		color.Yellow("ℹ️  INCONCLUSIVE — no guest-kernel structures found, protection not confirmed")
		fmt.Println()
		color.HiBlack("Guest kernel fingerprints: 0 of %d found in %s of guest memory.",
			len(kernelFingerprintPatterns), guestBytesScanned(c))
		color.HiBlack("That has two possible causes and this dump cannot distinguish them:")
		color.HiBlack("  1. guest memory is encrypted, so the host cannot read it, or")
		color.HiBlack("  2. the guest kernel was not in memory yet (VM still in firmware")
		color.HiBlack("     or a bootloader), in which case the VM may be fully exposed.")
		fmt.Println()
		color.HiBlack("Run `vmgrab list` to see whether this target is a confidential VM, and")
		color.HiBlack("re-dump once the guest has finished booting. Dumps taken by a current")
		color.HiBlack("`vmgrab dump` record the detected technology in the %s sidecar,", dumpmeta.Suffix)
		color.HiBlack("which makes this verdict definitive.")
		return
	}

	color.Green("✅ %s PROTECTED — guest private memory is not readable from the host", tech)
	fmt.Println()
	color.HiBlack("Target was detected as %s when the dump was taken (%s sidecar).", tech, dumpmeta.Suffix)
	if c != nil && c.IsELFCore {
		color.HiBlack("ELF/core metadata is readable, as it is in any core file.")
	}
	color.HiBlack("Guest kernel fingerprints: 0 of %d found in %s of guest memory.",
		len(kernelFingerprintPatterns), guestBytesScanned(c))
	color.HiBlack("Pattern '%s' was not found.", pattern)
	fmt.Println()
	if c.ReadableRuns > 0 {
		color.HiBlack("Note: this dump does contain readable byte runs. On a confidential VM")
		color.HiBlack("that is expected — shared I/O buffers (virtio/DMA rings) and firmware")
		color.HiBlack("tables are NOT encrypted by design, only guest private memory is.")
		color.HiBlack("A secret that travelled over virtio (console, network, disk) can appear")
		color.HiBlack("there even on a protected guest; that is a workload issue, not a SEV-SNP failure.")
	}
}

// warnMetaContentMismatch prints a single-line warning when the sidecar's
// declared kind disagrees with the content profile. The warning does not
// override the meta-driven verdict — it just tells the operator the two
// signals are inconsistent (possible tampering, wrong meta, or moved dump).
func warnMetaContentMismatch(meta *dumpmeta.Meta, c *search.DumpClassification) {
	if c == nil {
		return
	}
	switch meta.Kind {
	case "pod-runc":
		// Only flag when the dump looks like an actual confidential-VM image
		// (Encrypted verdict). A high zero-ratio alone is not enough — small
		// runc dumps with mostly-empty pages legitimately have ~93% zeros.
		if c.Verdict == search.VerdictEncrypted {
			fmt.Println()
			color.Yellow("⚠️  Content profile (zeros=%.0f%%, printable=%.0f%%) looks encrypted, but meta claims pod-runc.",
				c.ZeroRatio*100, c.PrintableRatio*100)
			color.Yellow("    Meta is unsigned — it may be stale, wrong, or tampered.")
		}
	case "pod-kata":
		if c.Verdict == search.VerdictUnencryptedProcess || c.HasLinuxBanner {
			fmt.Println()
			color.Yellow("⚠️  Content profile looks like a process / unencrypted dump, but meta claims pod-kata.")
			color.Yellow("    Meta is unsigned — it may be stale, wrong, or tampered.")
		}
	}
}

func showEncryptedSnippets(s *search.Searcher) {
	fmt.Println()
	color.Cyan("📜 Random snippets from dump:")
	color.HiBlack("(encrypted pages appear as zeros to the host)")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	snippets, _ := s.GetRandomSnippets(3, 128)
	for i, snippet := range snippets {
		fmt.Printf("\n%s\n", color.HiBlackString(fmt.Sprintf("Snippet %d (offset: 0x%x):", i+1, snippet.Offset)))
		visualizer.ShowEncryptedSnippet(snippet.Data)
	}
}
