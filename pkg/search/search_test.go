package search

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestSearchPatterns_FoundAndMissing(t *testing.T) {
	body := make([]byte, 0, 4096)
	body = append(body, []byte("padding ")...)
	bannerOff := len(body)
	body = append(body, []byte("Linux version 6.8.0-110-generic ")...)
	swapperOff := len(body) + 3 // "..." prefix before swapper/0
	body = append(body, []byte("...swapper/0 task...")...)
	// __init_task and CONFIG_SEV_GUEST intentionally omitted
	for len(body) < 4096 {
		body = append(body, 0)
	}
	path := writeFixture(t, "fp.bin", body)

	patterns := []string{
		`Linux version [0-9]+\.[0-9]+\.[0-9]+`,
		`swapper/0`,
		`__init_task`,
		`CONFIG_SEV_GUEST`,
	}

	s := New(path, false)
	results, err := s.SearchPatterns(patterns)
	if err != nil {
		t.Fatalf("SearchPatterns: %v", err)
	}
	if len(results) != len(patterns) {
		t.Fatalf("got %d results, want %d", len(results), len(patterns))
	}

	if !results[0].Found || results[0].Offset != int64(bannerOff) {
		t.Errorf("Linux banner: found=%v offset=%d, want true %d", results[0].Found, results[0].Offset, bannerOff)
	}
	if !results[1].Found || results[1].Offset != int64(swapperOff) {
		t.Errorf("swapper/0: found=%v offset=%d, want true %d", results[1].Found, results[1].Offset, swapperOff)
	}
	if results[2].Found {
		t.Errorf("__init_task incorrectly reported found")
	}
	if results[3].Found {
		t.Errorf("CONFIG_SEV_GUEST incorrectly reported found")
	}
}

func TestSearchPatterns_BadRegex(t *testing.T) {
	path := writeFixture(t, "x.bin", []byte("anything"))
	s := New(path, false)
	if _, err := s.SearchPatterns([]string{"[unbalanced"}); err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

// makeVsockHeader builds a 44-byte virtio_vsock_hdr (LE) with the given fields.
// Unspecified fields are filled with zeros.
func makeVsockHeader(srcCID, dstCID uint64, msgLen uint32, msgType uint16) []byte {
	h := make([]byte, vsockHeaderSize)
	binary.LittleEndian.PutUint64(h[0:8], srcCID)
	binary.LittleEndian.PutUint64(h[8:16], dstCID)
	binary.LittleEndian.PutUint32(h[24:28], msgLen)
	binary.LittleEndian.PutUint16(h[28:30], msgType)
	return h
}

func TestLooksLikeVsockSharedBuffer_Positive(t *testing.T) {
	header := makeVsockHeader(2, 3, 64, 1) // host -> guest, STREAM, 64 bytes
	payload := []byte("GUEST_SECRET_MARKER=LIVE_SECRET_TWKX")
	body := append(header, payload...)
	path := writeFixture(t, "vsock_pos.bin", body)

	s := New(path, false)
	got, hex := s.LooksLikeVsockSharedBuffer(int64(vsockHeaderSize))
	if !got {
		t.Fatalf("LooksLikeVsockSharedBuffer = false, want true")
	}
	if hex == "" {
		t.Errorf("expected non-empty hex prefix")
	}
}

func TestLooksLikeVsockSharedBuffer_NegativeRandomBefore(t *testing.T) {
	bogus := make([]byte, vsockHeaderSize)
	for i := range bogus {
		bogus[i] = 0xAB
	}
	payload := []byte("MARKER")
	body := append(bogus, payload...)
	path := writeFixture(t, "vsock_neg.bin", body)

	s := New(path, false)
	got, _ := s.LooksLikeVsockSharedBuffer(int64(vsockHeaderSize))
	if got {
		t.Fatalf("LooksLikeVsockSharedBuffer = true, want false on random prefix")
	}
}

func TestLooksLikeVsockSharedBuffer_NegativeWrongType(t *testing.T) {
	header := makeVsockHeader(2, 3, 64, 2) // type=2 (DGRAM)
	payload := []byte("MARKER")
	body := append(header, payload...)
	path := writeFixture(t, "vsock_dgram.bin", body)

	s := New(path, false)
	got, _ := s.LooksLikeVsockSharedBuffer(int64(vsockHeaderSize))
	if got {
		t.Fatalf("LooksLikeVsockSharedBuffer = true for type=DGRAM, want false")
	}
}

func TestLooksLikeVsockSharedBuffer_NegativeZeroLen(t *testing.T) {
	header := makeVsockHeader(2, 3, 0, 1) // len=0
	payload := []byte("MARKER")
	body := append(header, payload...)
	path := writeFixture(t, "vsock_zerolen.bin", body)

	s := New(path, false)
	got, _ := s.LooksLikeVsockSharedBuffer(int64(vsockHeaderSize))
	if got {
		t.Fatalf("LooksLikeVsockSharedBuffer = true for len=0, want false")
	}
}

func TestLooksLikeVsockSharedBuffer_OffsetTooSmall(t *testing.T) {
	path := writeFixture(t, "small.bin", []byte("MARKER"))
	s := New(path, false)
	got, _ := s.LooksLikeVsockSharedBuffer(0)
	if got {
		t.Fatalf("LooksLikeVsockSharedBuffer = true at offset 0, want false")
	}
}

// makeEncryptedLikeDump returns a buffer that mimics how SEV-SNP guest memory
// appears to the host: mostly zero pages with a small fraction of random /
// shared-memory bytes near the edges. No Linux banner.
func makeEncryptedLikeDump(t *testing.T, totalBytes, nonZeroBytes int) []byte {
	t.Helper()
	buf := make([]byte, totalBytes)
	for i := 0; i < nonZeroBytes; i++ {
		buf[i*7%totalBytes] = byte(0x80 | (i & 0x7f)) // non-zero, non-printable
	}
	return buf
}

func TestClassifyDump_Encrypted(t *testing.T) {
	// ~99% zeros, no banner, sized above the budget so sampling kicks in.
	buf := makeEncryptedLikeDump(t, 1<<20, 1024)
	path := writeFixture(t, "snp.dump", buf)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Verdict != VerdictEncrypted {
		t.Errorf("Verdict = %q, want %q (zeros=%.2f printable=%.2f sampled=%d)",
			c.Verdict, VerdictEncrypted, c.ZeroRatio, c.PrintableRatio, c.SampledBytes)
	}
	if c.HasLinuxBanner {
		t.Errorf("HasLinuxBanner = true, want false")
	}
}

func TestClassifyDump_UnencryptedProcess(t *testing.T) {
	// Process dump: ~50% printable ASCII (heap with strings), no banner.
	buf := make([]byte, 1<<20)
	text := []byte("mongodb_secret_value_abcdefghij ")
	for i := 0; i+len(text) < len(buf); i += 2 * len(text) {
		copy(buf[i:], text)
	}
	path := writeFixture(t, "proc.dump", buf)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Verdict != VerdictUnencryptedProcess {
		t.Errorf("Verdict = %q, want %q (zeros=%.2f printable=%.2f)",
			c.Verdict, VerdictUnencryptedProcess, c.ZeroRatio, c.PrintableRatio)
	}
}

func TestClassifyDump_UnencryptedVM(t *testing.T) {
	// VM dump signature: zeros + Linux banner anywhere in the file.
	buf := make([]byte, 1<<20)
	copy(buf[2048:], []byte("Linux version 6.8.0-110-generic blah blah"))
	path := writeFixture(t, "vm.dump", buf)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Verdict != VerdictUnencryptedVM {
		t.Errorf("Verdict = %q, want %q", c.Verdict, VerdictUnencryptedVM)
	}
	if !c.HasLinuxBanner {
		t.Errorf("HasLinuxBanner = false, want true")
	}
}

func TestClassifyDump_AmbiguousSmall(t *testing.T) {
	// Tiny dump below the min sample size. No banner, mixed bytes.
	buf := []byte{0, 0, 0, 0, 1, 2, 3, 4, 0, 0}
	path := writeFixture(t, "tiny.dump", buf)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Verdict != VerdictAmbiguous {
		t.Errorf("Verdict = %q, want %q", c.Verdict, VerdictAmbiguous)
	}
}

// TestClassifyDump_RuncFalsePositiveRegression reproduces a reported field
// scenario: a small runc process dump (~436 KiB) that has no Linux banner.
// Under the old banner-only logic this was misclassified as SEV-SNP. The new
// classifier must not return VerdictEncrypted here.
func TestClassifyDump_RuncFalsePositiveRegression(t *testing.T) {
	buf := make([]byte, 436*1024)
	heap := []byte("PID_CONFIG=/etc/foo bar=baz mongodb_cache_entry abcdef0123 ")
	for i := 0; i+len(heap) < len(buf); i += 64 {
		copy(buf[i:], heap)
	}
	path := writeFixture(t, "runc.dump", buf)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Verdict == VerdictEncrypted {
		t.Errorf("runc process dump misclassified as Encrypted (regression): zeros=%.2f printable=%.2f",
			c.ZeroRatio, c.PrintableRatio)
	}
}

// TestClassifyDump_LiveRuncProfile reproduces a byte profile measured on a
// real runc container dump: ~93% zeros and ~3% printable. With the old thresholds this got Encrypted -> false-positive
// tamper warning. Must classify as UnencryptedProcess.
func TestClassifyDump_LiveRuncProfile(t *testing.T) {
	const size = 436 * 1024
	const printableTarget = size * 3 / 100
	buf := make([]byte, size)
	text := []byte("config_value=abc ")
	written := 0
	for i := 0; written < printableTarget && i+len(text) < size; i += 384 {
		copy(buf[i:], text)
		written += len(text)
	}
	path := writeFixture(t, "runc_live.dump", buf)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Verdict != VerdictUnencryptedProcess {
		t.Errorf("Verdict = %q, want %q (zeros=%.2f printable=%.2f)",
			c.Verdict, VerdictUnencryptedProcess, c.ZeroRatio, c.PrintableRatio)
	}
}

// TestClassifyDump_SparsePlainVM reproduces a measured scenario: a large
// guest-RAM dump of a plain (unencrypted) VM whose resident set is tiny and
// concentrated in the low addresses, so the file is ~99% zeros with readable
// strings only near the start and the entire middle empty. Middle-of-file
// sampling read all zeros and wrongly returned Encrypted; the whole-file string
// scan must classify it as readable (not Encrypted).
func TestClassifyDump_SparsePlainVM(t *testing.T) {
	const size = 8 << 20 // 8 MiB stand-in for the multi-GB sparse region
	buf := make([]byte, size)
	// Readable content (GRUB/config-like) only in the first ~64 KiB; the rest,
	// including the entire middle that sampling would hit, stays zero.
	text := []byte("menuentry 'Debian GNU/Linux' root=PARTUUID=ee7feeef ro console=ttyS0 ")
	for i := 0; i < 64*1024; i += 128 {
		copy(buf[i:], text)
	}
	path := writeFixture(t, "sparse_plain_vm.dump", buf)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Verdict == VerdictEncrypted {
		t.Errorf("sparse plain-VM dump misclassified as Encrypted (regression): zeros=%.4f strings=%d",
			c.ZeroRatio, c.ReadableRuns)
	}
	if c.ReadableRuns < classifyReadableRunsMin {
		t.Errorf("ReadableRuns = %d, want >= %d", c.ReadableRuns, classifyReadableRunsMin)
	}
}

// --- ELF-core (QEMU dump-guest-memory) classification, issue #8 ---

type coreSeg struct {
	ptype uint32
	data  []byte
}

const (
	ptLoad = 1
	ptNote = 4
)

// buildELFCore assembles a minimal ELF64 little-endian core file with the given
// program segments, laid out as: ELF header, program headers, then segment data
// in order. It is enough for debug/elf.NewFile to enumerate PT_LOAD ranges.
func buildELFCore(t *testing.T, segs []coreSeg) []byte {
	t.Helper()
	const ehdrSize = 64
	const phEntry = 56
	n := len(segs)
	dataStart := ehdrSize + phEntry*n

	var body bytes.Buffer
	offsets := make([]int, n)
	off := dataStart
	for i, s := range segs {
		offsets[i] = off
		body.Write(s.data)
		off += len(s.data)
	}

	var b bytes.Buffer
	// e_ident
	b.Write([]byte("\x7fELF"))
	b.WriteByte(2) // ELFCLASS64
	b.WriteByte(1) // ELFDATA2LSB
	b.WriteByte(1) // EI_VERSION
	b.Write(make([]byte, 9))
	le := binary.LittleEndian
	w16 := func(v uint16) { tmp := make([]byte, 2); le.PutUint16(tmp, v); b.Write(tmp) }
	w32 := func(v uint32) { tmp := make([]byte, 4); le.PutUint32(tmp, v); b.Write(tmp) }
	w64 := func(v uint64) { tmp := make([]byte, 8); le.PutUint64(tmp, v); b.Write(tmp) }
	w16(4)  // e_type = ET_CORE
	w16(62) // e_machine = EM_X86_64
	w32(1)  // e_version
	w64(0)  // e_entry
	w64(ehdrSize) // e_phoff
	w64(0)  // e_shoff
	w32(0)  // e_flags
	w16(ehdrSize) // e_ehsize
	w16(phEntry)  // e_phentsize
	w16(uint16(n)) // e_phnum
	w16(0) // e_shentsize
	w16(0) // e_shnum
	w16(0) // e_shstrndx

	for i, s := range segs {
		w32(s.ptype)                 // p_type
		w32(4)                       // p_flags (R)
		w64(uint64(offsets[i]))      // p_offset
		w64(0x1000 * uint64(i+1))    // p_vaddr
		w64(0x1000 * uint64(i+1))    // p_paddr
		w64(uint64(len(s.data)))     // p_filesz
		w64(uint64(len(s.data)))     // p_memsz
		w64(1)                       // p_align
	}
	b.Write(body.Bytes())
	return b.Bytes()
}

func readableBlob(n int) []byte {
	txt := []byte("root@localhost app.go config.yaml GET /api/store HTTP/1.1 Content-Type ")
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, txt...)
	}
	return out[:n]
}

// TestClassifyDump_ELFCore_SNP reproduces issue #8 case 2: a QEMU core dump of
// an SEV-SNP guest. The ELF/core metadata (PT_NOTE) is readable, but the guest
// PT_LOAD segments read back as zeros. Scanning the whole file would count the
// metadata strings and wrongly return READABLE; scanning only PT_LOAD must give
// Encrypted with IsELFCore set.
func TestClassifyDump_ELFCore_SNP(t *testing.T) {
	note := readableBlob(8 << 10)       // 8 KiB readable metadata
	load := make([]byte, 512<<10)       // 512 KiB zeroed guest memory
	data := buildELFCore(t, []coreSeg{{ptNote, note}, {ptLoad, load}})
	path := writeFixture(t, "snp_core.dump", data)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if !c.IsELFCore {
		t.Fatalf("IsELFCore = false, want true")
	}
	if c.Verdict != VerdictVMCoreNoBanner {
		t.Errorf("Verdict = %q, want %q (readable ELF metadata leaked into scan?): strings=%d zeros=%.4f",
			c.Verdict, VerdictVMCoreNoBanner, c.ReadableRuns, c.ZeroRatio)
	}
	if c.ReadableRuns != 0 {
		t.Errorf("ReadableRuns = %d over PT_LOAD, want 0", c.ReadableRuns)
	}
}

// TestClassifyDump_ELFCore_PlainVM is the contrast: a QEMU core dump of a plain
// VM whose PT_LOAD segment carries the kernel banner and readable strings. It
// must NOT be classified as encrypted.
func TestClassifyDump_ELFCore_PlainVM(t *testing.T) {
	note := readableBlob(8 << 10)
	load := make([]byte, 512<<10)
	copy(load, []byte("Linux version 6.17.0-0.rc7.56.fc43.x86_64 (mockbuild@) "))
	copy(load[4096:], readableBlob(256<<10))
	data := buildELFCore(t, []coreSeg{{ptNote, note}, {ptLoad, load}})
	path := writeFixture(t, "plain_core.dump", data)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if !c.IsELFCore {
		t.Fatalf("IsELFCore = false, want true")
	}
	if c.Verdict == VerdictEncrypted {
		t.Errorf("plain-VM core misclassified as Encrypted: strings=%d banner=%v", c.ReadableRuns, c.HasLinuxBanner)
	}
	if !c.HasLinuxBanner {
		t.Errorf("HasLinuxBanner = false, want true")
	}
}

// TestClassifyDump_ELFCore_SharedIOPlaintext reproduces a measured finding on a
// real SEV-SNP guest: a core dump whose PT_LOAD segments contain real plaintext
// (HTTP headers from shared virtio/DMA buffers, which SEV-SNP does not encrypt)
// but no guest kernel banner. Counting printable runs classified this as
// "READABLE DUMP — encryption is not active here" (issue #8). It must instead
// defer to the kernel-fingerprint probe via VerdictVMCoreNoBanner.
func TestClassifyDump_ELFCore_SharedIOPlaintext(t *testing.T) {
	note := readableBlob(8 << 10)
	load := make([]byte, 1<<20)
	// Shared I/O buffer content: real, long, readable strings, no kernel banner.
	http := []byte("Content-Type: application/soap+xml, application/xml, text/xml;q=0.9, */*;q=0.1\r\n")
	for i := 0; i+len(http) < 256<<10; i += 512 {
		copy(load[i:], http)
	}
	data := buildELFCore(t, []coreSeg{{ptNote, note}, {ptLoad, load}})
	path := writeFixture(t, "snp_shared_io.dump", data)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.HasLinuxBanner {
		t.Fatalf("fixture must not contain a kernel banner")
	}
	if c.Verdict == VerdictUnencryptedProcess {
		t.Errorf("shared-I/O plaintext in a VM core misclassified as %q (issue #8 regression); strings=%d",
			c.Verdict, c.ReadableRuns)
	}
	if c.Verdict != VerdictVMCoreNoBanner {
		t.Errorf("Verdict = %q, want %q", c.Verdict, VerdictVMCoreNoBanner)
	}
	if c.ReadableRuns == 0 {
		t.Errorf("fixture should contain readable runs, got 0")
	}
}

// TestClassifyDump_ELFCore_UnprotectedAtBootloader pins down what content alone
// can and cannot prove. An UNPROTECTED VM sitting in its bootloader has fully
// readable guest memory, yet carries no kernel banner and no kernel structures,
// exactly like a protected guest. The classifier must therefore return
// VerdictVMCoreNoBanner and must NOT return an "encrypted" verdict: deciding
// between the two requires the confidential-computing status recorded in the
// dump's metadata sidecar, not byte statistics.
func TestClassifyDump_ELFCore_UnprotectedAtBootloader(t *testing.T) {
	note := readableBlob(8 << 10)
	load := make([]byte, 4<<20)
	grub := []byte("GNU GRUB version 2.06  menuentry 'Debian GNU/Linux' set root='hd0,gpt2' linux /vmlinuz ro quiet ")
	for i := 0; i+len(grub) < (1 << 20); i += 128 {
		copy(load[i:], grub)
	}
	data := buildELFCore(t, []coreSeg{{ptNote, note}, {ptLoad, load}})
	path := writeFixture(t, "plain_at_grub.dump", data)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.HasLinuxBanner {
		t.Fatalf("fixture must not contain a kernel banner")
	}
	if c.Verdict == VerdictEncrypted {
		t.Errorf("unprotected VM in bootloader classified as %q; content cannot prove encryption", c.Verdict)
	}
	if c.Verdict != VerdictVMCoreNoBanner {
		t.Errorf("Verdict = %q, want %q", c.Verdict, VerdictVMCoreNoBanner)
	}
}

// TestClassifyDump_ELFCore_Truncated covers the artifact left behind by the
// dump-completion bug in issue #8: a core file whose program headers describe
// more guest memory than the file actually contains. A "not found" result on
// such a dump is meaningless, so the classifier must flag it.
func TestClassifyDump_ELFCore_Truncated(t *testing.T) {
	note := readableBlob(8 << 10)
	load := make([]byte, 1<<20)
	data := buildELFCore(t, []coreSeg{{ptNote, note}, {ptLoad, load}})
	cut := data[:len(data)/3] // interrupted mid-write
	path := writeFixture(t, "truncated.dump", cut)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump on a truncated file must not error: %v", err)
	}
	if !c.Truncated {
		t.Errorf("Truncated = false, want true (declared %d bytes, file %d)", c.DeclaredBytes, c.FileSize)
	}
	if c.DeclaredBytes <= c.FileSize {
		t.Errorf("DeclaredBytes %d should exceed FileSize %d", c.DeclaredBytes, c.FileSize)
	}
}

// TestClassifyDump_ELFCore_NotTruncated guards the opposite direction: an
// intact core file must never be flagged as truncated.
func TestClassifyDump_ELFCore_NotTruncated(t *testing.T) {
	note := readableBlob(8 << 10)
	load := make([]byte, 1<<20)
	data := buildELFCore(t, []coreSeg{{ptNote, note}, {ptLoad, load}})
	path := writeFixture(t, "intact.dump", data)
	s := New(path, false)

	c, err := s.ClassifyDump()
	if err != nil {
		t.Fatalf("ClassifyDump: %v", err)
	}
	if c.Truncated {
		t.Errorf("intact core flagged as truncated (declared %d, file %d)", c.DeclaredBytes, c.FileSize)
	}
}
