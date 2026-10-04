package search

import (
	"github.com/enclaive/vmgrab/pkg/dumpmeta"
	"testing"
)

func TestAnalysisDoesNotInferEncryption(t *testing.T) {
	p := writeFixture(t, "input", []byte("plain-data"))
	for _, kind := range []string{"pod-runc", "pod-kata", ""} {
		m := &dumpmeta.Meta{Kind: kind, Size: 10, Security: "SEV-SNP"}
		if err := m.Write(p); err != nil {
			t.Fatal(err)
		}
		a, err := New(p, false).Analyze("missing", 5)
		if err != nil {
			t.Fatal(err)
		}
		if a.Status() != "NOT_FOUND" {
			t.Fatal(a.Status())
		}
		a, err = New(p, false).Analyze("plain-data", 5)
		if err != nil {
			t.Fatal(err)
		}
		if a.Status() != "MATCH_FOUND" {
			t.Fatal(a.Status())
		}
	}
}
func TestAnalysisIncompleteEvenWhenPatternFound(t *testing.T) {
	p := writeFixture(t, "input", []byte("marker00"))
	m := &dumpmeta.Meta{Size: 8, Capture: &dumpmeta.Capture{Complete: false, BytesRead: 6, BytesPadded: 2, Errors: []string{"read failed"}}}
	if err := m.Write(p); err != nil {
		t.Fatal(err)
	}
	a, err := New(p, false).Analyze("marker", 5)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status() != "MATCH_FOUND" || a.Check() == nil {
		t.Fatalf("analysis=%+v", a)
	}
	a, err = New(p, false).Analyze("absent", 5)
	if err != nil || a.Status() != "INCONCLUSIVE" {
		t.Fatalf("analysis=%+v err=%v", a, err)
	}
}
func TestAnalysisRejectsSizeMismatch(t *testing.T) {
	p := writeFixture(t, "input", []byte("marker"))
	m := &dumpmeta.Meta{Size: 100}
	if err := m.Write(p); err != nil {
		t.Fatal(err)
	}
	a, err := New(p, false).Analyze("marker", 5)
	if err != nil {
		t.Fatal(err)
	}
	if a.Check() == nil {
		t.Fatal("size mismatch ignored")
	}
}
func TestAnalysisDoesNotSearchPaddingOrJoinUnrelatedMappings(t *testing.T) {
	p := writeFixture(t, "input", []byte("ABCDEFmarker"))
	m := &dumpmeta.Meta{Size: 12, Containers: []dumpmeta.ContainerDump{{Processes: []dumpmeta.ProcessDump{{PID: 1, Regions: []dumpmeta.RegionDump{
		{Start: 100, End: 103, ByteStart: 0, ByteEnd: 3, BytesRead: 3},
		{Start: 200, End: 209, ByteStart: 3, ByteEnd: 12, BytesRead: 3},
	}}}}}}
	if err := m.Write(p); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"ABCDEF", "marker"} {
		a, err := New(p, false).Analyze(pattern, 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Scan.Matches) != 0 {
			t.Fatalf("synthetic match: %+v", a.Scan.Matches)
		}
	}
}
func TestAnalysisSearchesAdjacentMappings(t *testing.T) {
	p := writeFixture(t, "input", []byte("ABCDEF"))
	m := &dumpmeta.Meta{Size: 6, Containers: []dumpmeta.ContainerDump{{Processes: []dumpmeta.ProcessDump{{PID: 1, Regions: []dumpmeta.RegionDump{
		{Start: 100, End: 103, ByteStart: 0, ByteEnd: 3, BytesRead: 3},
		{Start: 103, End: 106, ByteStart: 3, ByteEnd: 6, BytesRead: 3},
	}}}}}}
	if err := m.Write(p); err != nil {
		t.Fatal(err)
	}
	a, err := New(p, false).Analyze("ABCDEF", 5)
	if err != nil || len(a.Scan.Matches) != 1 {
		t.Fatalf("analysis=%+v err=%v", a, err)
	}
}

func TestLegacyV2CaptureStillSearchesWholeFile(t *testing.T) {
	p := writeFixture(t, "input", []byte("marker"))
	m := &dumpmeta.Meta{Version: 2, Size: 6, Containers: []dumpmeta.ContainerDump{{Name: "legacy"}}}
	if err := m.Write(p); err != nil {
		t.Fatal(err)
	}
	a, err := New(p, false).Analyze("marker", 5)
	if err != nil || len(a.Scan.Matches) != 1 {
		t.Fatalf("analysis=%+v err=%v", a, err)
	}
}
func TestAnalysisRejectsUnaccountedBytes(t *testing.T) {
	p := writeFixture(t, "input", []byte("ABCDEF"))
	m := &dumpmeta.Meta{Size: 6, Containers: []dumpmeta.ContainerDump{{Processes: []dumpmeta.ProcessDump{{Regions: []dumpmeta.RegionDump{{Start: 100, End: 103, ByteStart: 0, ByteEnd: 3, BytesRead: 3}}}}}}}
	if err := m.Write(p); err != nil {
		t.Fatal(err)
	}
	if _, err := New(p, false).Analyze("DEF", 5); err == nil {
		t.Fatal("silently skipped unaccounted bytes")
	}
}
