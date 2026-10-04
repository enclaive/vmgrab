package cmd

import (
	"errors"
	"github.com/enclaive/vmgrab/pkg/dumpmeta"
	"github.com/enclaive/vmgrab/pkg/search"
	"testing"
)

func demoResult(matches int, security string) demoPhase {
	return demoPhase{Target: "target", Analysis: &search.Analysis{Scan: search.ScanResult{Matches: make([]search.Match, matches)}, Meta: &dumpmeta.Meta{Security: security, Capture: &dumpmeta.Capture{Complete: true}}}}
}
func TestDemoRequiresPositiveControlAndActualResults(t *testing.T) {
	cases := []struct {
		name                   string
		standard, confidential demoPhase
		wantError              bool
	}{
		{"observed contrast", demoResult(1, ""), demoResult(0, "SEV-SNP"), false},
		{"missing positive control", demoResult(0, ""), demoResult(0, "SEV-SNP"), true},
		{"readable confidential data", demoResult(1, ""), demoResult(1, "SEV-SNP"), true},
		{"CC not detected", demoResult(1, ""), demoResult(0, ""), true},
		{"wrong standard target", demoResult(1, "SEV-SNP"), demoResult(0, "SEV-SNP"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkDemo(tc.standard, tc.confidential); (err != nil) != tc.wantError {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
func TestDemoRejectsIncompleteCapture(t *testing.T) {
	standard, confidential := demoResult(1, ""), demoResult(0, "SEV-SNP")
	confidential.Analysis.Incomplete = []string{"read failed"}
	if checkDemo(standard, confidential) == nil {
		t.Fatal("partial capture passed")
	}
	confidential = demoResult(0, "SEV-SNP")
	confidential.Err = errors.New("dump failed")
	if checkDemo(standard, confidential) == nil {
		t.Fatal("capture error passed")
	}
	confidential = demoResult(0, "SEV-SNP")
	confidential.Analysis.Meta.Capture = nil
	if checkDemo(standard, confidential) == nil {
		t.Fatal("unknown coverage passed")
	}
}
