package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/enclaive/vmgrab/pkg/backend"
	"github.com/enclaive/vmgrab/pkg/dumpmeta"
)

func memoryProtection(kind, security string) string {
	if security != "" {
		return security + " configured"
	}
	if kind == "pod-runc" {
		return "Host kernel (no SEV/TDX VM)"
	}
	if kind == "pod-unknown" {
		return "Unknown (target unresolved)"
	}
	return "Not detected in VM configuration"
}

func targetBackend(target string, verbose bool) (backend.Backend, error) {
	if backendName != "" {
		b := backend.Get(backendName, verbose)
		if b == nil || !b.Available() {
			return nil, fmt.Errorf("backend unavailable: %s", backendName)
		}
		return b, nil
	}
	if strings.Contains(target, "/") {
		b := backend.Get("pod", verbose)
		if b == nil || !b.Available() {
			return nil, fmt.Errorf("pod backend requires access to the node CRI endpoint through crictl")
		}
		return b, nil
	}
	b, vm := backend.FindVM(target, verbose)
	if b == nil || vm == nil {
		return nil, fmt.Errorf("target not found: %s", target)
	}
	return b, nil
}

func cleanupCapture(path string) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Cleanup %s: %v\n", path, err)
	}
	if err := dumpmeta.Remove(path); err != nil {
		fmt.Fprintf(os.Stderr, "Cleanup metadata: %v\n", err)
	}
}
