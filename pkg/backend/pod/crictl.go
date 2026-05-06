package pod

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// podListItem is the subset of `crictl pods -o json` fields we consume.
type podListItem struct {
	ID       string `json:"id"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	State          string            `json:"state"`
	RuntimeHandler string            `json:"runtimeHandler"`
	Annotations    map[string]string `json:"annotations"`
}

type podList struct {
	Items []podListItem `json:"items"`
}

type containerItem struct {
	ID       string `json:"id"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	State string `json:"state"`
}

type containerList struct {
	Containers []containerItem `json:"containers"`
}

// containerInspect is the subset of `crictl inspect <cid> -o json` we consume.
type containerInspect struct {
	Info struct {
		PID int `json:"pid"`
	} `json:"info"`
}

// podInspect is the subset of `crictl inspectp <pod> -o json` we consume.
//
// Where to find RuntimeHandler:
//   - status.runtimeHandler        — containerd (standard CRI field)
//   - info.runtimeSpec.annotations["io.kubernetes.cri-o.RuntimeHandler"]
//                                   — CRI-O (OpenShift). The top-level
//                                   `runtimeHandler` from `crictl pods` is
//                                   empty on live OCP even for Kata pods.
//
// Where to find the Kata sandbox PID / id:
//   - info.pid                     — usually the Kata shim on containerd, but
//                                   on OpenShift CRI-O + Enclaive Kata this
//                                   is already the QEMU host PID (verified on
//                                   RHCOS 9.6 + kata-enclaive 2026-04). We
//                                   still verify by inspecting cmdline before
//                                   trusting it.
//   - info.runtimeSpec.annotations["io.katacontainers.pkg.oci.sandbox_id"]
//                                   — set by upstream Kata; Enclaive variant
//                                   does NOT set it. Use CRI pod ID as a
//                                   fallback match string (QEMU cmdline
//                                   always contains `-name sandbox-<podID>`).
type podInspect struct {
	Status struct {
		RuntimeHandler string `json:"runtimeHandler"`
	} `json:"status"`
	Info struct {
		PID         int    `json:"pid"`
		SandboxID   string `json:"sandboxId"`
		RuntimeSpec struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

// runCrictl invokes crictl with the given args and returns stdout.
// All our calls are read-only (pods/ps/inspect/inspectp).
func runCrictl(args ...string) ([]byte, error) {
	out, err := exec.Command("crictl", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("crictl %v: %s", args, string(ee.Stderr))
		}
		return nil, fmt.Errorf("crictl %v: %w", args, err)
	}
	return out, nil
}

// listPods returns every sandbox in SANDBOX_READY state.
func listPods() ([]podListItem, error) {
	out, err := runCrictl("pods", "-o", "json")
	if err != nil {
		return nil, err
	}
	var pl podList
	if err := json.Unmarshal(out, &pl); err != nil {
		return nil, fmt.Errorf("parse crictl pods: %w", err)
	}
	ready := pl.Items[:0]
	for _, p := range pl.Items {
		if p.State == "SANDBOX_READY" {
			ready = append(ready, p)
		}
	}
	return ready, nil
}

// firstRunningContainer returns the first CONTAINER_RUNNING container in the
// given pod sandbox, plus a count of running containers (for a verbose warning
// when > 1).
func firstRunningContainer(podID string) (*containerItem, int, error) {
	out, err := runCrictl("ps", "--pod", podID, "-o", "json")
	if err != nil {
		return nil, 0, err
	}
	var cl containerList
	if err := json.Unmarshal(out, &cl); err != nil {
		return nil, 0, fmt.Errorf("parse crictl ps: %w", err)
	}
	running := 0
	var first *containerItem
	for i := range cl.Containers {
		if cl.Containers[i].State == "CONTAINER_RUNNING" {
			running++
			if first == nil {
				first = &cl.Containers[i]
			}
		}
	}
	return first, running, nil
}

// containerPID returns the host PID of the given container's main process.
// Note: `crictl inspect` and `inspectp` default to JSON output and treat
// any extra positional arg as another ID — so DO NOT pass `-o json` here,
// older/newer CRI-O crictl versions reject it.
func containerPID(containerID string) (int, error) {
	out, err := runCrictl("inspect", containerID)
	if err != nil {
		return 0, err
	}
	var ci containerInspect
	if err := json.Unmarshal(out, &ci); err != nil {
		return 0, fmt.Errorf("parse crictl inspect: %w", err)
	}
	if ci.Info.PID == 0 {
		return 0, fmt.Errorf("container %s has no host pid (likely Kata)", containerID)
	}
	return ci.Info.PID, nil
}

// inspectPod returns the parsed inspectp JSON for the given sandbox.
func inspectPod(podID string) (*podInspect, error) {
	out, err := runCrictl("inspectp", podID)
	if err != nil {
		return nil, err
	}
	var pi podInspect
	if err := json.Unmarshal(out, &pi); err != nil {
		return nil, fmt.Errorf("parse crictl inspectp: %w", err)
	}
	return &pi, nil
}

// runtimeHandler extracts the RuntimeHandler name from the two places CRI
// implementations put it. Order matters: CRI-O's annotation is authoritative
// on OCP (status.runtimeHandler is empty there).
func (pi *podInspect) runtimeHandler() string {
	if h := pi.Info.RuntimeSpec.Annotations["io.kubernetes.cri-o.RuntimeHandler"]; h != "" {
		return h
	}
	return pi.Status.RuntimeHandler
}

// sandboxHint returns a string guaranteed to appear in the Kata QEMU cmdline
// for this pod: either the dedicated Kata sandbox_id annotation (upstream
// Kata) or the CRI pod ID itself (which QEMU embeds as `-name sandbox-<id>`
// — used by Enclaive Kata where the annotation is absent).
func (pi *podInspect) sandboxHint(fallbackPodID string) string {
	if id := pi.Info.RuntimeSpec.Annotations["io.katacontainers.pkg.oci.sandbox_id"]; id != "" {
		return id
	}
	if pi.Info.SandboxID != "" {
		return pi.Info.SandboxID
	}
	return fallbackPodID
}
