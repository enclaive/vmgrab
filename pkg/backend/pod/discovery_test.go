package pod

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fakeProcess(t *testing.T, root string, pid int, exe, cgroup string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0600); err != nil {
		t.Fatal(err)
	}
	fields := []string{"S"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, "1234")
	os.WriteFile(filepath.Join(dir, "stat"), []byte(fmt.Sprintf("%d (test (worker)) %s", pid, strings.Join(fields, " "))), 0600)
	os.WriteFile(filepath.Join(dir, "comm"), []byte("worker\n"), 0600)
}
func fakeCRI(t *testing.T, podPID, containerPID int, handler string) {
	t.Helper()
	dir := t.TempDir()
	pi := map[string]any{"info": map[string]any{"pid": podPID, "runtimeSpec": map[string]any{"annotations": map[string]string{"io.kubernetes.cri-o.RuntimeHandler": handler}}}}
	data, _ := json.Marshal(pi)
	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\ninfo) echo '{}' ;;\npods) echo '{\"items\":[{\"id\":\"sandbox\",\"metadata\":{\"name\":\"app\",\"namespace\":\"ns\"},\"state\":\"SANDBOX_READY\"}]}' ;;\ninspectp) printf '%%s\\n' '%s' ;;\nps) echo '{\"containers\":[{\"id\":\"cid\",\"metadata\":{\"name\":\"app\"},\"state\":\"CONTAINER_RUNNING\"}]}' ;;\ninspect) echo '{\"info\":{\"pid\":%d}}' ;;\n*) exit 1 ;;\nesac\n", data, containerPID)
	if err := os.WriteFile(filepath.Join(dir, "crictl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}
func TestClassifyUsesProcessesNotHandlerNames(t *testing.T) {
	for _, tc := range []struct {
		name, exe, handler, want string
		vm                       bool
	}{
		{"vendor QEMU", "/opt/vendor/qemu-system-x86_64", "arbitrary-name", "pod-kata", false},
		{"RHEL QEMU", "/usr/libexec/qemu-kvm", "arbitrary-name", "pod-kata", false},
		{"misleading handler", "/usr/bin/app", "kata-named-not-a-vm", "pod-runc", false},
		{"vm missing QEMU", "/usr/bin/app", "arbitrary-name", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			fakeProcess(t, root, 42, tc.exe, "0::/kubepods/crio-cid.scope\n")
			fakeCRI(t, 42, 42, tc.handler)
			p := podListItem{ID: "sandbox"}
			pi, err := inspectPod("sandbox")
			if err != nil {
				t.Fatal(err)
			}
			b := New(false)
			b.procRoot = root
			got, _, err := b.classify(p, pi, sandboxInventory{qemu: map[string][]int{}, vmRuntimes: map[string]bool{tc.handler: tc.vm}})
			if tc.want == "" {
				if err == nil {
					t.Fatal("VM mismatch silently became runc")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got=%s err=%v", got, err)
			}
		})
	}
}
func TestQEMUBinaryIdentity(t *testing.T) {
	for _, name := range []string{"/bin/sh", "/usr/bin/echo qemu-system-x86_64", "/tmp/not-qemu-kvm"} {
		if isQEMUExecutable(name) {
			t.Fatalf("false QEMU: %s", name)
		}
	}
}
func TestRuntimeConfig(t *testing.T) {
	got := parseVMRuntimes("[crio.runtime.runtimes.any-vendor]\nruntime_type = \"vm\"\n[crio.runtime.runtimes.runc]\nruntime_type = \"oci\"\n")
	if !got["any-vendor"] || got["runc"] {
		t.Fatal(got)
	}
}
func TestCgroupIncludesExecAndNestedProcesses(t *testing.T) {
	root := t.TempDir()
	fakeProcess(t, root, 10, "/bin/app", "0::/kubepods/crio-cid.scope\n")
	fakeProcess(t, root, 11, "/bin/exec-worker", "0::/kubepods/crio-cid.scope\n")
	fakeProcess(t, root, 12, "/bin/worker", "0::/kubepods/crio-cid.scope/child\n")
	fakeProcess(t, root, 13, "/bin/other", "0::/kubepods/crio-cid.scope-other\n")
	fakeProcess(t, root, 14, "/bin/host", "0::/\n")
	got, err := containerPIDs(root, "cid", 10)
	if err != nil || !reflect.DeepEqual(got, []int{10, 11, 12}) {
		t.Fatalf("got=%v err=%v", got, err)
	}
	if _, err := containerPIDs(root, "cid", 14); err == nil {
		t.Fatal("accepted host root cgroup")
	}
	start, err := processStartTime(root, 10)
	if err != nil || start != 1234 {
		t.Fatalf("start=%d err=%v", start, err)
	}
}
func TestCgroupV1(t *testing.T) {
	root := t.TempDir()
	fakeProcess(t, root, 10, "/bin/app", "2:cpu,cpuacct:/kubepods/cid\n3:memory:/kubepods/cid\n")
	got, err := containerPIDs(root, "cid", 10)
	if err != nil || !reflect.DeepEqual(got, []int{10}) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
func TestAmbiguousPod(t *testing.T) {
	pods := make([]podListItem, 2)
	for i := range pods {
		pods[i].Metadata.Name = "app"
		pods[i].Metadata.Namespace = fmt.Sprint(i)
	}
	if _, err := selectPod(pods, "app"); err == nil {
		t.Fatal("ambiguous name accepted")
	}
	if p, err := selectPod(pods, "1/app"); err != nil || p.Metadata.Namespace != "1" {
		t.Fatalf("p=%v err=%v", p, err)
	}
}

func TestFindInspectsOnlyRequestedSandbox(t *testing.T) {
	root := t.TempDir()
	fakeProcess(t, root, 42, "/opt/vendor/qemu-system-x86_64", "")
	fakeCRI(t, 42, 42, "arbitrary-runtime")
	cri := filepath.Join(strings.Split(os.Getenv("PATH"), ":")[0], "crictl")
	data, err := os.ReadFile(cri)
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "cri-calls")
	script := strings.Replace(string(data), "#!/bin/sh\n", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+log+"'\n", 1)
	script = strings.Replace(script, `"items":[`, `"items":[{"id":"stale","metadata":{"name":"broken","namespace":"other"},"state":"SANDBOX_READY"},`, 1)
	if err := os.WriteFile(cri, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	b := New(false)
	b.procRoot = root
	vm, err := b.Find("ns/app")
	if err != nil || vm == nil || vm.PID != 42 || vm.Kind != "pod-kata" {
		t.Fatalf("vm=%+v err=%v", vm, err)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "stale") || !strings.Contains(string(calls), "inspectp sandbox") {
		t.Fatalf("unexpected CRI calls: %s", calls)
	}
}
