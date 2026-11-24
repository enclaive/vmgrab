package pod

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func cgroupPaths(data string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) == 3 {
			result[fields[0]+":"+fields[1]] = fields[2]
		}
	}
	return result
}

func containerCgroup(root, id string, pid int) (map[string]string, error) {
	if id == "" || pid <= 0 {
		return nil, fmt.Errorf("invalid container identity")
	}
	data, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return nil, err
	}
	selected := map[string]string{}
	for key, path := range cgroupPaths(string(data)) {
		for _, part := range strings.Split(path, "/") {
			if part == id || part == "crio-"+id+".scope" || part == "cri-containerd-"+id+".scope" {
				selected[key] = path
				break
			}
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("pid %d is not in a cgroup identifying container %s", pid, id)
	}
	return selected, nil
}

// cgroup membership includes exec-created and reparented processes that a
// traversal of PID 1's children would miss. Never fall back to a host/root cgroup.
func containerPIDs(root, id string, pid int) ([]int, error) {
	groups, err := containerCgroup(root, id, pid)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []int
	for _, entry := range entries {
		candidate, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name(), "cgroup"))
		if processGone(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("enumerate process %d: %w", candidate, err)
		}
		paths := cgroupPaths(string(data))
		for key, path := range groups {
			if paths[key] == path || strings.HasPrefix(paths[key], path+"/") {
				result = append(result, candidate)
				break
			}
		}
	}
	sort.Ints(result)
	if len(result) == 0 {
		return nil, fmt.Errorf("no processes remain in container %s", id)
	}
	return result, nil
}

// A process that exits mid-scan yields ENOENT on open or ESRCH on read.
func processGone(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, syscall.ESRCH)
}

func processStartTime(root string, pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	// comm is parenthesized and may itself contain spaces and parentheses.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("short process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
