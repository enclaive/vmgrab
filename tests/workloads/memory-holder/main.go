// memory-holder keeps synthetic confidential data resident without printing it.
// Build: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/memory-holder ./tests/workloads/memory-holder
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		panic(err)
	}
	record := []byte("VMGRAB_DEMO_RECORD|id=" + hex.EncodeToString(token) + "|name=Demo Patient|diagnosis=SYNTHETIC_ONLY|END\n")
	memory := make([]byte, 64*1024)
	for i := 0; i+len(record) <= len(memory); i += len(record) {
		copy(memory[i:], record)
	}
	lockErr := unix.Mlock(memory)
	digest := sha256.Sum256(memory)
	ready := map[string]any{"event": "ready", "pid": os.Getpid(), "bytes": len(memory), "sha256": fmt.Sprintf("%x", digest), "mlock": lockErr == nil, "synthetic": true}
	if lockErr != nil {
		ready["mlock_error"] = lockErr.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		panic(err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if sha256.Sum256(memory) != digest {
				fmt.Fprintln(os.Stderr, "memory integrity check failed")
				os.Exit(1)
			}
			runtime.KeepAlive(memory)
		case <-stop:
			if lockErr == nil {
				_ = unix.Munlock(memory)
			}
			return
		}
	}
}
