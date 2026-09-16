package qemu

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestQMPAwaitReply_SkipsEventBeforeReply reproduces the root cause of issue #8
// case 1. QMP delivers an asynchronous "STOP" event as the guest pauses for the
// dump, and it arrives BEFORE the dump-guest-memory reply. The old code did a
// single Read and treated that event as the reply, returning "success" while
// QEMU was still writing the file. qmpAwaitReply must skip the event and the
// greeting and return only the reply whose id matches.
func TestQMPAwaitReply_SkipsEventBeforeReply(t *testing.T) {
	stream := strings.Join([]string{
		`{"QMP": {"version": {}, "capabilities": []}}`,
		`{"timestamp": {"seconds": 1}, "event": "STOP"}`,
		`{"return": {}, "id": "dump"}`,
		`{"timestamp": {"seconds": 2}, "event": "RESUME"}`,
	}, "\n") + "\n"

	b := &Backend{}
	r := bufio.NewReader(strings.NewReader(stream))

	// Consume the greeting exactly as dumpViaQMP does.
	if _, err := r.ReadBytes('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	msg, err := b.qmpAwaitReply(r, "dump")
	if err != nil {
		t.Fatalf("qmpAwaitReply returned error: %v", err)
	}
	if _, ok := msg["return"]; !ok {
		t.Fatalf("expected a return reply, got %v", msg)
	}
	if id, _ := msg["id"].(string); id != "dump" {
		t.Fatalf("matched wrong id %q, want dump", id)
	}
}

// TestQMPAwaitReply_IgnoresOtherIDs ensures a reply for a different command
// (e.g. the capabilities reply arriving late) is not mistaken for ours.
func TestQMPAwaitReply_IgnoresOtherIDs(t *testing.T) {
	stream := `{"return": {}, "id": "caps"}` + "\n" +
		`{"event": "NIC_RX_FILTER_CHANGED"}` + "\n" +
		`{"return": {}, "id": "dump"}` + "\n"

	b := &Backend{}
	r := bufio.NewReader(strings.NewReader(stream))
	msg, err := b.qmpAwaitReply(r, "dump")
	if err != nil {
		t.Fatalf("qmpAwaitReply: %v", err)
	}
	if id, _ := msg["id"].(string); id != "dump" {
		t.Fatalf("matched id %q, want dump", id)
	}
}

// TestQMPAwaitReply_SurfacesError checks a QMP error reply becomes a Go error.
func TestQMPAwaitReply_SurfacesError(t *testing.T) {
	stream := `{"event": "STOP"}` + "\n" +
		`{"error": {"class": "GenericError", "desc": "dump already in progress"}, "id": "dump"}` + "\n"

	b := &Backend{}
	r := bufio.NewReader(strings.NewReader(stream))
	if _, err := b.qmpAwaitReply(r, "dump"); err == nil {
		t.Fatal("expected error from QMP error reply, got nil")
	}
}

// TestWaitFileStable_ReturnsWhenStable checks the happy path: a fully written
// file whose size does not change is reported stable.
func TestWaitFileStable_ReturnsWhenStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump")
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	start := time.Now()
	if err := waitFileStable(path, false); err != nil {
		t.Fatalf("waitFileStable: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("waitFileStable took too long on a stable file")
	}
}

// TestWaitFileStable_WaitsForGrowingFile confirms that a file still being
// written is not reported stable until writing stops.
func TestWaitFileStable_WaitsForGrowingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 4; i++ {
			data := make([]byte, 1<<20)
			appendFile(t, path, data)
			time.Sleep(250 * time.Millisecond)
		}
	}()

	if err := waitFileStable(path, false); err != nil {
		t.Fatalf("waitFileStable: %v", err)
	}
	<-done
	// After stability is reported, the writer goroutine must have finished, so
	// the final size is the full 4 MiB.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 4<<20 {
		t.Fatalf("reported stable at %d bytes before writes finished (want %d)", info.Size(), 4<<20)
	}
}

func appendFile(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("append write: %v", err)
	}
}

// TestWaitFileStableFor_TimesOutWhileGrowing checks the bounded-wait behaviour:
// a file that never stops growing must report an error rather than block or
// silently claim the dump is complete.
func TestWaitFileStableFor_TimesOutWhileGrowing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				appendFile(t, path, make([]byte, 1<<16))
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	err := waitFileStableFor(path, false, 1*time.Second, 50*time.Millisecond)
	close(stop)
	<-done

	if err == nil {
		t.Fatal("expected a timeout error for a continuously growing file, got nil")
	}
}
