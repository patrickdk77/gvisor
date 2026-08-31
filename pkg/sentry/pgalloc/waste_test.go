// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pgalloc

import (
	"io"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

const wasteTestTimeout = 10 * time.Second

func newWasteTestFile(t *testing.T, retain uint64) *MemoryFile {
	t.Helper()
	fd, err := memutil.CreateMemFD("pgalloc-waste-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f, err := NewMemoryFile(os.NewFile(uintptr(fd), "pgalloc-waste-test"), MemoryFileOpts{
		DisableMemoryAccounting: true,
		WasteRetainBytes:        retain,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)
	return f
}

func allocateWastePage(t *testing.T, f *MemoryFile) memmap.FileRange {
	t.Helper()
	fr, err := f.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous, Mode: AllocateAndCommit})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	return fr
}

func wasteState(f *MemoryFile) (haveWaste bool, wasteBytes uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.haveWaste, f.wasteBytes
}

func waitForWaste(t *testing.T, f *MemoryFile, what string, done func(haveWaste bool, wasteBytes uint64) bool) {
	t.Helper()
	deadline := time.Now().Add(wasteTestTimeout)
	for {
		haveWaste, wasteBytes := wasteState(f)
		if done(haveWaste, wasteBytes) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: haveWaste=%t wasteBytes=%d", what, haveWaste, wasteBytes)
		}
		time.Sleep(time.Millisecond)
	}
}

func saveWithTimeout(t *testing.T, f *MemoryFile) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- f.SaveTo(context.Background(), io.Discard, &SaveOpts{})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SaveTo: %v", err)
		}
	case <-time.After(wasteTestTimeout):
		haveWaste, wasteBytes := wasteState(f)
		t.Fatalf("SaveTo did not return within %v: haveWaste=%t wasteBytes=%d", wasteTestTimeout, haveWaste, wasteBytes)
	}
}

// wasteRecycledBeforeRelease leaves f as DecRef does when an allocation then
// recycles all of the new waste before the releaser runs: haveWaste set and
// signaled, with no waste left.
func wasteRecycledBeforeRelease(f *MemoryFile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wasteBytes != 0 {
		panic("wasteRecycledBeforeRelease called with waste present")
	}
	f.haveWaste = true
	f.releaseCond.Signal()
}

func TestWasteReleased(t *testing.T) {
	f := newWasteTestFile(t, 0)
	f.DecRef(allocateWastePage(t, f))
	waitForWaste(t, f, "waste release", func(haveWaste bool, wasteBytes uint64) bool {
		return !haveWaste && wasteBytes == 0
	})
}

func TestSaveToDrainsRetainedWaste(t *testing.T) {
	f := newWasteTestFile(t, 1<<20)
	f.DecRef(allocateWastePage(t, f))
	if _, wasteBytes := wasteState(f); wasteBytes != hostarch.PageSize {
		t.Fatalf("wasteBytes before SaveTo: got %d, want %d", wasteBytes, hostarch.PageSize)
	}
	saveWithTimeout(t, f)
	if haveWaste, wasteBytes := wasteState(f); haveWaste || wasteBytes != 0 {
		t.Fatalf("after SaveTo: haveWaste=%t wasteBytes=%d, want false and 0", haveWaste, wasteBytes)
	}
}

func TestSaveToAfterWasteRecycled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		retain uint64
	}{
		{name: "no-retain", retain: 0},
		{name: "retain", retain: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWasteTestFile(t, tc.retain)
			allocateWastePage(t, f)
			wasteRecycledBeforeRelease(f)
			saveWithTimeout(t, f)
		})
	}
}

func TestReleaseResumesAfterWasteRecycled(t *testing.T) {
	f := newWasteTestFile(t, 0)
	allocateWastePage(t, f)
	wasteRecycledBeforeRelease(f)
	f.DecRef(allocateWastePage(t, f))
	waitForWaste(t, f, "waste release", func(haveWaste bool, wasteBytes uint64) bool {
		return !haveWaste && wasteBytes == 0
	})
}

func TestWasteRetainCapHolds(t *testing.T) {
	const retain = hostarch.PageSize
	f := newWasteTestFile(t, retain)
	pages := []memmap.FileRange{
		allocateWastePage(t, f),
		allocateWastePage(t, f),
		allocateWastePage(t, f),
	}
	f.DecRef(pages[0])
	if _, wasteBytes := wasteState(f); wasteBytes != retain {
		t.Fatalf("wasteBytes after first free: got %d, want %d", wasteBytes, retain)
	}
	// Let the releaser go back to sleep holding the retained page.
	time.Sleep(100 * time.Millisecond)
	f.DecRef(pages[1])
	f.DecRef(pages[2])
	waitForWaste(t, f, "waste above the retention cap to be released", func(_ bool, wasteBytes uint64) bool {
		return wasteBytes <= retain
	})
}
