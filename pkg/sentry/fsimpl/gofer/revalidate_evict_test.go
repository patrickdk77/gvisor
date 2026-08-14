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

package gofer

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	ktime "gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

// newTestFS builds a filesystem whose dentry cache can hold entries, so that a
// dentry dropped to zero references is cached rather than destroyed.
func newTestFS(ctx context.Context, maxCached uint64) *filesystem {
	return &filesystem{
		mf:          pgalloc.MemoryFileFromContext(ctx),
		inoByKey:    make(map[inoKey]uint64),
		inodeByKey:  make(map[inoKey]*inode),
		clock:       ktime.RealtimeClockFromContext(ctx),
		dentryCache: &dentryCache{maxCachedDentries: maxCached},
		client:      &lisafs.Client{},
	}
}

// newTestChild creates a parent directory and a child file under it, and
// returns both.
func newTestChild(ctx context.Context, t *testing.T, fs *filesystem) (*dentry, *dentry) {
	t.Helper()
	parent, err := fs.newLisafsDentry(ctx, &lisafs.Inode{
		ControlFD: 1,
		Stat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE,
			Mode: linux.S_IFDIR | 0777,
		},
	})
	if err != nil {
		t.Fatalf("newLisafsDentry(parent): %v", err)
	}
	child, err := fs.newLisafsDentry(ctx, &lisafs.Inode{
		ControlFD: 2,
		Stat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_SIZE,
			Mode: linux.S_IFREG | 0666,
		},
	})
	if err != nil {
		t.Fatalf("newLisafsDentry(child): %v", err)
	}
	parent.opMu.Lock()
	parent.childrenMu.Lock()
	parent.cacheNewChildLocked(child, "child")
	parent.childrenMu.Unlock()
	parent.opMu.Unlock()
	return parent, child
}

// TestEvictionDropsCachedMetadata records why a revalidation TTL alone does not
// reduce work on a mount whose dentries are idle-evicted: eviction does not
// merely close the host FDs, it destroys the dentry, so there is no cached
// metadata left for the TTL to trust. A file idle longer than the dentry cache
// TTL therefore costs a full cold lookup on its next access however long the
// revalidation TTL is.
func TestEvictionDropsCachedMetadata(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := newTestFS(ctx, 100)
	parent, child := newTestChild(ctx, t, fs)

	// The child's metadata is fresh, so a revalidation covering it would be
	// skipped entirely.
	revalidateTTLSaved := revalidateTTL
	revalidateTTL = time.Minute.Nanoseconds()
	defer func() { revalidateTTL = revalidateTTLSaved }()
	child.inode.attrsAt.Store(cacheNowNanos())
	state := &revalidateState{start: parent}
	state.add(child)
	if !state.allFresh() {
		t.Fatal("a just-created child is not fresh; the test cannot show what it means to")
	}

	// Drop the child's last reference so it lands in the dentry cache, the
	// state an idle file is in.
	fs.renameMu.Lock()
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	fs.renameMu.Unlock()

	parent.childrenMu.Lock()
	_, cached := parent.children["child"]
	parent.childrenMu.Unlock()
	if !cached {
		t.Fatal("child was not retained in the dentry cache")
	}

	// Evict it, which is what the idle sweeper does once the dentry cache TTL
	// has passed.
	child.evict(ctx)

	parent.childrenMu.Lock()
	_, stillCached := parent.children["child"]
	parent.childrenMu.Unlock()
	if stillCached {
		t.Error("child survived eviction; if eviction only released FDs, a revalidation TTL could still cover it")
	}
}

// TestRevalidateTTLCoversCachedDentry is the other half: a dentry that has not
// been evicted is covered by the TTL, so repeated access to the same path skips
// revalidation.
func TestRevalidateTTLCoversCachedDentry(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := newTestFS(ctx, 100)
	parent, child := newTestChild(ctx, t, fs)

	saved := revalidateTTL
	revalidateTTL = time.Minute.Nanoseconds()
	defer func() { revalidateTTL = saved }()

	state := &revalidateState{start: parent, refreshStart: true}
	state.add(child)

	now := cacheNowNanos()
	parent.inode.attrsAt.Store(now)
	child.inode.attrsAt.Store(now)
	if !state.allFresh() {
		t.Error("allFresh() = false for a parent and child both just refreshed")
	}

	// Once the child's metadata ages past the TTL, the batch is revalidated
	// again, so staleness is bounded by the TTL.
	child.inode.attrsAt.Store(now - 2*time.Minute.Nanoseconds())
	if state.allFresh() {
		t.Error("allFresh() = true for a child older than the TTL")
	}
}

// newNamedChild adds another child file to parent, so that a test can refill
// the dentry cache after it has drained.
func newNamedChild(ctx context.Context, t *testing.T, fs *filesystem, parent *dentry, controlFD lisafs.FDID, name string) *dentry {
	t.Helper()
	child, err := fs.newLisafsDentry(ctx, &lisafs.Inode{
		ControlFD: controlFD,
		Stat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_SIZE,
			Mode: linux.S_IFREG | 0666,
		},
	})
	if err != nil {
		t.Fatalf("newLisafsDentry(%s): %v", name, err)
	}
	parent.opMu.Lock()
	parent.childrenMu.Lock()
	parent.cacheNewChildLocked(child, name)
	parent.childrenMu.Unlock()
	parent.opMu.Unlock()
	return child
}

// cacheChild drops the child's last reference, which is what an idle file's
// dentry does: it lands in the dentry cache holding its host FDs open.
func cacheChild(ctx context.Context, fs *filesystem, child *dentry) {
	fs.renameMu.Lock()
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	fs.renameMu.Unlock()
}

// cachedLen reports how many dentries are currently cached.
func cachedLen(dc *dentryCache) uint64 {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.dentriesLen
}

// waitForCacheDrain waits for the sweeper to evict everything.
func waitForCacheDrain(dc *dentryCache, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cachedLen(dc) == 0 {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cachedLen(dc) == 0
}

// TestSweeperEvictsIdleDentry covers the basic contract of --dcache-ttl: a
// dentry left unreferenced for the TTL is evicted, releasing its host FDs. This
// is what keeps the sandbox from holding files open on an NFS server.
func TestSweeperEvictsIdleDentry(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := newTestFS(ctx, 100)
	fs.dentryCache.ttl = 200 * time.Millisecond
	fs.dentryCache.startSweeper()
	defer close(fs.dentryCache.sweeperStop)

	parent, child := newTestChild(ctx, t, fs)
	// Hold the parent, as an in-use directory does. Otherwise evicting the
	// child drops the child's reference on its parent, the parent falls to
	// zero references, and the sweeper evicts the directory too, which is
	// correct but not what these tests are measuring.
	parent.IncRef()
	cacheChild(ctx, fs, child)
	if got := cachedLen(fs.dentryCache); got != 1 {
		t.Fatalf("cached dentries = %d, want 1", got)
	}
	// Not evicted before it has been idle for the TTL.
	time.Sleep(20 * time.Millisecond)
	if got := cachedLen(fs.dentryCache); got != 1 {
		t.Errorf("cached dentries = %d after 20ms of a %v TTL, want 1", got, fs.dentryCache.ttl)
	}
	if !waitForCacheDrain(fs.dentryCache, 10*time.Second) {
		t.Error("an idle dentry was never evicted, so its host FDs stay open for as long as the sandbox lives")
	}
}

// TestSweeperWakesAfterCacheDrains is the regression test for the sweeper
// parking instead of polling.
//
// The sweeper does no work while nothing is cached, so it has to be woken by
// the insert that makes the cache non-empty again. If that wakeup is missed,
// everything cached after the first drain is never evicted and the sandbox
// holds those host FDs forever, which is worse than the polling it replaced and
// invisible until an NFS server runs out of open files.
func TestSweeperWakesAfterCacheDrains(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := newTestFS(ctx, 100)
	fs.dentryCache.ttl = 200 * time.Millisecond
	fs.dentryCache.startSweeper()
	defer close(fs.dentryCache.sweeperStop)

	parent, child := newTestChild(ctx, t, fs)
	// Hold the parent, as an in-use directory does. Otherwise evicting the
	// child drops the child's reference on its parent, the parent falls to
	// zero references, and the sweeper evicts the directory too, which is
	// correct but not what these tests are measuring.
	parent.IncRef()
	cacheChild(ctx, fs, child)
	if !waitForCacheDrain(fs.dentryCache, 10*time.Second) {
		t.Fatal("the first idle dentry was never evicted")
	}

	// The cache is empty and the sweeper is parked. Refill it.
	for i, name := range []string{"second", "third"} {
		next := newNamedChild(ctx, t, fs, parent, lisafs.FDID(10+i), name)
		cacheChild(ctx, fs, next)
		if !waitForCacheDrain(fs.dentryCache, 10*time.Second) {
			t.Fatalf("dentry %q was never evicted after the cache had drained: the sweeper parked and was not woken", name)
		}
	}
}

// TestSweeperHonoursTTLPromptly covers the reason the sweeper sleeps to a
// deadline rather than polling on an interval.
//
// It used to wake every ttl/4, floored at 10 seconds, so a dentry could hold
// its host FDs for the TTL plus most of an interval. At the 15s used to keep
// files from staying open on NFS that meant up to 25s, which is not what the
// flag says.
func TestSweeperHonoursTTLPromptly(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := newTestFS(ctx, 100)
	const ttl = 300 * time.Millisecond
	fs.dentryCache.ttl = ttl
	fs.dentryCache.startSweeper()
	defer close(fs.dentryCache.sweeperStop)

	parent, child := newTestChild(ctx, t, fs)
	// Hold the parent, as an in-use directory does. Otherwise evicting the
	// child drops the child's reference on its parent, the parent falls to
	// zero references, and the sweeper evicts the directory too, which is
	// correct but not what these tests are measuring.
	parent.IncRef()
	start := time.Now()
	cacheChild(ctx, fs, child)
	if !waitForCacheDrain(fs.dentryCache, 10*time.Second) {
		t.Fatal("an idle dentry was never evicted")
	}
	// Generous, because this is a scheduling deadline and not a hard
	// guarantee. The point is that it is not a fixed 10s sweep interval.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("eviction took %v for a %v TTL; the sweeper is polling on an interval rather than sleeping to the entry's deadline", elapsed, ttl)
	}
}

// TestNoSweeperWithoutTTL covers the default configuration, where no sweeper
// runs at all. The insert path signals the sweeper through a channel that only
// exists when there is one, so this also covers that the signal is safe when
// there is not.
func TestNoSweeperWithoutTTL(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := newTestFS(ctx, 100)
	if fs.dentryCache.ttl != 0 {
		t.Fatalf("ttl = %v, want 0 for this test", fs.dentryCache.ttl)
	}
	fs.dentryCache.startSweeper()
	if fs.dentryCache.sweeperStop != nil || fs.dentryCache.notEmpty != nil {
		t.Error("a sweeper was started for a zero TTL")
	}

	_, child := newTestChild(ctx, t, fs)
	// Must not panic on the nil signal channel.
	cacheChild(ctx, fs, child)
	time.Sleep(50 * time.Millisecond)
	if got := cachedLen(fs.dentryCache); got != 1 {
		t.Errorf("cached dentries = %d, want 1: with no TTL a dentry is only evicted by size pressure", got)
	}
}
