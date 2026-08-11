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
