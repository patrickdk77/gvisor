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
)

// newTTLTestState builds a revalidation state over dentries whose metadata was
// last refreshed ageNanos ago.
func newTTLTestState(refreshStart bool, ages ...int64) *revalidateState {
	now := cacheNowNanos()
	mk := func(age int64) *dentry {
		d := &dentry{inode: &inode{}}
		d.inode.attrsAt.Store(now - age)
		return d
	}
	r := &revalidateState{
		start:        mk(0),
		refreshStart: refreshStart,
	}
	for _, age := range ages {
		r.dentries = append(r.dentries, mk(age))
	}
	return r
}

// TestRevalidateTTL covers when revalidation may be skipped. Without a TTL the
// remote filesystem is consulted on every access, which is what made a shared
// mount send one request per path component per operation.
func TestRevalidateTTL(t *testing.T) {
	const ttl = time.Minute
	fresh := int64(time.Second)
	stale := int64(2 * time.Minute)

	for _, tc := range []struct {
		name         string
		ttl          time.Duration
		refreshStart bool
		ages         []int64
		wantFresh    bool
	}{
		{
			// The default: no TTL, so nothing is ever trusted.
			name:      "no ttl always revalidates",
			ttl:       0,
			ages:      []int64{fresh, fresh},
			wantFresh: false,
		},
		{
			name:      "all components fresh",
			ttl:       ttl,
			ages:      []int64{fresh, fresh, fresh},
			wantFresh: true,
		},
		{
			name:      "one stale component revalidates the batch",
			ttl:       ttl,
			ages:      []int64{fresh, stale, fresh},
			wantFresh: false,
		},
		{
			// The names sent to the remote form a path walked from
			// start, so a stale first or last component cannot be
			// skipped over.
			name:      "stale first component",
			ttl:       ttl,
			ages:      []int64{stale, fresh},
			wantFresh: false,
		},
		{
			name:      "stale last component",
			ttl:       ttl,
			ages:      []int64{fresh, stale},
			wantFresh: false,
		},
		{
			name:         "start is checked when it is refreshed",
			ttl:          ttl,
			refreshStart: true,
			ages:         []int64{fresh},
			wantFresh:    true,
		},
		{
			name:      "no components is fresh",
			ttl:       ttl,
			ages:      nil,
			wantFresh: true,
		},
		{
			// Exactly at the TTL is stale, so a TTL of N never
			// serves metadata older than N.
			name:      "at the ttl boundary",
			ttl:       ttl,
			ages:      []int64{ttl.Nanoseconds()},
			wantFresh: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := revalidateTTL
			revalidateTTL = tc.ttl.Nanoseconds()
			defer func() { revalidateTTL = saved }()

			r := newTTLTestState(tc.refreshStart, tc.ages...)
			if got := r.allFresh(); got != tc.wantFresh {
				t.Errorf("allFresh() = %t, want %t", got, tc.wantFresh)
			}
		})
	}
}

// TestRevalidateTTLStartStale checks that a stale start dentry forces
// revalidation only when the start is part of the request.
func TestRevalidateTTLStartStale(t *testing.T) {
	saved := revalidateTTL
	revalidateTTL = time.Minute.Nanoseconds()
	defer func() { revalidateTTL = saved }()

	r := newTTLTestState(true, int64(time.Second))
	r.start.inode.attrsAt.Store(cacheNowNanos() - int64(2*time.Minute))
	if r.allFresh() {
		t.Error("allFresh() = true with a stale start that is being refreshed")
	}
	// The same state, with the start not part of the request, is fresh.
	r.refreshStart = false
	if !r.allFresh() {
		t.Error("allFresh() = false with a stale start that is not being refreshed")
	}
}

// TestSetRevalidateTTL checks that a negative duration is rejected rather than
// disabling revalidation.
func TestSetRevalidateTTL(t *testing.T) {
	saved := revalidateTTL
	defer func() { revalidateTTL = saved }()

	SetRevalidateTTL(30 * time.Second)
	if got, want := revalidateTTL, (30 * time.Second).Nanoseconds(); got != want {
		t.Errorf("revalidateTTL = %d, want %d", got, want)
	}
	SetRevalidateTTL(-time.Second)
	if got, want := revalidateTTL, (30 * time.Second).Nanoseconds(); got != want {
		t.Errorf("a negative TTL changed revalidateTTL to %d, want %d unchanged", got, want)
	}
}
