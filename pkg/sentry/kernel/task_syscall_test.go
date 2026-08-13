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

package kernel

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/confine"
)

// TestExtractErrnoKillError covers the errno reported for a violation of an
// AppArmor profile in kill mode.
//
// ExtractErrno panics on an error it cannot translate, and it is reached from
// seven places on the syscall return path, including strace and the seccheck
// points. A *confine.KillError is a type of this package's own, so linuxerr
// cannot translate it and only an explicit case keeps it from panicking the
// sentry - which would take down every container in the sandbox on the first
// denial under a kill-mode profile.
func TestExtractErrnoKillError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{
			name: "the wrapped errno is reported",
			err:  &confine.KillError{Signal: int32(unix.SIGKILL), Err: linuxerr.EACCES},
			want: int(unix.EACCES),
		},
		{
			name: "a profile's error= flag is preserved",
			err:  &confine.KillError{Signal: int32(unix.SIGKILL), Err: linuxerr.EPERM},
			want: int(unix.EPERM),
		},
		{
			name: "the signal does not change the errno",
			err:  &confine.KillError{Signal: int32(unix.SIGTERM), Err: linuxerr.EACCES},
			want: int(unix.EACCES),
		},
		{
			name: "an enforce-mode denial is unaffected",
			err:  linuxerr.EACCES,
			want: int(unix.EACCES),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ExtractErrno(%v) panicked: %v; a kill-mode denial must return an errno, not crash the sentry", tc.err, r)
				}
			}()
			if got := ExtractErrno(tc.err, 1); got != tc.want {
				t.Errorf("ExtractErrno(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestExtractErrnoKillErrorNested covers a KillError that reaches the syscall
// layer wrapped by something else, which is how it arrives from a path walk.
func TestExtractErrnoKillErrorNested(t *testing.T) {
	err := fmt.Errorf("walking: %w", &confine.KillError{Err: linuxerr.EACCES})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ExtractErrno(%v) panicked: %v", err, r)
		}
	}()
	// A wrapped KillError is translated through the generic unwrapping path,
	// so this documents the behaviour rather than asserting a specific errno
	// that linuxerr may not be able to recover.
	if got := ExtractErrno(err, 1); got != int(unix.EACCES) {
		t.Errorf("ExtractErrno(%v) = %d, want %d", err, got, int(unix.EACCES))
	}
}
