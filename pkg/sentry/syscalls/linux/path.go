// Copyright 2020 The gVisor Authors.
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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func copyInPath(t *kernel.Task, addr hostarch.Addr) (fspath.Path, error) {
	pathname, err := t.CopyInString(addr, linux.PATH_MAX)
	if err != nil {
		return fspath.Path{}, err
	}
	return fspath.Parse(pathname), nil
}

type taskPathOperation struct {
	pop          vfs.PathOperation
	haveStartRef bool
}

func getTaskPathOperation(t *kernel.Task, dirfd int32, path fspath.Path, emptyPathCheck shouldAllowEmptyPathType, shouldFollowFinalSymlink shouldFollowFinalSymlink) (taskPathOperation, error) {
	root := t.FSContext().RootDirectory()
	start := root
	haveStartRef := false
	if !path.Absolute {
		if !path.HasComponents() && !emptyPathCheck.allow() {
			root.DecRef(t)
			return taskPathOperation{}, linuxerr.ENOENT
		}
		if dirfd == linux.AT_FDCWD {
			start = t.FSContext().WorkingDirectory()
			haveStartRef = true
		} else {
			dirfile := t.GetFile(dirfd)
			if dirfile == nil {
				root.DecRef(t)
				return taskPathOperation{}, linuxerr.EBADF
			}
			defer dirfile.DecRef(t)

			// AT_EMPTY_PATH is allowed only if t's creds are identical to the creds under which the FD was
			// opened, or if t has CAP_DAC_READ_SEARCH in those creds' userns.
			// Similar to how Linux handles LOOKUP_LINKAT_EMPTY in path_init() in fs/namei.c.
			if emptyPathCheck == allowEmptyPathWithCredsCheck {
				if dirfile.Credentials() != t.Credentials() && !t.HasCapabilityIn(linux.CAP_DAC_READ_SEARCH, dirfile.Credentials().UserNamespace) {
					root.DecRef(t)
					return taskPathOperation{}, linuxerr.ENOENT
				}
			}

			start = dirfile.VirtualDentry()
			start.IncRef()
			haveStartRef = true
		}
	}
	return taskPathOperation{
		pop: vfs.PathOperation{
			Root:               root,
			Start:              start,
			Path:               path,
			FollowFinalSymlink: bool(shouldFollowFinalSymlink),
		},
		haveStartRef: haveStartRef,
	}, nil
}

// getTaskPathOperationRootedAtDirfd is getTaskPathOperation() for openat2(2)'s
// RESOLVE_IN_ROOT and RESOLVE_BENEATH, which resolve with dirfd itself as the
// root: "/" and ".." both stop there, and an absolute symlink restarts there
// rather than at the process's root.
//
// Unlike getTaskPathOperation(), dirfd is resolved even for an absolute
// pathname, because under these flags an absolute pathname is resolved
// relative to dirfd (RESOLVE_IN_ROOT) or refused (RESOLVE_BENEATH) instead of
// starting at the process's root.
func getTaskPathOperationRootedAtDirfd(t *kernel.Task, dirfd int32, path fspath.Path, shouldFollowFinalSymlink shouldFollowFinalSymlink, resolve uint64) (taskPathOperation, error) {
	if path.Absolute && resolve&linux.RESOLVE_BENEATH != 0 {
		// An absolute pathname leaves dirfd by definition.
		return taskPathOperation{}, linuxerr.EXDEV
	}
	// An empty pathname is ENOENT, as for openat(2) without AT_EMPTY_PATH.
	// "/" is not empty: it names the root itself, which here is dirfd.
	if !path.Absolute && !path.HasComponents() {
		return taskPathOperation{}, linuxerr.ENOENT
	}

	var root vfs.VirtualDentry
	if dirfd == linux.AT_FDCWD {
		root = t.FSContext().WorkingDirectory()
	} else {
		dirfile := t.GetFile(dirfd)
		if dirfile == nil {
			return taskPathOperation{}, linuxerr.EBADF
		}
		root = dirfile.VirtualDentry()
		root.IncRef()
		dirfile.DecRef(t)
	}
	return taskPathOperation{
		pop: vfs.PathOperation{
			Root:               root,
			Start:              root,
			Path:               path,
			FollowFinalSymlink: bool(shouldFollowFinalSymlink),
			Resolve:            resolve,
		},
		// Root and Start are the same VirtualDentry holding a single
		// reference, which Release() drops through Root.
		haveStartRef: false,
	}, nil
}

func (tpop *taskPathOperation) Release(t *kernel.Task) {
	tpop.pop.Root.DecRef(t)
	if tpop.haveStartRef {
		tpop.pop.Start.DecRef(t)
		tpop.haveStartRef = false
	}
}

type shouldAllowEmptyPathType uint8

const (
	disallowEmptyPath shouldAllowEmptyPathType = iota
	allowEmptyPath
	allowEmptyPathWithCredsCheck
)

func (sa shouldAllowEmptyPathType) allow() bool {
	return sa != disallowEmptyPath
}

func shouldAllowEmptyPath(allow bool) shouldAllowEmptyPathType {
	if allow {
		return allowEmptyPath
	}
	return disallowEmptyPath
}

type shouldFollowFinalSymlink bool

const (
	nofollowFinalSymlink shouldFollowFinalSymlink = false
	followFinalSymlink   shouldFollowFinalSymlink = true
)
