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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// checkDentryConfinement evaluates confinement for an access to d. It is a
// no-op for tasks that have not entered a profile, which is the common case
// and costs one load and a branch.
//
// Preconditions: d.inode.fs.renameMu must be locked for reading, or the
// caller must accept a path that raced with a rename.
func (d *dentry) checkDentryConfinement(creds *auth.Credentials, ats vfs.AccessTypes) error {
	if !creds.Confined() {
		return nil
	}
	// Walk to the filesystem root, collecting names.
	var names []string
	for cur := d; cur != nil; cur = cur.parent.Load() {
		names = append(names, cur.name)
	}
	mode := linux.FileMode(d.inode.mode.Load())
	// The mount point's own path. "/" for the root filesystem.
	path := confine.Path(d.inode.fs.iopts.UniqueID.Path, names,
		mode.FileType() == linux.ModeDirectory)
	return confine.Check(creds, path, ats, mode,
		auth.KUID(d.inode.uid.Load()))
}
