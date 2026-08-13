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
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// confinePath returns the path of d as the application sees it.
//
// Preconditions: d.inode.fs.renameMu must be locked for reading, or the
// caller must accept a path that raced with a rename.
func (d *dentry) confinePath() string {
	var names []string
	for cur := d; cur != nil; cur = cur.parent.Load() {
		names = append(names, cur.name)
	}
	mode := linux.FileMode(d.inode.mode.Load())
	return confine.Path(d.inode.fs.iopts.UniqueID.Path, names,
		mode.FileType() == linux.ModeDirectory)
}

// checkDACPermissions checks d's mode, owner and group only. Callers that
// mediate an operation on a name within d use this together with
// checkChildConfinement(), because AppArmor mediates creating, removing and
// renaming a file by a rule on that file's own path, not by a write rule on
// the directory holding it.
func (d *dentry) checkDACPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(d.inode.mode.Load()), nil, auth.KUID(d.inode.uid.Load()), auth.KGID(d.inode.gid.Load()))
}

// checkChildConfinement evaluates confinement for an operation on the name
// child within directory d, against the path that child has rather than d's.
//
// The child need not exist: creating it is mediated by the same rule that
// would mediate writing it, which is what AppArmor does.
func (d *dentry) checkChildConfinement(creds *auth.Credentials, child string, ats vfs.AccessTypes) error {
	if !creds.Confined() {
		return nil
	}
	path := d.childConfinePath(child)
	// The child's mode is unknown when it does not exist yet.
	return confine.Check(creds, path, ats, linux.FileMode(0), auth.KUID(creds.EffectiveKUID))
}

// childConfinePath returns the path the name child within directory d has.
func (d *dentry) childConfinePath(child string) string {
	path := d.confinePath()
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path + child
}

// checkChildPerm evaluates a specific permission for the name child within
// directory d. Callers use it for permissions that do not correspond to a
// vfs.AccessType, such as 'l' when creating a link.
func (d *dentry) checkChildPerm(creds *auth.Credentials, child string, want confine.Perm) error {
	if !creds.Confined() {
		return nil
	}
	return confine.CheckPerms(creds, d.childConfinePath(child), want, linux.FileMode(0), auth.KUID(creds.EffectiveKUID))
}

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

// checkAppendWriteConfinement evaluates a write to d that the application
// opened with O_APPEND, which either 'a' or 'w' permits.
func (d *dentry) checkAppendWriteConfinement(creds *auth.Credentials) error {
	if !creds.Confined() {
		return nil
	}
	return confine.CheckAppendWrite(creds, d.confinePath(),
		linux.FileMode(d.inode.mode.Load()), auth.KUID(d.inode.uid.Load()))
}
