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
	"gvisor.dev/gvisor/pkg/context"
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
func (d *dentry) checkChildConfinement(ctx context.Context, creds *auth.Credentials, op confine.Op, child string, ats vfs.AccessTypes) error {
	return d.checkChildConfinementDir(ctx, creds, op, child, ats, false /* isDir */)
}

// checkChildConfinementDir is checkChildConfinement for an entry that is, or is
// being created as, a directory. "When AppArmor looks up a directory the
// pathname being looked up will end with a slash [...] Only rules that match a
// trailing slash will match directories."
func (d *dentry) checkChildConfinementDir(ctx context.Context, creds *auth.Credentials, op confine.Op, child string, ats vfs.AccessTypes, isDir bool) error {
	if !creds.Confined() {
		return nil
	}
	path := d.childConfinePath(child)
	if isDir {
		path += "/"
	}
	// The child's mode is unknown when it does not exist yet.
	return confine.Check(ctx, creds, op, path, ats, linux.FileMode(0), auth.KUID(creds.EffectiveKUID))
}

// checkChildCreateConfinement mediates creating the name child within directory
// d. Creating a file asks for 'w' on the new file's own path; creating a hard
// link asks for 'l' instead, which is what AppArmor's link rules are keyed on.
// The link's target is then mediated by checkLinkConfinement().
func (d *dentry) checkChildCreateConfinement(ctx context.Context, creds *auth.Credentials, op confine.Op, child string, isDir bool) error {
	if op == confine.OpLink {
		return d.checkChildPerm(ctx, creds, op, child, confine.Link)
	}
	return d.checkChildConfinementDir(ctx, creds, op, child, vfs.MayWrite, isDir)
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
func (d *dentry) checkChildPerm(ctx context.Context, creds *auth.Credentials, op confine.Op, child string, want confine.Perm) error {
	if !creds.Confined() {
		return nil
	}
	return confine.CheckPerms(ctx, creds, op, d.childConfinePath(child), want, linux.FileMode(0), auth.KUID(creds.EffectiveKUID))
}

// checkDentryConfinement evaluates confinement for an access to d. It is a
// no-op for tasks that have not entered a profile, which is the common case
// and costs one load and a branch.
//
// Preconditions: d.inode.fs.renameMu must be locked for reading, or the
// caller must accept a path that raced with a rename.
func (d *dentry) checkDentryConfinement(ctx context.Context, creds *auth.Credentials, op confine.Op, ats vfs.AccessTypes) error {
	if !creds.Confined() {
		return nil
	}
	mode := linux.FileMode(d.inode.mode.Load())
	if !confine.Mediates(ats, mode.FileType() == linux.ModeDirectory) {
		// Nothing in this access is mediated (directory traversal being
		// the common case, on every component of every walk), so do not
		// pay to build the path.
		return nil
	}
	// Walk to the filesystem root, collecting names.
	var names []string
	for cur := d; cur != nil; cur = cur.parent.Load() {
		names = append(names, cur.name)
	}
	// The mount point's own path. "/" for the root filesystem.
	path := confine.Path(d.inode.fs.iopts.UniqueID.Path, names,
		mode.FileType() == linux.ModeDirectory)
	return confine.CheckRevalidating(ctx, creds, op, path, ats, mode,
		auth.KUID(d.inode.uid.Load()), d.ownerRevalidator(ctx))
}

// ownerRevalidator returns a closure that fetches d's owner uid fresh from the
// remote, for the confine engine to consult before denying an owner rule. It
// is nil when d's cached metadata is authoritative, so nothing can be stale
// and the engine does no revalidation.
//
// On a shared mount the cached owner can lag: another client's in-progress
// create is briefly root-owned before its owner is set, and a lookup that
// catches that window caches the root owner. A real kernel refreshes
// attributes on open, so an owner rule must not be denied against a stale
// owner without a fresh check first.
func (d *dentry) ownerRevalidator(ctx context.Context) func() auth.KUID {
	if d.inode.cachedMetadataAuthoritative() {
		return nil
	}
	return func() auth.KUID {
		// A failed refresh keeps the cached owner, which leaves the denial
		// in place rather than allowing on unknown data.
		_ = d.inode.updateMetadata(ctx)
		return auth.KUID(d.inode.uid.Load())
	}
}

// checkOpenConfinement evaluates confinement for an open of d, whose flags
// decide which permissions the open asks for.
func (d *dentry) checkOpenConfinement(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes, flags uint32, fileExec bool) error {
	if fileExec {
		// An open on behalf of execve. The kernel mediates this as
		// operation "exec" asking for "x" alone: reading the program is
		// the kernel's own doing, not the task's "r", so a profile
		// granting bare "ix" execs a file it cannot read.
		return d.checkConfinePerm(ctx, creds, confine.OpExec, confine.Exec)
	}
	if !creds.Confined() {
		return nil
	}
	return confine.CheckOpenRevalidating(ctx, creds, d.confinePath(), ats, flags,
		linux.FileMode(d.inode.mode.Load()), auth.KUID(d.inode.uid.Load()),
		d.ownerRevalidator(ctx))
}

// checkLinkConfinement evaluates creating the link name within directory d to
// the file target.
func (d *dentry) checkLinkConfinement(ctx context.Context, creds *auth.Credentials, name string, target *dentry) error {
	if !creds.Confined() {
		return nil
	}
	return confine.CheckLink(ctx, creds, d.childConfinePath(name), target.confinePath(),
		linux.FileMode(target.inode.mode.Load()), auth.KUID(target.inode.uid.Load()))
}

// Reading a file's metadata is not mediated. Linux registers an
// inode_getattr hook, but a real kernel does not deny a stat of a path that no
// rule in the profile matches: verified against apparmor 4.0.1 with a
// production profile, where
//
//	aa-exec -p cageweb -- stat /var/www/vhosts/s/t/<site>
//
// succeeds and audits nothing even though none of the profile's 487 compiled
// rules match that path. Mediating it here denied what a host kernel permits,
// which is worse than not mediating it at all.

// checkSetattrConfinement mediates changing d's metadata, which AppArmor asks
// for AA_MAY_SETATTR, AA_MAY_CHMOD or AA_MAY_CHOWN for, all of which 'w'
// grants. Truncation asks for MAY_WRITE as well.
func (d *dentry) checkSetattrConfinement(ctx context.Context, creds *auth.Credentials, op confine.Op) error {
	return d.checkConfinePerm(ctx, creds, op, confine.Write)
}

// checkLockConfinement mediates locking d, which AppArmor asks for
// AA_MAY_LOCK for and 'k' grants.
func (d *dentry) checkLockConfinement(ctx context.Context, creds *auth.Credentials) error {
	return d.checkConfinePerm(ctx, creds, confine.OpFlock, confine.Lock)
}

// checkConfinePerm evaluates one permission against d's path.
//
// Preconditions: d.inode.fs.renameMu must be locked for reading, or the
// caller must accept a path that raced with a rename.
func (d *dentry) checkConfinePerm(ctx context.Context, creds *auth.Credentials, op confine.Op, want confine.Perm) error {
	if !creds.Confined() {
		return nil
	}
	return confine.CheckPermsRevalidating(ctx, creds, op, d.confinePath(), want,
		linux.FileMode(d.inode.mode.Load()),
		auth.KUID(d.inode.uid.Load()), d.ownerRevalidator(ctx))
}
