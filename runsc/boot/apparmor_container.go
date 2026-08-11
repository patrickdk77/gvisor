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

package boot

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// containerPolicyFS reads AppArmor policy from a container's own filesystem,
// through the Sentry's VFS. It is used by --apparmor-policy-source=container,
// which cannot read the policy at sandbox startup because the container's mount
// namespace does not exist yet.
//
// Reads are done with the credentials that created the mount namespace, not
// with the confined task's, so that a profile can restrict access to the policy
// it is itself derived from.
type containerPolicyFS struct {
	ctx    context.Context
	vfsObj *vfs.VirtualFilesystem
	root   vfs.VirtualDentry
	creds  *auth.Credentials
}

// pathOp returns a PathOperation for path, resolved from the container's root.
func (c *containerPolicyFS) pathOp(path string) *vfs.PathOperation {
	return &vfs.PathOperation{
		Root:  c.root,
		Start: c.root,
		Path:  fspath.Parse(path),
	}
}

// ReadDir implements policyFS.ReadDir.
func (c *containerPolicyFS) ReadDir(path string) ([]policyDirent, error) {
	fd, err := c.vfsObj.OpenAt(c.ctx, c.creds, c.pathOp(path), &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		return nil, err
	}
	defer fd.DecRef(c.ctx)
	var out []policyDirent
	if err := fd.IterDirents(c.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		switch d.Name {
		case ".", "..":
			return nil
		}
		out = append(out, policyDirent{
			Name:  d.Name,
			IsDir: d.Type == linux.DT_DIR,
		})
		return nil
	})); err != nil {
		return nil, err
	}
	return out, nil
}

// Stat implements policyFS.Stat.
func (c *containerPolicyFS) Stat(path string) (bool, error) {
	stat, err := c.vfsObj.StatAt(c.ctx, c.creds, c.pathOp(path), &vfs.StatOptions{
		Mask: linux.STATX_TYPE,
	})
	if err != nil {
		return false, err
	}
	if stat.Mask&linux.STATX_TYPE == 0 {
		return false, linuxerr.EIO
	}
	return stat.Mode&linux.FileTypeMask == linux.ModeDirectory, nil
}

// Open implements policyFS.Open.
func (c *containerPolicyFS) Open(path string) (io.ReadCloser, error) {
	fd, err := c.vfsObj.OpenAt(c.ctx, c.creds, c.pathOp(path), &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		return nil, err
	}
	return &containerPolicyFile{ctx: c.ctx, fd: fd}, nil
}

// IsNotExist implements policyFS.IsNotExist.
func (c *containerPolicyFS) IsNotExist(err error) bool {
	return linuxerr.Equals(linuxerr.ENOENT, err)
}

// containerPolicyFile adapts a vfs.FileDescription to io.ReadCloser.
type containerPolicyFile struct {
	ctx context.Context
	fd  *vfs.FileDescription
}

// Read implements io.Reader.Read.
func (f *containerPolicyFile) Read(buf []byte) (int, error) {
	n, err := f.fd.Read(f.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return int(n), err
}

// Close implements io.Closer.Close.
func (f *containerPolicyFile) Close() error {
	f.fd.DecRef(f.ctx)
	return nil
}

// loadContainerAppArmorPolicy reads the policy from a container's filesystem
// and merges it into the sandbox's. It is called once per container, after its
// mount namespace exists and before its initial process runs.
//
// The host source is loaded once for the sandbox; this is loaded per container,
// so several containers may each contribute profiles. They are merged rather
// than replaced: a profile another container already defined is kept, because
// replacing it would leave tasks already running under it confined by rules
// they never started with, and would let one container weaken another's
// profile.
func loadContainerAppArmorPolicy(ctx context.Context, vfsObj *vfs.VirtualFilesystem, mns *vfs.MountNamespace, creds *auth.Credentials, dir string) error {
	root := mns.Root(ctx)
	defer root.DecRef(ctx)
	pfs := &containerPolicyFS{
		ctx:    ctx,
		vfsObj: vfsObj,
		root:   root,
		creds:  creds,
	}
	// A container that ships no policy directory supplies no profiles, which
	// is the normal case for an image that carries none at all, the pod's
	// pause container among them. Report it as a plain fact rather than an
	// error, so the log distinguishes it from policy that exists and could
	// not be parsed.
	if isDir, err := pfs.Stat(dir); err != nil {
		if pfs.IsNotExist(err) {
			log.Infof("AppArmor: container has no policy directory %q; in-sandbox enforcement is off for it", dir)
			return nil
		}
		return fmt.Errorf("reading policy directory %q: %w", dir, err)
	} else if !isDir {
		return fmt.Errorf("policy directory %q is not a directory", dir)
	}
	policy, err := loadAppArmorPolicyDir(pfs, dir)
	if err != nil {
		return err
	}
	if appArmorPolicy == nil {
		appArmorPolicy = &AppArmorPolicy{}
	}
	appArmorPolicy.merge(policy)
	auth.SetExecConfinementProfiles(appArmorPolicy.ExecAttach)
	confine.SetPolicy(appArmorPolicy.Rules)
	return nil
}
