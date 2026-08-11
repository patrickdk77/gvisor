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

package tmpfs

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// newConfinedTmpfs mounts a tmpfs at mountPath and creates one file in it.
func newConfinedTmpfs(ctx context.Context, mountPath string) (*vfs.VirtualFilesystem, vfs.VirtualDentry, func(), error) {
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOpts{MountPath: mountPath},
		},
	}, nil)
	if err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("mounting tmpfs: %v", err)
	}
	root := mntns.Root(ctx)
	return vfsObj, root, func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	}, nil
}

// TestConfinement checks that a task in a profile is mediated on a tmpfs mount,
// against the path the application sees rather than the path within the mount.
func TestConfinement(t *testing.T) {
	confine.SetPolicy(map[string]*confine.Profile{
		"p": {Name: "p", Rules: []confine.Rule{
			{Pattern: "/scratch/", Perms: confine.ParsePerms("r")},
			{Pattern: "/scratch/allowed", Perms: confine.ParsePerms("rw")},
			{Pattern: "/scratch/readonly", Perms: confine.ParsePerms("r")},
		}},
	})
	defer confine.SetPolicy(nil)

	for _, tc := range []struct {
		name      string
		mountPath string
		file      string
		profile   string
		ats       vfs.AccessTypes
		wantErr   bool
	}{
		{
			name:      "a rule for the path the application sees",
			mountPath: "/scratch",
			file:      "allowed",
			profile:   "p",
			ats:       vfs.MayRead | vfs.MayWrite,
		},
		{
			// The rule grants only read, and the path within the
			// mount ("/readonly") is not what is matched.
			name:      "write denied by a read-only rule",
			mountPath: "/scratch",
			file:      "readonly",
			profile:   "p",
			ats:       vfs.MayRead | vfs.MayWrite,
			wantErr:   true,
		},
		{
			name:      "no rule for the file",
			mountPath: "/scratch",
			file:      "other",
			profile:   "p",
			ats:       vfs.MayRead,
			wantErr:   true,
		},
		{
			name:      "an unconfined task is not mediated",
			mountPath: "/scratch",
			file:      "other",
			ats:       vfs.MayRead | vfs.MayWrite,
		},
		{
			// The SysV shm mount and the files backing shared
			// anonymous mappings have no path an application can
			// name, so they must not be matched against rules.
			name:    "a mount with no path is not mediated",
			file:    "other",
			profile: "p",
			ats:     vfs.MayRead | vfs.MayWrite,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			creds := auth.CredentialsFromContext(ctx)
			vfsObj, root, cleanup, err := newConfinedTmpfs(ctx, tc.mountPath)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			pop := &vfs.PathOperation{
				Root:  root,
				Start: root,
				Path:  fspath.Parse(tc.file),
			}
			// Create the file while unconfined, so that only the
			// access below is mediated.
			fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{
				Flags: linux.O_RDWR | linux.O_CREAT,
				Mode:  0666,
			})
			if err != nil {
				t.Fatalf("creating %q: %v", tc.file, err)
			}
			fd.DecRef(ctx)

			confined := creds.Fork()
			confined.ConfinementProfile = tc.profile
			flags := uint32(linux.O_RDONLY)
			if tc.ats.MayWrite() {
				flags = linux.O_RDWR
			}
			fd, err = vfsObj.OpenAt(ctx, confined, pop, &vfs.OpenOptions{Flags: flags})
			if err == nil {
				fd.DecRef(ctx)
			}
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("OpenAt(%q) = %v, wantErr %t", tc.file, err, tc.wantErr)
			}
			if tc.wantErr && err != nil && !linuxerr.Equals(linuxerr.EACCES, err) {
				t.Errorf("OpenAt(%q) = %v, want EACCES", tc.file, err)
			}
		})
	}
}
