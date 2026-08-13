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

// TestUnmediatedOperations pins the operations Linux's AppArmor does not hook,
// which must therefore not be mediated here either: it registers no
// inode_readlink, path_readlink or inode_permission hook, so readlink(2) and
// access(2) are not mediated operations. Mediating one denies what a host kernel
// permits, and a profile written for runc then fails under gVisor. This test
// exists because readlink(2) was mediated by mistake, which denied every
// resolution of a root-owned symlink under an owner rule.
func TestUnmediatedOperations(t *testing.T) {
	var records []string
	confine.SetTestLogSink(func(record string) {
		records = append(records, record)
	})
	defer confine.SetTestLogSink(nil)

	// A profile that grants nothing beyond creating the fixture: any
	// mediated access to the link or the file is denied, so a denial here
	// means the operation is mediated.
	confine.SetPolicy(map[string]*confine.Profile{
		"p": {Name: "p"},
	})
	defer confine.SetPolicy(nil)

	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newConfinedTmpfs(ctx, "/scratch")
	if err != nil {
		t.Fatalf("newConfinedTmpfs: %v", err)
	}
	defer cleanup()

	// Create the target and a symlink to it while unconfined.
	pop := func(name string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(name)}
	}
	if err := vfsObj.MknodAt(ctx, creds, pop("target"), &vfs.MknodOptions{Mode: linux.ModeRegular | 0644}); err != nil {
		t.Fatalf("MknodAt: %v", err)
	}
	if err := vfsObj.SymlinkAt(ctx, creds, pop("link"), "target"); err != nil {
		t.Fatalf("SymlinkAt: %v", err)
	}

	confined := *creds
	confined.ConfinementProfile = "p"

	for _, tc := range []struct {
		name string
		do   func() error
	}{
		{
			name: "readlink is not mediated",
			do: func() error {
				_, err := vfsObj.ReadlinkAt(ctx, &confined, pop("link"))
				return err
			},
		},
		{
			name: "access is not mediated",
			do: func() error {
				return vfsObj.AccessAt(ctx, &confined, vfs.MayRead, pop("target"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records = nil
			if err := tc.do(); err != nil {
				t.Errorf("operation denied under a profile that mediates nothing: %v", err)
			}
			if len(records) != 0 {
				t.Errorf("operation produced %d audit records, so it is mediated: %v", len(records), records)
			}
		})
	}

	// A mediated operation on the same paths must still be denied, so that
	// the test above cannot pass because nothing is mediated at all. Reading
	// metadata is not such an operation; opening the file is.
	if fd, err := vfsObj.OpenAt(ctx, &confined, pop("target"), &vfs.OpenOptions{Flags: linux.O_RDONLY}); err == nil {
		fd.DecRef(ctx)
		t.Error("OpenAt was permitted under a profile that grants nothing; the fixture no longer proves anything")
	}
}

// TestMetadataReadsAreNotMediated pins that reading a file's metadata is not
// mediated, in any of its forms, and that a symlink is neither resolved nor
// checked for it.
//
// Linux registers an inode_getattr hook, but a real kernel does not deny a stat
// of a path no rule matches: under apparmor 4.0.1 with a production profile
// whose 487 compiled rules contain nothing for the path, the stat succeeds and
// audits nothing, and fifteen years of that profile in production have produced
// no such denial. Mediating it denied what a host kernel permits, which is a bug
// rather than a gap, and it broke a live workload. The positive control below
// keeps this test from passing merely because nothing is mediated at all.
func TestMetadataReadsAreNotMediated(t *testing.T) {
	var records []string
	confine.SetTestLogSink(func(record string) {
		records = append(records, record)
	})
	defer confine.SetTestLogSink(nil)

	// Only the owner may read anything, which is the shape of a
	// multi-tenant profile and the case that broke.
	confine.SetPolicy(map[string]*confine.Profile{
		"p": {Name: "p", Rules: []confine.Rule{
			{Pattern: "/scratch/**", Perms: confine.ParsePerms("r"), Owner: true},
		}},
	})
	defer confine.SetPolicy(nil)

	ctx := contexttest.Context(t)
	root := auth.CredentialsFromContext(ctx)
	vfsObj, mntRoot, cleanup, err := newConfinedTmpfs(ctx, "/scratch")
	if err != nil {
		t.Fatalf("newConfinedTmpfs: %v", err)
	}
	defer cleanup()

	pop := func(name string, follow bool) *vfs.PathOperation {
		return &vfs.PathOperation{
			Root:               mntRoot,
			Start:              mntRoot,
			Path:               fspath.Parse(name),
			FollowFinalSymlink: follow,
		}
	}

	// The target belongs to the tenant; the link belongs to root, as the
	// domain aliases in the incident did.
	const tenant = auth.KUID(47102)
	asTenant := *root
	asTenant.EffectiveKUID = tenant
	asTenant.RealKUID = tenant
	if err := vfsObj.MknodAt(ctx, &asTenant, pop("target", false), &vfs.MknodOptions{Mode: linux.ModeRegular | 0644}); err != nil {
		t.Fatalf("MknodAt: %v", err)
	}
	if err := vfsObj.SymlinkAt(ctx, root, pop("link", false), "target"); err != nil {
		t.Fatalf("SymlinkAt: %v", err)
	}

	// A task that owns neither the link nor anything else here.
	other := *root
	other.ConfinementProfile = "p"
	other.EffectiveKUID = auth.KUID(30002)
	other.RealKUID = auth.KUID(30002)

	for _, tc := range []struct {
		name string
		do   func() error
	}{
		{
			name: "lstat of a link the task does not own",
			do: func() error {
				_, err := vfsObj.StatAt(ctx, &other, pop("link", false), &vfs.StatOptions{})
				return err
			},
		},
		{
			name: "stat through that link",
			do: func() error {
				_, err := vfsObj.StatAt(ctx, &other, pop("link", true), &vfs.StatOptions{})
				return err
			},
		},
		{
			name: "lstat of a file the task does not own",
			do: func() error {
				_, err := vfsObj.StatAt(ctx, &other, pop("target", false), &vfs.StatOptions{})
				return err
			},
		},
		{
			name: "readlink",
			do: func() error {
				_, err := vfsObj.ReadlinkAt(ctx, &other, pop("link", false))
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records = nil
			if err := tc.do(); err != nil {
				t.Errorf("denied, but a host kernel permits it: %v", err)
			}
			if len(records) != 0 {
				t.Errorf("produced audit records, so it is mediated: %v", records)
			}
		})
	}

	// Positive control: opening the file IS mediated, so the fixture proves
	// something.
	t.Run("opening the file is still mediated", func(t *testing.T) {
		records = nil
		fd, err := vfsObj.OpenAt(ctx, &other, pop("target", false), &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if err == nil {
			fd.DecRef(ctx)
			t.Fatal("an open of a file the task does not own was permitted under an owner rule")
		}
		if len(records) == 0 {
			t.Error("the denial produced no record")
		}
	})
}

// TestRemovalIsMediatedByEntryPath pins that deleting a file or directory is
// mediated by a rule for the entry's own path, the way AppArmor's
// path_unlink and path_rmdir hooks do it, and not by the DAC write bit on the
// directory holding it. UnlinkAt was missed when create and rename were fixed,
// which left file removal unmediated on this filesystem.
func TestRemovalIsMediatedByEntryPath(t *testing.T) {
	confine.SetPolicy(map[string]*confine.Profile{
		"p": {Name: "p", Rules: []confine.Rule{
			{Pattern: "/scratch/", Perms: confine.ParsePerms("r")},
			{Pattern: "/scratch/removable", Perms: confine.ParsePerms("rw")},
			{Pattern: "/scratch/removable-dir/", Perms: confine.ParsePerms("rw")},
			{Pattern: "/scratch/kept", Perms: confine.ParsePerms("r")},
			{Pattern: "/scratch/kept-dir/", Perms: confine.ParsePerms("r")},
		}},
	})
	defer confine.SetPolicy(nil)

	baseCtx := contexttest.Context(t)
	root := auth.CredentialsFromContext(baseCtx)
	// Deleting an entry pins and releases the mount namespace, so the
	// context must carry one, unlike the read-only tests above.
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(baseCtx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(baseCtx, root, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOpts{MountPath: "/scratch"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("mounting tmpfs: %v", err)
	}
	ctx := vfs.WithMountNamespace(baseCtx, mntns)
	mntRoot := mntns.Root(ctx)
	defer func() {
		mntRoot.DecRef(ctx)
		mntns.DecRef(ctx)
	}()

	pop := func(name string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: mntRoot, Start: mntRoot, Path: fspath.Parse(name)}
	}
	for _, f := range []string{"removable", "kept"} {
		if err := vfsObj.MknodAt(ctx, root, pop(f), &vfs.MknodOptions{Mode: linux.ModeRegular | 0644}); err != nil {
			t.Fatalf("MknodAt(%q): %v", f, err)
		}
	}
	for _, d := range []string{"removable-dir", "kept-dir"} {
		if err := vfsObj.MkdirAt(ctx, root, pop(d), &vfs.MkdirOptions{Mode: 0755}); err != nil {
			t.Fatalf("MkdirAt(%q): %v", d, err)
		}
	}

	confined := *root
	confined.ConfinementProfile = "p"

	// A file with only 'r' must not be removable; one with 'w' must be.
	if err := vfsObj.UnlinkAt(ctx, &confined, pop("kept")); err == nil {
		t.Error("unlink of a read-only entry was permitted; removal is not being mediated by the entry's path")
	}
	if err := vfsObj.UnlinkAt(ctx, &confined, pop("removable")); err != nil {
		t.Errorf("unlink of a writable entry was denied: %v", err)
	}
	// The same for directories, whose rules carry the trailing slash.
	if err := vfsObj.RmdirAt(ctx, &confined, pop("kept-dir")); err == nil {
		t.Error("rmdir of a read-only directory was permitted")
	}
	if err := vfsObj.RmdirAt(ctx, &confined, pop("removable-dir")); err != nil {
		t.Errorf("rmdir of a writable directory was denied: %v", err)
	}
}
