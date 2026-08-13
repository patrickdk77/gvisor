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

// Benchmarks of the cost in-sandbox confinement adds to a filesystem
// operation. Each one comes as a pair: the Unconfined half runs with no policy
// installed and a task in no profile, which is what the operation costs today,
// and the Confined half runs the same operation under a profile that permits
// it. The difference is what mediation costs.
//
// The mediated cost of an operation is the path the engine is given plus the
// check itself, and the path is built by walking the dentry to the filesystem
// root, so the Open benchmarks vary the depth of the file.
//
// How a check scales with the size of a profile is measured in
// pkg/sentry/confine; the profile here is a small one, so that what these
// benchmarks show is the fixed cost of mediating an operation.
//
// Reading metadata is deliberately not mediated (see
// TestMetadataReadsAreNotMediated), so there is no stat benchmark here: it
// would measure a pair with nothing between them.

package tmpfs

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	// confineBenchMount is where the benchmark's tmpfs is mounted, which
	// is the path the profile's rules are written against.
	confineBenchMount = "/scratch"

	// confineBenchProfile is the profile a confined benchmark enters.
	confineBenchProfile = "bench"

	// confineBenchEntries is how many entries the directory that is listed
	// holds.
	confineBenchEntries = 1024
)

// confineBenchDepths are the numbers of directories between the mount root and
// the file that is opened. The path a check is given is built by walking to the
// filesystem root, so an operation deep in a tree has more of it to build.
var confineBenchDepths = []int{1, 8}

// confineBenchRules returns the profile's rules: the mount and everything
// under it, plus unrelated rules of the shapes a real profile uses, so that the
// automaton is not unrepresentatively small.
func confineBenchRules() []confine.Rule {
	rules := []confine.Rule{
		{
			Pattern: confineBenchMount + "/",
			Perms:   confine.ParsePerms("r"),
		},
		{
			Pattern: confineBenchMount + "/**",
			Perms:   confine.ParsePerms("rwmlk"),
		},
	}
	for i := 0; i < 128; i++ {
		site := fmt.Sprintf("site%03d.example", i)
		rules = append(rules, confine.Rule{
			Pattern: "/var/www/vhosts/s/i/" + site + "/www/**",
			Perms:   confine.ParsePerms("rw"),
			Owner:   true,
		})
	}
	return rules
}

// confineBenchFixture is the mount one benchmark runs against.
type confineBenchFixture struct {
	// ctx carries a mount namespace, which UnlinkAt() needs.
	ctx context.Context

	vfsObj *vfs.VirtualFilesystem
	root   vfs.VirtualDentry

	// creds are the credentials the measured operations run with, which
	// are confined only if the benchmark measures mediation.
	creds *auth.Credentials

	// unconfined are credentials that never carry a profile, used to build
	// the fixture so that only the measured operation is mediated.
	unconfined *auth.Credentials
}

// newConfineBenchFixture mounts a tmpfs and, if confined is set, installs the
// policy and enters its profile.
func newConfineBenchFixture(
	b *testing.B,
	confined bool,
) (*confineBenchFixture, func()) {
	ctx := contexttest.Context(b)
	unconfined := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newConfinedTmpfs(ctx, confineBenchMount)
	if err != nil {
		b.Fatalf("newConfinedTmpfs: %v", err)
	}
	// UnlinkAt() takes the mount namespace from the context and
	// contexttest provides none, which would leave it nil. The namespace
	// only decides whether the file being removed is a mount point, and
	// nothing here mounts on one, so a second namespace on the same
	// VirtualFilesystem serves; vfs.WithMountNamespace() hands out a
	// reference per lookup, as a task's context does.
	mntns, err := vfsObj.NewMountNamespace(ctx, unconfined, "", "tmpfs",
		&vfs.MountOptions{}, nil)
	if err != nil {
		cleanup()
		b.Fatalf("creating a mount namespace: %v", err)
	}
	f := &confineBenchFixture{
		ctx:        vfs.WithMountNamespace(ctx, mntns),
		vfsObj:     vfsObj,
		root:       root,
		creds:      unconfined,
		unconfined: unconfined,
	}
	if confined {
		confine.SetPolicy(map[string]*confine.Profile{
			confineBenchProfile: {
				Name:  confineBenchProfile,
				Rules: confineBenchRules(),
			},
		})
		creds := unconfined.Fork()
		creds.ConfinementProfile = confineBenchProfile
		f.creds = creds
	}
	return f, func() {
		confine.SetPolicy(nil)
		mntns.DecRef(ctx)
		cleanup()
	}
}

// pop returns a PathOperation for a path relative to the mount root.
func (f *confineBenchFixture) pop(path string) *vfs.PathOperation {
	return &vfs.PathOperation{
		Root:  f.root,
		Start: f.root,
		Path:  fspath.Parse(path),
	}
}

// mkdirs creates depth nested directories under the mount root while
// unconfined. It returns the innermost one and the prefix its path adds to a
// path relative to the mount root. The caller must DecRef the dentry.
func (f *confineBenchFixture) mkdirs(
	b *testing.B,
	depth int,
) (vfs.VirtualDentry, string) {
	var prefix strings.Builder
	vd := f.root
	vd.IncRef()
	for i := 1; i <= depth; i++ {
		name := fmt.Sprintf("%d", i)
		pop := &vfs.PathOperation{
			Root:  f.root,
			Start: vd,
			Path:  fspath.Parse(name),
		}
		err := f.vfsObj.MkdirAt(f.ctx, f.unconfined, pop,
			&vfs.MkdirOptions{Mode: 0755})
		if err != nil {
			vd.DecRef(f.ctx)
			b.Fatalf("mkdir %q: %v", name, err)
		}
		next, err := f.vfsObj.GetDentryAt(f.ctx, f.unconfined, pop,
			&vfs.GetDentryOptions{})
		if err != nil {
			vd.DecRef(f.ctx)
			b.Fatalf("walking to %q: %v", name, err)
		}
		vd.DecRef(f.ctx)
		vd = next
		prefix.WriteString(name)
		prefix.WriteByte('/')
	}
	return vd, prefix.String()
}

// benchmarkOpen measures opening and closing a file that already exists, which
// is the operation a confined workload performs most.
func benchmarkOpen(b *testing.B, confined bool) {
	for _, depth := range confineBenchDepths {
		b.Run(fmt.Sprintf("depth%d", depth), func(b *testing.B) {
			b.ReportAllocs()
			f, cleanup := newConfineBenchFixture(b, confined)
			defer cleanup()

			dir, prefix := f.mkdirs(b, depth)
			const name = "file"
			err := f.vfsObj.MknodAt(f.ctx, f.unconfined,
				&vfs.PathOperation{
					Root:  f.root,
					Start: dir,
					Path:  fspath.Parse(name),
				},
				&vfs.MknodOptions{
					Mode: linux.ModeRegular | 0644,
				})
			dir.DecRef(f.ctx)
			if err != nil {
				b.Fatalf("mknod %q: %v", name, err)
			}
			path := prefix + name
			pop := f.pop(path)
			opts := &vfs.OpenOptions{Flags: linux.O_RDONLY}

			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fd, err := f.vfsObj.OpenAt(f.ctx, f.creds, pop,
					opts)
				if err != nil {
					b.Fatalf("open(%q): %v", path, err)
				}
				fd.DecRef(f.ctx)
			}
			// Don't include deferred cleanup in benchmark time.
			b.StopTimer()
		})
	}
}

func BenchmarkTmpfsOpenUnconfined(b *testing.B) {
	benchmarkOpen(b, false /* confined */)
}

func BenchmarkTmpfsOpenConfined(b *testing.B) {
	benchmarkOpen(b, true /* confined */)
}

// benchmarkCreateRemove measures creating a file and removing it again.
//
// Only the create is mediated: it is checked against the new file's own path,
// while UnlinkAt() carries no confinement check, so the difference between the
// pair is the cost of mediating the create.
func benchmarkCreateRemove(b *testing.B, confined bool) {
	b.ReportAllocs()
	f, cleanup := newConfineBenchFixture(b, confined)
	defer cleanup()

	const name = "created"
	pop := f.pop(name)
	opts := &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	}

	runtime.GC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fd, err := f.vfsObj.OpenAt(f.ctx, f.creds, pop, opts)
		if err != nil {
			b.Fatalf("create(%q): %v", name, err)
		}
		fd.DecRef(f.ctx)
		if err := f.vfsObj.UnlinkAt(f.ctx, f.creds, pop); err != nil {
			b.Fatalf("unlink(%q): %v", name, err)
		}
	}
	// Don't include deferred cleanup in benchmark time.
	b.StopTimer()
}

func BenchmarkTmpfsCreateRemoveUnconfined(b *testing.B) {
	benchmarkCreateRemove(b, false /* confined */)
}

func BenchmarkTmpfsCreateRemoveConfined(b *testing.B) {
	benchmarkCreateRemove(b, true /* confined */)
}

// benchmarkListDir measures listing a directory of many entries, as opening it,
// reading every entry and closing it.
//
// Opening the directory is mediated, and asks for read on the path with the
// trailing slash a directory is matched with. Reading the entries is not
// mediated per entry, so the mediated part of the operation is a constant that
// the size of the directory does not change.
func benchmarkListDir(b *testing.B, confined bool) {
	b.ReportAllocs()
	f, cleanup := newConfineBenchFixture(b, confined)
	defer cleanup()

	// The directory and its entries are created unconfined, so that only
	// the listing below is mediated.
	const dirName = "dir"
	dirPop := f.pop(dirName)
	err := f.vfsObj.MkdirAt(f.ctx, f.unconfined, dirPop,
		&vfs.MkdirOptions{Mode: 0755})
	if err != nil {
		b.Fatalf("mkdir %q: %v", dirName, err)
	}
	dir, err := f.vfsObj.GetDentryAt(f.ctx, f.unconfined, dirPop,
		&vfs.GetDentryOptions{})
	if err != nil {
		b.Fatalf("walking to %q: %v", dirName, err)
	}
	defer dir.DecRef(f.ctx)
	for i := 0; i < confineBenchEntries; i++ {
		name := fmt.Sprintf("f%d", i)
		err := f.vfsObj.MknodAt(f.ctx, f.unconfined, &vfs.PathOperation{
			Root:  f.root,
			Start: dir,
			Path:  fspath.Parse(name),
		}, &vfs.MknodOptions{Mode: linux.ModeRegular | 0644})
		if err != nil {
			b.Fatalf("mknod %q: %v", name, err)
		}
	}

	var seen int
	cb := vfs.IterDirentsCallbackFunc(func(vfs.Dirent) error {
		seen++
		return nil
	})
	// "." and ".." are listed too.
	want := confineBenchEntries + 2
	opts := &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	}

	runtime.GC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fd, err := f.vfsObj.OpenAt(f.ctx, f.creds, dirPop, opts)
		if err != nil {
			b.Fatalf("open(%q): %v", dirName, err)
		}
		seen = 0
		err = fd.IterDirents(f.ctx, cb)
		fd.DecRef(f.ctx)
		if err != nil {
			b.Fatalf("listing %q: %v", dirName, err)
		}
		if seen != want {
			b.Fatalf("listed %d entries, want %d", seen, want)
		}
	}
	// Don't include deferred cleanup in benchmark time.
	b.StopTimer()
}

func BenchmarkTmpfsListDirUnconfined(b *testing.B) {
	benchmarkListDir(b, false /* confined */)
}

func BenchmarkTmpfsListDirConfined(b *testing.B) {
	benchmarkListDir(b, true /* confined */)
}
