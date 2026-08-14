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

package confine

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func TestMatchConfinePattern(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		path    string
		want    bool
	}{
		// '*' stays within a path component.
		{"/var/www/*", "/var/www/site", true},
		{"/var/www/*", "/var/www/site/index.php", false},
		// '**' crosses components, but a wildcard that is a whole
		// component needs at least one character: apparmor_parser
		// compiles "/var/www/**" to "/var/www/[^/\x00][^\x00]*", so it
		// does not cover "/var/www/" itself. A rule for the directory is
		// written with the trailing slash instead.
		{"/var/www/**", "/var/www/a/b/c.php", true},
		{"/var/www/**", "/var/www/", false},
		{"/var/www/**", "/var/www//a", false},
		{"/var/www/*", "/var/www/", false},
		// Only a whole-component wildcard has that minimum: in
		// "*.php" the star may still match nothing, which the parser
		// compiles to "[^/\x00]*\.php".
		{"/var/www/*.php", "/var/www/.php", true},
		{"/var/www/**.php", "/var/www/a/b.php", true},
		{"/var/www/?/?/*/**", "/var/www/p/a/site.com/www/index.php", true},
		{"/var/www/?/?/*/**", "/var/www/p/a/site.com", false},
		// '?' matches one character, never '/'.
		{"/etc/php?/conf.d/x.ini", "/etc/php8/conf.d/x.ini", true},
		{"/etc/php?/conf.d/x.ini", "/etc/php/conf.d/x.ini", false},
		{"/a/?", "/a/b", true},
		{"/a/?", "/a/", false},
		// Alternations.
		{"/etc/{php,php8}/x", "/etc/php8/x", true},
		{"/etc/{php,php8}/x", "/etc/php7/x", false},
		{"/{a,b}/{c,d}", "/b/d", true},
		// Character classes, including negation and ranges.
		{"/proc/[0-9]*/stat", "/proc/1234/stat", true},
		{"/proc/[0-9]*/stat", "/proc/self/stat", false},
		{"/proc/[^1-9]*", "/proc/self", true},
		{"/proc/[^1-9]*", "/proc/1", false},
		// Literals.
		{"/etc/passwd", "/etc/passwd", true},
		{"/etc/passwd", "/etc/passwd2", false},
		{"/etc/", "/etc/", true},
	} {
		if got := MatchPattern(tc.pattern, tc.path); got != tc.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestParsePerms(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Perm
	}{
		{"r", Read},
		// apparmor_parser maps 'w' to AA_MAY_WRITE|AA_MAY_APPEND.
		{"rw", Read | Write | Append},
		{"rwkmlix", Read | Write | Append | Lock | Mmap | Link | Exec},
		{"ix", Exec},
		{"rk", Read | Lock},
		{"a", Append},
	} {
		if got := ParsePerms(tc.in); got != tc.want {
			t.Errorf("ParsePerms(%q) = %b, want %b", tc.in, got, tc.want)
		}
	}
}

// TestCheckConfinement covers the rule semantics that matter for a
// multi-tenant profile: an allow list, owner-qualified rules, non-owner rules
// in the same subtree, deny precedence, and per-permission granularity.
func TestCheckConfinement(t *testing.T) {
	const (
		siteUID  = auth.KUID(1000)
		otherUID = auth.KUID(2000)
	)
	SetPolicy(map[string]*Profile{
		"cageweb": {
			Name: "cageweb",
			Rules: []Rule{
				// Site content: only the owner, but full access.
				{Pattern: "/var/www/vhosts/?/?/*/**", Perms: ParsePerms("rwkmlix"), Owner: true},
				// Shared trees: any user may read.
				{Pattern: "/var/www/vhosts/assets/**", Perms: ParsePerms("rk")},
				// Read-only system files.
				{Pattern: "/etc/**", Perms: ParsePerms("r")},
				// An explicit prohibition that overrides the above.
				{Pattern: "/etc/apache2/**", Perms: ParsePerms("rwlkx"), Deny: true},
				// Directory rules, as profiles write them.
				{Pattern: "/tmp/**", Perms: ParsePerms("rwmlk")},
				{Pattern: "/etc/php8/", Perms: ParsePerms("r")},
				// /tmp is writable but grants no 'x', as profiles do
				// to prevent dropping and running a binary.
				{Pattern: "/tmp/**", Perms: ParsePerms("rwmlk")},
				// Executables the profile permits running.
				{Pattern: "/usr/bin/*", Perms: ParsePerms("ixr")},
			},
		},
	})
	defer SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.EffectiveKUID = siteUID
	creds.ConfinementProfile = "cageweb"

	for _, tc := range []struct {
		name    string
		path    string
		ats     vfs.AccessTypes
		mode    linux.FileMode
		kuid    auth.KUID
		wantErr bool
	}{
		{
			name: "owner may write own site file",
			path: "/var/www/vhosts/p/a/site.com/www/index.php",
			ats:  vfs.MayWrite, mode: 0644, kuid: siteUID,
		},
		{
			name: "non-owner may not read another site's file",
			path: "/var/www/vhosts/p/a/other.com/www/wp-config.php",
			ats:  vfs.MayRead, mode: 0644, kuid: otherUID, wantErr: true,
		},
		{
			name: "non-owner may read a shared tree the profile grants",
			path: "/var/www/vhosts/assets/shared.html",
			ats:  vfs.MayRead, mode: 0644, kuid: otherUID,
		},
		{
			name: "shared tree grants no write, even to the owner",
			path: "/var/www/vhosts/assets/shared.html",
			ats:  vfs.MayWrite, mode: 0644, kuid: siteUID, wantErr: true,
		},
		{
			name: "read-only rule does not grant write",
			path: "/etc/php8/php.ini",
			ats:  vfs.MayWrite, mode: 0644, kuid: 0, wantErr: true,
		},
		{
			name: "read-only rule grants read regardless of owner",
			path: "/etc/php8/php.ini",
			ats:  vfs.MayRead, mode: 0644, kuid: 0,
		},
		{
			name: "deny rule overrides a matching allow rule",
			path: "/etc/apache2/apache2.conf",
			ats:  vfs.MayRead, mode: 0644, kuid: 0, wantErr: true,
		},
		{
			// The escalation path: a profile granting rw but not x on
			// /tmp must not permit executing a dropped binary.
			name: "exec from a no-exec directory is denied",
			path: "/tmp/dropped-binary",
			ats:  vfs.MayExec, mode: 0755, kuid: siteUID, wantErr: true,
		},
		{
			name: "writing under /tmp is permitted",
			path: "/tmp/my-test-file",
			ats:  vfs.MayWrite, mode: 0644, kuid: siteUID,
		},
		{
			name: "creating a file needs write on the parent directory",
			path: "/tmp/",
			ats:  vfs.MayWrite, mode: linux.ModeDirectory | 01777, kuid: 0,
		},
		{
			name: "exec of a permitted binary is allowed",
			path: "/usr/bin/id",
			ats:  vfs.MayExec, mode: 0755, kuid: 0,
		},
		{
			name: "exec of a binary outside any x rule is denied",
			path: "/usr/lib/openssh/sftp-server",
			ats:  vfs.MayExec, mode: 0755, kuid: 0, wantErr: true,
		},
		{
			name: "path no rule matches is denied",
			path: "/srv/secret",
			ats:  vfs.MayRead, mode: 0644, kuid: siteUID, wantErr: true,
		},
		{
			// AppArmor does not mediate traversal, and gVisor checks
			// MayExec on every directory it walks, so an unlisted
			// ancestor must not deny the access.
			name: "directory traversal is not mediated",
			path: "/srv/no/rule/here",
			ats:  vfs.MayExec, mode: linux.ModeDirectory | 0755, kuid: 0,
		},
		{
			name: "listing a directory with no matching rule is denied",
			path: "/srv/secret-dir/",
			ats:  vfs.MayRead, mode: linux.ModeDirectory | 0755, kuid: 0, wantErr: true,
		},
		{
			// A whole-component "**" needs at least one character, so
			// "/tmp/** rw" does not cover "/tmp/" itself; the
			// profile in this test names the directory separately.
			name: "a ** rule does not cover the directory itself",
			path: "/tmp/",
			ats:  vfs.MayRead, mode: linux.ModeDirectory | 0755, kuid: 0, wantErr: true,
		},
		{
			name: "a directory rule written with a trailing slash matches",
			path: "/etc/php8/",
			ats:  vfs.MayRead, mode: linux.ModeDirectory | 0755, kuid: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(bgCtx, creds, OpFperm, tc.path, tc.ats, tc.mode, tc.kuid)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Check(%q, %v) error = %v, wantErr %v", tc.path, tc.ats, err, tc.wantErr)
			}
		})
	}
}

// TestOwnerRevalidation covers the owner-rule revalidation that keeps a shared
// gofer mount from denying against a stale owner. When an owner rule is the
// sole reason an access would be denied, the engine consults the revalidate
// hook for a fresh owner before denying; if the fresh owner matches the
// accessor, the access is allowed, and no spurious DENIED record is emitted.
func TestOwnerRevalidation(t *testing.T) {
	const siteUID = auth.KUID(48559)
	SetPolicy(map[string]*Profile{
		"p": {Name: "p", Rules: []Rule{
			// Owner-only, like the production site-content rule. No
			// non-owner rule covers this path, so the only way to allow
			// is for the file to be owned by the accessor.
			{Pattern: "/data/**", Perms: ParsePerms("rwkmlix"), Owner: true},
		}},
	})
	defer SetPolicy(nil)
	defer SetTestLogSink(nil)

	creds := auth.NewAnonymousCredentials()
	creds.EffectiveKUID = siteUID
	creds.ConfinementProfile = "p"

	const path = "/data/.lock.error404.log"
	for _, tc := range []struct {
		name string
		// cached is the owner the check first sees; fresh is what
		// revalidation returns (0 means no revalidation hook).
		cached, fresh auth.KUID
		wantErr       bool
		wantDenied    bool // a DENIED record was emitted
	}{
		{
			name: "stale root owner corrected to the accessor is allowed",
			// The cross-pod create window: cached owner is root, but the
			// file is really the site user's by the time we revalidate.
			cached: 0, fresh: siteUID, wantErr: false, wantDenied: false,
		},
		{
			name: "owner really not the accessor is denied",
			// Revalidation confirms a genuinely foreign owner.
			cached: 0, fresh: auth.KUID(1234), wantErr: true, wantDenied: true,
		},
		{
			name:   "accessor already owns it needs no revalidation",
			cached: siteUID, fresh: 0, wantErr: false, wantDenied: false,
		},
		{
			name:   "without a revalidation hook a stale owner still denies",
			cached: 0, fresh: 0, wantErr: true, wantDenied: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged []string
			SetTestLogSink(func(record string) { logged = append(logged, record) })
			var revalidate func() auth.KUID
			revalidated := false
			if tc.fresh != 0 {
				revalidate = func() auth.KUID { revalidated = true; return tc.fresh }
			}
			err := CheckOpenRevalidating(bgCtx, creds, path, vfs.MayRead, 0,
				0o644, tc.cached, revalidate)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("CheckOpenRevalidating = %v, wantErr %v", err, tc.wantErr)
			}
			var denied bool
			for _, r := range logged {
				if strings.Contains(r, `apparmor="DENIED"`) {
					denied = true
				}
			}
			if denied != tc.wantDenied {
				t.Errorf("emitted DENIED = %v, want %v (records: %v)", denied, tc.wantDenied, logged)
			}
			// The hook must not be consulted when the accessor already
			// owns the file: that is the common path and must stay
			// RPC-free.
			if tc.cached == siteUID && revalidated {
				t.Error("revalidated even though the accessor already owns the file")
			}
		})
	}
}

// TestCheckConfinementUndefinedProfile verifies that entering a profile the
// policy does not define denies access rather than leaving the task
// unconfined.
func TestCheckConfinementUndefinedProfile(t *testing.T) {
	SetPolicy(map[string]*Profile{})
	defer SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.ConfinementProfile = "nonexistent"
	if err := Check(bgCtx, creds, OpFperm, "/etc/passwd", vfs.MayRead, 0644, 0); err == nil {
		t.Error("Check with an undefined profile = nil, want error")
	}
}

func TestPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mountPath string
		names     []string
		isDir     bool
		want      string
	}{
		{
			name:  "root of the root filesystem",
			names: []string{""},
			isDir: true,
			want:  "/",
		},
		{
			name:  "file in the root filesystem",
			names: []string{"passwd", "etc", ""},
			want:  "/etc/passwd",
		},
		{
			name:  "directory gets a trailing slash",
			names: []string{"tmp", ""},
			isDir: true,
			want:  "/tmp/",
		},
		{
			// A submount's dentries only know their path within
			// the mount, so the mount's own path is prepended.
			name:      "file under a submount",
			mountPath: "/var/www",
			names:     []string{"index.html", "site", ""},
			want:      "/var/www/site/index.html",
		},
		{
			name:      "root of a submount is the mount point",
			mountPath: "/var/www",
			names:     []string{""},
			isDir:     true,
			want:      "/var/www/",
		},
		{
			name:      "trailing slash on the mount path is not doubled",
			mountPath: "/var/www/",
			names:     []string{"x", ""},
			want:      "/var/www/x",
		},
		{
			name:      "a mount at / is the same as no mount path",
			mountPath: "/",
			names:     []string{"bin", ""},
			isDir:     true,
			want:      "/bin/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Path(tc.mountPath, tc.names, tc.isDir); got != tc.want {
				t.Errorf("Path(%q, %v, %v) = %q, want %q", tc.mountPath, tc.names, tc.isDir, got, tc.want)
			}
		})
	}
}

// TestCheckPermsMmap covers the 'm' permission, which mmap(2) requests
// directly because it does not correspond to a vfs.AccessType.
func TestCheckPermsMmap(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"p": {Name: "p", Rules: []Rule{
			{Pattern: "/lib/**", Perms: ParsePerms("mr")},
			{Pattern: "/tmp/**", Perms: ParsePerms("rw")},
			{Pattern: "/opt/**", Perms: ParsePerms("rm"), Owner: true},
			{Pattern: "/opt/blocked", Perms: ParsePerms("m"), Deny: true},
		}},
	})
	defer SetPolicy(nil)

	const fileMode = linux.FileMode(0644)
	for _, tc := range []struct {
		name    string
		path    string
		kuid    auth.KUID
		wantErr bool
	}{
		{name: "granted by an m rule", path: "/lib/libc.so"},
		{
			// The reason this permission exists: a task denied 'x' on a
			// file it can write must not be able to run it by mapping it.
			name:    "readable and writable but not mappable",
			path:    "/tmp/payload",
			wantErr: true,
		},
		{name: "owner rule, owned", path: "/opt/mine", kuid: 1000},
		{name: "owner rule, not owned", path: "/opt/theirs", kuid: 1001, wantErr: true},
		{name: "deny rule wins", path: "/opt/blocked", kuid: 1000, wantErr: true},
		{name: "no matching rule", path: "/etc/shadow", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := auth.NewAnonymousCredentials()
			creds.EffectiveKUID = 1000
			creds.ConfinementProfile = "p"
			err := CheckPerms(bgCtx, creds, OpFperm, tc.path, Mmap, fileMode, tc.kuid)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("CheckPerms(%q, Mmap) = %v, wantErr %t", tc.path, err, tc.wantErr)
			}
		})
	}
}

// TestOpenPermsMatchUpstream covers the mapping Linux's
// aa_map_file_to_perms() does. apparmor_parser maps 'w' to
// AA_MAY_WRITE|AA_MAY_APPEND, so 'w' permits an append open; 'a' grants only
// append, so it does not permit a plain or truncating write.
func TestOpenPermsMatchUpstream(t *testing.T) {
	if p := ParsePerms("w"); p&Append == 0 {
		t.Errorf(`ParsePerms("w") = %v, want Append set`, p)
	}
	if p := ParsePerms("a"); p&Write != 0 {
		t.Errorf(`ParsePerms("a") = %v, want Write clear`, p)
	}

	SetPolicy(map[string]*Profile{
		"w": {Name: "w", Rules: []Rule{{Pattern: "/log", Perms: ParsePerms("w")}}},
		"a": {Name: "a", Rules: []Rule{{Pattern: "/log", Perms: ParsePerms("a")}}},
		"r": {Name: "r", Rules: []Rule{{Pattern: "/log", Perms: ParsePerms("r")}}},
	})
	defer SetPolicy(nil)
	const mode = linux.FileMode(0644)
	for _, tc := range []struct {
		name      string
		profile   string
		flags     uint32
		wantAllow bool
	}{
		{name: "a plain write needs w", profile: "w", wantAllow: true},
		{name: "a plain write is not an append", profile: "a", wantAllow: false},
		{name: "a plain write is not a read", profile: "r", wantAllow: false},
		{
			name: "w permits an append open", profile: "w",
			flags: linux.O_APPEND, wantAllow: true,
		},
		{
			name: "a permits an append open", profile: "a",
			flags: linux.O_APPEND, wantAllow: true,
		},
		{
			name: "r permits neither", profile: "r",
			flags: linux.O_APPEND, wantAllow: false,
		},
		{
			// O_TRUNC asks for 'w' again, so append alone is not
			// enough to truncate.
			name: "a does not permit a truncating append", profile: "a",
			flags: linux.O_APPEND | linux.O_TRUNC, wantAllow: false,
		},
		{
			name: "w permits a truncating append", profile: "w",
			flags: linux.O_APPEND | linux.O_TRUNC, wantAllow: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := auth.NewAnonymousCredentials()
			creds.ConfinementProfile = tc.profile
			err := CheckOpen(bgCtx, creds, "/log", vfs.MayWrite, tc.flags, mode, auth.KUID(0))
			if gotAllow := err == nil; gotAllow != tc.wantAllow {
				t.Errorf("allowed=%t, want %t (err=%v)", gotAllow, tc.wantAllow, err)
			}
		})
	}
}

func TestCheckChangeProfile(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"docker-hosted": {
			Name: "docker-hosted",
			ChangeProfile: []ChangeRule{
				{Pattern: "cage*"},
				{Pattern: "/usr/bin/cage*"},
				// A deny rule overrides the allow above it.
				{Pattern: "cageroot", Deny: true},
			},
		},
		"cageweb":           {Name: "cageweb"},
		"/usr/bin/cagebash": {Name: "/usr/bin/cagebash"},
		"unrelated":         {Name: "unrelated"},
		"anything": {
			Name:          "anything",
			ChangeProfile: []ChangeRule{{Pattern: "**"}},
		},
	})
	defer SetPolicy(nil)

	for _, tc := range []struct {
		name    string
		from    string
		to      string
		wantErr bool
	}{
		{
			// What Apache's suexec does after init is confined.
			name: "a permitted target",
			from: "docker-hosted",
			to:   "cageweb",
		},
		{name: "a permitted path-named target", from: "docker-hosted", to: "/usr/bin/cagebash"},
		{name: "a target no rule names", from: "docker-hosted", to: "unrelated", wantErr: true},
		{
			// deny wins over the "cage*" allow rule.
			name:    "a target a deny rule names",
			from:    "docker-hosted",
			to:      "cageroot",
			wantErr: true,
		},
		{name: "unconfined may enter any profile", from: "", to: "cageweb"},
		{name: "a bare change_profile permits any target", from: "anything", to: "unrelated"},
		{name: "entering the same profile is a no-op", from: "cageweb", to: "cageweb"},
		{
			// Would leave the task denied every access.
			name:    "an undefined target",
			from:    "docker-hosted",
			to:      "cagetypo",
			wantErr: true,
		},
		{
			// A confined task must never reach a weaker profile by
			// way of one with no change_profile rules.
			name:    "a profile with no change_profile rules",
			from:    "cageweb",
			to:      "unrelated",
			wantErr: true,
		},
		{name: "a task in an undefined profile", from: "gone", to: "cageweb", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckChangeProfile(bgCtx, tc.from, tc.to)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("CheckChangeProfile(%q, %q) = %v, wantErr %t", tc.from, tc.to, err, tc.wantErr)
			}
		})
	}
}

// TestTransitionOnExec covers the profile a task enters when it execs, which is
// decided by the exec rules of the profile it is in.
func TestTransitionOnExec(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"outer": {Name: "outer", ExecRules: []ExecRule{
			// What the "file" rule class grants: exec with no
			// transition modifier.
			{Pattern: "/**"},
			{Pattern: "/bin/inherit", Mode: ExecInherit},
			{Pattern: "/bin/unconfined", Mode: ExecUnconfined},
			{Pattern: "/bin/named", Mode: ExecProfile, Target: "cage"},
			{Pattern: "/bin/missing", Mode: ExecProfile, Target: "nosuch"},
			{Pattern: "/bin/bare", Mode: ExecProfile},
			{Pattern: "/bin/kid", Mode: ExecChild, Target: "kid"},
			{Pattern: "/bin/nokid", Mode: ExecChild, Target: "nokid"},
		}},
		"cage":        {Name: "cage"},
		"outer//kid":  {Name: "outer//kid"},
		"/bin/bare":   {Name: "/bin/bare"},
		"/bin/attach": {Name: "/bin/attach"},
		"empty":       {Name: "empty"},
	})
	defer SetPolicy(nil)
	auth.SetExecConfinementProfiles(map[string]string{
		"/bin/bare":   "/bin/bare",
		"/bin/attach": "/bin/attach",
	})
	defer auth.SetExecConfinementProfiles(nil)

	for _, tc := range []struct {
		name    string
		from    string
		path    string
		want    string
		wantErr bool
	}{
		{
			// A path-named profile attaches even though the task is
			// already confined: before this, a confined task kept
			// its own profile and the cage was never entered.
			name: "no modifier enters a path-named profile",
			from: "outer",
			path: "/bin/attach",
			want: "/bin/attach",
		},
		{
			name: "no modifier and no path-named profile inherits",
			from: "outer",
			path: "/bin/other",
			want: "outer",
		},
		{name: "ix inherits", from: "outer", path: "/bin/inherit", want: "outer"},
		{
			// The one way out of a profile, and only because the
			// profile asks for it.
			name: "ux runs unconfined",
			from: "outer",
			path: "/bin/unconfined",
			want: "",
		},
		{name: "px enters the named profile", from: "outer", path: "/bin/named", want: "cage"},
		{name: "px with no target uses the executable's profile", from: "outer", path: "/bin/bare", want: "/bin/bare"},
		{
			// Running in the wrong profile is not a safe substitute
			// for the one the rule requires.
			name:    "px naming an undefined profile fails the exec",
			from:    "outer",
			path:    "/bin/missing",
			wantErr: true,
		},
		{name: "cx enters a child profile", from: "outer", path: "/bin/kid", want: "outer//kid"},
		{name: "cx naming an undefined child fails the exec", from: "outer", path: "/bin/nokid", wantErr: true},
		{
			name: "an unconfined task enters a path-named profile",
			from: "",
			path: "/bin/attach",
			want: "/bin/attach",
		},
		{name: "an unconfined task stays unconfined otherwise", from: "", path: "/bin/other", want: ""},
		{
			// A profile with no exec rules keeps its task confined.
			name: "a profile with no exec rules inherits",
			from: "empty",
			path: "/bin/attach",
			want: "empty",
		},
		{
			// A task in a profile the policy does not define is
			// denied everything and must not exec out of it.
			name: "an undefined profile is kept",
			from: "gone",
			path: "/bin/unconfined",
			want: "gone",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := TransitionOnExec(bgCtx, tc.from, tc.path)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("TransitionOnExec(bgCtx, %q, %q) error = %v, wantErr %t", tc.from, tc.path, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("TransitionOnExec(bgCtx, %q, %q) = %q, want %q", tc.from, tc.path, got, tc.want)
			}
		})
	}
}

// TestTransitionMostSpecificRuleWins checks that a specific rule overrides the
// catch-all one the "file" rule class produces.
func TestTransitionMostSpecificRuleWins(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"p": {Name: "p", ExecRules: []ExecRule{
			{Pattern: "/**"},
			{Pattern: "/bin/**", Mode: ExecUnconfined},
			{Pattern: "/bin/tool", Mode: ExecInherit},
		}},
	})
	defer SetPolicy(nil)
	for path, want := range map[string]string{
		"/bin/tool":  "p",
		"/bin/other": "",
		"/usr/thing": "p",
	} {
		got, _, err := TransitionOnExec(bgCtx, "p", path)
		if err != nil {
			t.Fatalf("TransitionOnExec(bgCtx, %q) = %v", path, err)
		}
		if got != want {
			t.Errorf("TransitionOnExec(bgCtx, %q) = %q, want %q", path, got, want)
		}
	}
}

// TestCreateMediatedByFilePath covers what AppArmor mediates when a file is
// created: a rule for the file's own path, not a write rule on the directory
// holding it. A profile that grants "owner /var/www/vhosts/sessions/?/?/*
// rwk" and only "r" on the directories above it must be able to create a
// session file, which is what PHP does.
func TestCreateMediatedByFilePath(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"cageweb": {Name: "cageweb", Rules: []Rule{
			{Pattern: "/var/www/vhosts/sessions/", Perms: ParsePerms("r")},
			{Pattern: "/var/www/vhosts/sessions/?/", Perms: ParsePerms("r")},
			{Pattern: "/var/www/vhosts/sessions/?/?/", Perms: ParsePerms("r")},
			{Pattern: "/var/www/vhosts/sessions/?/?/*", Perms: ParsePerms("rwk"), Owner: true},
		}},
	})
	defer SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.EffectiveKUID = 1000
	creds.ConfinementProfile = "cageweb"
	const sess = "/var/www/vhosts/sessions/q/4/sess_q453ond5ff7v6celijpb8duab8b5e0vf"

	// Writing the session file is permitted: the owner rule covers it. A file
	// being created has no mode yet, which must not make the check fail.
	if err := Check(bgCtx, creds, OpFperm, sess, vfs.MayWrite, linux.FileMode(0), auth.KUID(1000)); err != nil {
		t.Errorf("Check(%q, MayWrite) = %v, want nil", sess, err)
	}
	if err := Check(bgCtx, creds, OpFperm, sess, vfs.MayRead|vfs.MayWrite, linux.FileMode(0644), auth.KUID(1000)); err != nil {
		t.Errorf("Check(%q, MayRead|MayWrite) = %v, want nil", sess, err)
	}
	// A directory's write permission is not mediated at all: the kernel
	// requires it to create an entry, but AppArmor has no equivalent, so
	// requiring it here denied writes the profile allows.
	dir := "/var/www/vhosts/sessions/q/4/"
	if err := Check(bgCtx, creds, OpFperm, dir, vfs.MayWrite, linux.FileMode(linux.ModeDirectory|0777), auth.KUID(0)); err != nil {
		t.Errorf("Check(%q, MayWrite) = %v, want nil: a directory's write bit is not mediated", dir, err)
	}
	// Reading it is mediated, and the profile grants that.
	if err := Check(bgCtx, creds, OpFperm, dir, vfs.MayRead, linux.FileMode(linux.ModeDirectory|0777), auth.KUID(0)); err != nil {
		t.Errorf("Check(%q, MayRead) = %v, want nil", dir, err)
	}
	// Another user's session file is still denied by the owner rule.
	if err := Check(bgCtx, creds, OpFperm, sess, vfs.MayRead, linux.FileMode(0600), auth.KUID(1001)); err == nil {
		t.Error("reading another user's session file was permitted")
	}
}

// TestMmapReadOnlyNeedsNoM records that a read-only mapping is not mediated by
// 'm'. AppArmor's 'm' covers PROT_EXEC; gating on what a mapping could become
// through mprotect(2) instead demanded 'm' for every mapping of any readable
// file, so a profile granting only 'r' on /etc/ld.so.cache could not map it and
// glibc reported every library it should have found as missing.
func TestMmapReadOnlyNeedsNoM(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"p": {Name: "p", Rules: []Rule{
			{Pattern: "/etc/ld.so.cache", Perms: ParsePerms("r")},
			{Pattern: "/usr/share/zoneinfo/**", Perms: ParsePerms("r")},
			{Pattern: "/lib/**", Perms: ParsePerms("mr")},
		}},
	})
	defer SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.ConfinementProfile = "p"
	const mode = linux.FileMode(0644)

	// An executable mapping still requires 'm'.
	for _, path := range []string{"/etc/ld.so.cache", "/usr/share/zoneinfo/UTC"} {
		if err := CheckPerms(bgCtx, creds, OpFperm, path, Mmap, mode, auth.KUID(0)); err == nil {
			t.Errorf("CheckPerms(%q, Mmap) = nil, want a denial: the profile grants only r", path)
		}
		// Reading it is what the profile grants, and is what a read-only
		// mapping is mediated by.
		if err := Check(bgCtx, creds, OpFperm, path, vfs.MayRead, mode, auth.KUID(0)); err != nil {
			t.Errorf("Check(%q, MayRead) = %v, want nil", path, err)
		}
	}
	if err := CheckPerms(bgCtx, creds, OpFperm, "/lib/x86_64-linux-gnu/libc.so.6", Mmap, mode, auth.KUID(0)); err != nil {
		t.Errorf("CheckPerms(libc, Mmap) = %v, want nil: the profile grants m", err)
	}
}

// TestTransitionScrubsEnvironment covers the uppercase transition modifiers,
// which apparmor.d(5) defines as invoking "the Linux Kernel's unsafe_exec
// routines to scrub the environment, similar to setuid programs". The lowercase
// forms do not.
func TestTransitionScrubsEnvironment(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"p": {Name: "p", ExecRules: []ExecRule{
			{Pattern: "/bin/px", Mode: ExecProfile, Target: "cage"},
			{Pattern: "/bin/Px", Mode: ExecProfile, Target: "cage", Scrub: true},
			{Pattern: "/bin/cx", Mode: ExecChild, Target: "kid"},
			{Pattern: "/bin/Cx", Mode: ExecChild, Target: "kid", Scrub: true},
			{Pattern: "/bin/ux", Mode: ExecUnconfined},
			{Pattern: "/bin/Ux", Mode: ExecUnconfined, Scrub: true},
			{Pattern: "/bin/ix", Mode: ExecInherit},
		}},
		"cage":   {Name: "cage"},
		"p//kid": {Name: "p//kid"},
	})
	defer SetPolicy(nil)

	for path, wantScrub := range map[string]bool{
		"/bin/px": false,
		"/bin/Px": true,
		"/bin/cx": false,
		"/bin/Cx": true,
		"/bin/ux": false,
		"/bin/Ux": true,
		"/bin/ix": false,
	} {
		_, scrub, err := TransitionOnExec(bgCtx, "p", path)
		if err != nil {
			t.Errorf("TransitionOnExec(bgCtx, %q) = %v", path, err)
			continue
		}
		if scrub != wantScrub {
			t.Errorf("TransitionOnExec(bgCtx, %q) scrub = %t, want %t", path, scrub, wantScrub)
		}
	}
}

// TestCheckChangeHat covers aa_change_hat(3): a hat is a subprofile named
// "<profile>//^<hat>", entering one that does not exist is ENOENT when the
// profile defines other hats and EPERM when it defines none, and a child
// profile that is not a hat cannot be entered as one.
func TestCheckChangeHat(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"web":          {Name: "web"},
		"web//^upload": {Name: "web//^upload", IsHat: true},
		"web//^admin":  {Name: "web//^admin", IsHat: true},
		"web//child":   {Name: "web//child"},
		"plain":        {Name: "plain"},
		"plain//kid":   {Name: "plain//kid"},
	})
	defer SetPolicy(nil)

	for _, tc := range []struct {
		name    string
		from    string
		hat     string
		want    string
		wantErr error
	}{
		{name: "a declared hat", from: "web", hat: "upload", want: "web//^upload"},
		{name: "another declared hat", from: "web", hat: "admin", want: "web//^admin"},
		{
			// "The specified subprofile does not exist in this
			// profile but other hats are defined."
			name:    "an undeclared hat where others exist",
			from:    "web",
			hat:     "nope",
			wantErr: linuxerr.ENOENT,
		},
		{
			name:    "a profile with no hats at all",
			from:    "plain",
			hat:     "nope",
			wantErr: linuxerr.EPERM,
		},
		{
			// A child profile is not a hat.
			name:    "a child profile is not a hat",
			from:    "web",
			hat:     "child",
			wantErr: linuxerr.ENOENT,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckChangeHat(tc.from, tc.hat)
			if tc.wantErr != nil {
				if err == nil || err.Error() != tc.wantErr.Error() {
					t.Fatalf("CheckChangeHat(%q, %q) error = %v, want %v", tc.from, tc.hat, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckChangeHat(%q, %q) = %v", tc.from, tc.hat, err)
			}
			if got != tc.want {
				t.Errorf("CheckChangeHat(%q, %q) = %q, want %q", tc.from, tc.hat, got, tc.want)
			}
		})
	}
}

// TestDenyIsSilentUnlessAudited covers apparmor.d(5): a deny rule denies
// "without logging. Can be combined with 'audit' to enable logging." A denial
// with no matching rule is logged; one from an explicit deny rule is not, which
// is what a profile uses deny for.
func TestDenyIsSilentUnlessAudited(t *testing.T) {
	var logged []string
	SetTestLogSink(func(record string) {
		logged = append(logged, record)
	})
	defer SetTestLogSink(nil)

	SetPolicy(map[string]*Profile{
		"p": {Name: "p", Rules: []Rule{
			{Pattern: "/data/**", Perms: ParsePerms("rw")},
			{Pattern: "/data/quiet", Perms: ParsePerms("rw"), Deny: true},
			{Pattern: "/data/loud", Perms: ParsePerms("rw"), Deny: true, Audit: true},
		}},
	})
	defer SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.ConfinementProfile = "p"
	const mode = linux.FileMode(0644)

	for _, tc := range []struct {
		name    string
		path    string
		wantLog bool
	}{
		{name: "a plain deny rule is silent", path: "/data/quiet", wantLog: false},
		{name: "an audited deny rule logs", path: "/data/loud", wantLog: true},
		{name: "no matching rule logs", path: "/elsewhere", wantLog: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged = nil
			if err := Check(bgCtx, creds, OpFperm, tc.path, vfs.MayRead, mode, auth.KUID(0)); err == nil {
				t.Fatalf("Check(%q) = nil, want a denial", tc.path)
			}
			if gotLog := len(logged) != 0; gotLog != tc.wantLog {
				t.Errorf("Check(%q) logged %d lines, want logged=%t: %v", tc.path, len(logged), tc.wantLog, logged)
			}
		})
	}
}

// TestStackedLabel covers profile stacking: every profile of the label must
// permit an access, so a stacked label grants the intersection.
func TestStackedLabel(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"outer": {Name: "outer", Rules: []Rule{
			{Pattern: "/a", Perms: ParsePerms("rw")},
			{Pattern: "/both", Perms: ParsePerms("rw")},
		}},
		"inner": {Name: "inner", Rules: []Rule{
			{Pattern: "/b", Perms: ParsePerms("rw")},
			{Pattern: "/both", Perms: ParsePerms("r")},
		}},
	})
	defer SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.ConfinementProfile = StackLabel("outer", "inner")
	if got, want := creds.ConfinementProfile, "outer"+StackSeparator+"inner"; got != want {
		t.Fatalf("StackLabel = %q, want %q", got, want)
	}
	const mode = linux.FileMode(0644)
	for _, tc := range []struct {
		path      string
		ats       vfs.AccessTypes
		wantAllow bool
	}{
		// Only outer grants /a, so the stack does not.
		{path: "/a", ats: vfs.MayRead, wantAllow: false},
		// Only inner grants /b.
		{path: "/b", ats: vfs.MayRead, wantAllow: false},
		// Both grant reading /both.
		{path: "/both", ats: vfs.MayRead, wantAllow: true},
		// Only outer grants writing it, so the stack does not.
		{path: "/both", ats: vfs.MayWrite, wantAllow: false},
	} {
		err := Check(bgCtx, creds, OpFperm, tc.path, tc.ats, mode, auth.KUID(0))
		if gotAllow := err == nil; gotAllow != tc.wantAllow {
			t.Errorf("Check(%q, %v) allowed=%t, want %t", tc.path, tc.ats, gotAllow, tc.wantAllow)
		}
	}
	// Stacking a profile already in the label changes nothing.
	if got := StackLabel(creds.ConfinementProfile, "inner"); got != creds.ConfinementProfile {
		t.Errorf("StackLabel(%q, inner) = %q, want unchanged", creds.ConfinementProfile, got)
	}
}

// TestChangeProfileExecCondition covers "change_profile <exec> -> <target>":
// the rule governs only a transition accompanying an exec of a matching
// program, which is what aa_change_onexec(3) requests.
func TestChangeProfileExecCondition(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"outer": {Name: "outer", ChangeProfile: []ChangeRule{
			{Pattern: "cage*"},
			{Pattern: "cageroot", Deny: true, Exec: "/usr/bin/suexec"},
		}},
		"cageweb":  {Name: "cageweb"},
		"cageroot": {Name: "cageroot"},
	})
	defer SetPolicy(nil)

	for _, tc := range []struct {
		name    string
		to      string
		exec    string
		wantErr bool
	}{
		{name: "an allowed target", to: "cageweb", exec: "/usr/bin/suexec"},
		{
			// The deny rule names this exec, so it applies.
			name:    "a denied target with the named exec",
			to:      "cageroot",
			exec:    "/usr/bin/suexec",
			wantErr: true,
		},
		{
			// A different exec does not match the condition, so the
			// deny rule does not apply and the wildcard allows it.
			name: "a denied target with a different exec",
			to:   "cageroot",
			exec: "/usr/bin/other",
		},
		{
			// An immediate change accompanies no exec.
			name: "an immediate change",
			to:   "cageroot",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckChangeProfileOnExec(bgCtx, "outer", tc.to, tc.exec)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("CheckChangeProfileOnExec(outer, %q, %q) = %v, wantErr %t", tc.to, tc.exec, err, tc.wantErr)
			}
		})
	}
}

// TestKillModeViolation covers the kill flag, which is enforce mode plus
// termination: a denial carries the signal the task must be killed with, and
// error= still selects the errno the syscall returns.
func TestKillModeViolation(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"killer": {Name: "killer", Mode: ModeKill, Rules: []Rule{
			{Pattern: "/allowed", Perms: ParsePerms("r")},
		}},
		"signalled": {Name: "signalled", Mode: ModeKill,
			KillSignal: int32(linux.SIGTERM), Error: int32(unix.EPERM)},
		"enforcer": {Name: "enforcer", Mode: ModeEnforce},
		"noisy":    {Name: "noisy", Mode: ModeKill, Complain: true},
	})
	defer SetPolicy(nil)

	for _, tc := range []struct {
		name     string
		profile  string
		wantErr  error
		wantKill bool
		wantSig  int32
	}{
		{
			name:     "kill mode carries the default signal",
			profile:  "killer",
			wantErr:  linuxerr.EACCES,
			wantKill: true,
		},
		{
			name:     "kill.signal and error= are both honored",
			profile:  "signalled",
			wantErr:  linuxerr.EPERM,
			wantKill: true,
			wantSig:  int32(linux.SIGTERM),
		},
		{
			name:    "enforce mode does not kill",
			profile: "enforcer",
			wantErr: linuxerr.EACCES,
		},
		{
			name:    "complain overrides kill",
			profile: "noisy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := auth.NewAnonymousCredentials()
			creds.ConfinementProfile = tc.profile
			err := Check(bgCtx, creds, OpFperm, "/denied", vfs.MayRead, linux.FileMode(0644), auth.KUID(0))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Check() = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr.Error() {
				t.Fatalf("Check() = %v, want %v", err, tc.wantErr)
			}
			kill, gotKill := AsKillError(err)
			if gotKill != tc.wantKill {
				t.Fatalf("AsKillError(%v) = %t, want %t", err, gotKill, tc.wantKill)
			}
			if gotKill && kill.Signal != tc.wantSig {
				t.Errorf("kill signal = %d, want %d", kill.Signal, tc.wantSig)
			}
		})
	}
}

// TestAuditLogsAllowedAccess covers the audit qualifier, which apparmor.d(5)
// says "will force audit messages to be generated" for the rule it is on, and
// the profile-wide audit flag, which "causes all actions whether allowed or
// denied to be logged". Both the automaton and the rule walk must agree.
func TestAuditLogsAllowedAccess(t *testing.T) {
	var logged []string
	SetTestLogSink(func(record string) {
		logged = append(logged, record)
	})
	defer SetTestLogSink(nil)

	rules := []Rule{
		{Pattern: "/data/quiet", Perms: ParsePerms("rw")},
		{Pattern: "/data/loud", Perms: ParsePerms("rw"), Audit: true},
		{Pattern: "/data/mixed", Perms: ParsePerms("r")},
		{Pattern: "/data/mixed", Perms: ParsePerms("w"), Audit: true},
	}
	plain := &Profile{Name: "plain", Rules: rules}
	plain.index()
	auditAll := &Profile{Name: "auditAll", Rules: rules, Audit: true}
	auditAll.index()
	SetPolicy(map[string]*Profile{"plain": plain, "auditAll": auditAll})
	defer SetPolicy(nil)

	const mode = linux.FileMode(0644)
	for _, tc := range []struct {
		name    string
		profile string
		path    string
		access  vfs.AccessTypes
		wantLog bool
	}{
		{
			name: "a plain allow rule is silent", profile: "plain",
			path: "/data/quiet", access: vfs.MayRead, wantLog: false,
		},
		{
			name: "an audited allow rule logs", profile: "plain",
			path: "/data/loud", access: vfs.MayRead, wantLog: true,
		},
		{
			// The audit bits are per permission, so the audited
			// write rule must not make the read log.
			name: "audit is per permission", profile: "plain",
			path: "/data/mixed", access: vfs.MayRead, wantLog: false,
		},
		{
			name: "the audited permission logs", profile: "plain",
			path: "/data/mixed", access: vfs.MayWrite, wantLog: true,
		},
		{
			name: "the audit flag logs every access", profile: "auditAll",
			path: "/data/quiet", access: vfs.MayRead, wantLog: true,
		},
	} {
		for _, linear := range []bool{false, true} {
			name := tc.name
			if linear {
				name += " (rule walk)"
			}
			t.Run(name, func(t *testing.T) {
				profile := profileFor(tc.profile)
				if linear {
					profile.dfa.markFullForTest()
				}
				logged = nil
				creds := auth.NewAnonymousCredentials()
				creds.ConfinementProfile = tc.profile
				if err := Check(bgCtx, creds, OpFperm, tc.path, tc.access, mode, auth.KUID(0)); err != nil {
					t.Fatalf("Check(%q) = %v, want nil", tc.path, err)
				}
				if gotLog := len(logged) != 0; gotLog != tc.wantLog {
					t.Errorf("Check(%q) logged %d lines, want logged=%t: %v", tc.path, len(logged), tc.wantLog, logged)
				}
			})
		}
	}
}

// TestKillModeFollowsAuditing covers the coupling Linux has between killing and
// auditing: aa_audit_file() returns before reaching aa_audit(), which is where
// KILL_MODE turns a denial into a kill, when the denied permissions are all
// quieted by a deny rule. A silent deny rule therefore denies without killing,
// while a denial with no matching rule, an audited deny rule, or any deny rule
// in a profile flagged 'audit' does kill.
func TestKillModeFollowsAuditing(t *testing.T) {
	var logged []string
	SetTestLogSink(func(record string) {
		logged = append(logged, record)
	})
	defer SetTestLogSink(nil)

	rules := []Rule{
		{Pattern: "/data/**", Perms: ParsePerms("rw")},
		{Pattern: "/data/quiet", Perms: ParsePerms("rw"), Deny: true},
		{Pattern: "/data/loud", Perms: ParsePerms("rw"), Deny: true, Audit: true},
	}
	killer := &Profile{Name: "killer", Mode: ModeKill, Rules: rules}
	killer.index()
	auditAll := &Profile{Name: "auditAll", Mode: ModeKill, Audit: true, Rules: rules}
	auditAll.index()
	SetPolicy(map[string]*Profile{"killer": killer, "auditAll": auditAll})
	defer SetPolicy(nil)

	const mode = linux.FileMode(0644)
	for _, tc := range []struct {
		name     string
		profile  string
		path     string
		wantKill bool
		wantLog  bool
	}{
		{
			name:    "a silent deny rule denies without killing",
			profile: "killer", path: "/data/quiet",
			wantKill: false, wantLog: false,
		},
		{
			name:    "an audited deny rule kills",
			profile: "killer", path: "/data/loud",
			wantKill: true, wantLog: true,
		},
		{
			name:    "a denial with no matching rule kills",
			profile: "killer", path: "/elsewhere",
			wantKill: true, wantLog: true,
		},
		{
			// The audit flag defeats a deny rule's silence, so the
			// denial reaches the kill decision after all.
			name:    "the audit flag makes a silent deny rule kill",
			profile: "auditAll", path: "/data/quiet",
			wantKill: true, wantLog: true,
		},
	} {
		for _, linear := range []bool{false, true} {
			name := tc.name
			if linear {
				name += " (rule walk)"
			}
			t.Run(name, func(t *testing.T) {
				if linear {
					profileFor(tc.profile).dfa.markFullForTest()
				}
				logged = nil
				creds := auth.NewAnonymousCredentials()
				creds.ConfinementProfile = tc.profile
				err := Check(bgCtx, creds, OpFperm, tc.path, vfs.MayRead, mode, auth.KUID(0))
				if err == nil {
					t.Fatalf("Check(%q) = nil, want a denial", tc.path)
				}
				if _, gotKill := AsKillError(err); gotKill != tc.wantKill {
					t.Errorf("Check(%q) kills = %t, want %t", tc.path, gotKill, tc.wantKill)
				}
				if gotLog := len(logged) != 0; gotLog != tc.wantLog {
					t.Errorf("Check(%q) logged %d lines, want logged=%t: %v", tc.path, len(logged), tc.wantLog, logged)
				}
			})
		}
	}
}

// TestDefaultAllowDenyIsSilentUnlessAudited covers a default_allow profile,
// where a deny rule is the only thing that refuses. Silence and killing follow
// the same rules there as in an enforcing profile.
func TestDefaultAllowDenyIsSilentUnlessAudited(t *testing.T) {
	var logged []string
	SetTestLogSink(func(record string) {
		logged = append(logged, record)
	})
	defer SetTestLogSink(nil)

	rules := []Rule{
		{Pattern: "/data/quiet", Perms: ParsePerms("rw"), Deny: true},
		{Pattern: "/data/loud", Perms: ParsePerms("rw"), Deny: true, Audit: true},
	}
	inverted := &Profile{Name: "inverted", Mode: ModeDefaultAllow, Rules: rules}
	inverted.index()
	SetPolicy(map[string]*Profile{"inverted": inverted})
	defer SetPolicy(nil)

	const mode = linux.FileMode(0644)
	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
		wantLog bool
	}{
		{name: "a path no deny rule names is allowed", path: "/data/other"},
		{name: "a silent deny rule refuses quietly", path: "/data/quiet", wantErr: true},
		{name: "an audited deny rule logs", path: "/data/loud", wantErr: true, wantLog: true},
	} {
		for _, linear := range []bool{false, true} {
			name := tc.name
			if linear {
				name += " (rule walk)"
			}
			t.Run(name, func(t *testing.T) {
				if linear {
					profileFor("inverted").dfa.markFullForTest()
				}
				logged = nil
				creds := auth.NewAnonymousCredentials()
				creds.ConfinementProfile = "inverted"
				err := Check(bgCtx, creds, OpFperm, tc.path, vfs.MayRead, mode, auth.KUID(0))
				if gotErr := err != nil; gotErr != tc.wantErr {
					t.Errorf("Check(%q) = %v, wantErr %t", tc.path, err, tc.wantErr)
				}
				if gotLog := len(logged) != 0; gotLog != tc.wantLog {
					t.Errorf("Check(%q) logged %d lines, want logged=%t: %v", tc.path, len(logged), tc.wantLog, logged)
				}
			})
		}
	}
}

// TestAuditRecordFormat pins the audit record to the format Linux produces, so
// that the tools which already parse AppArmor records (libapparmor's
// aa_parse_record, aa-logprof and the rest) can read these. The fields and
// their order are aa_audit_msg()'s and file_audit_cb()'s; pid and comm are
// absent because the engine is reached with credentials rather than a task.
func TestAuditRecordFormat(t *testing.T) {
	var logged []string
	SetTestLogSink(func(record string) {
		logged = append(logged, record)
	})
	defer SetTestLogSink(nil)

	SetPolicy(map[string]*Profile{
		"web": {Name: "web", Rules: []Rule{
			{Pattern: "/srv/**", Perms: ParsePerms("r")},
			{Pattern: "/srv/audited", Perms: ParsePerms("r"), Audit: true},
		}},
		"strict": {Name: "strict", Mode: ModeKill, Error: int32(unix.EPERM)},
		"noisy":  {Name: "noisy", Complain: true},
	})
	defer SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.EffectiveKUID = auth.KUID(33)

	// The engine resolves pid and comm through this hook, installed by the
	// kernel package in the sandbox. The records below assert their position.
	SetTaskInfoFunc(func(context.Context) (int32, string, bool) {
		return 1234, "cron", true
	})
	defer SetTaskInfoFunc(nil)

	for _, tc := range []struct {
		name    string
		profile string
		check   func(creds *auth.Credentials) error
		want    string
	}{
		{
			name:    "a denial with no matching rule",
			profile: "web",
			check: func(c *auth.Credentials) error {
				return CheckPerms(bgCtx, c, OpOpen, "/etc/shadow", Read, linux.FileMode(0640), auth.KUID(0))
			},
			want: `apparmor="DENIED" operation="open" class="file" profile="web" name="/etc/shadow" pid=1234 comm="cron" requested_mask="r" denied_mask="r" fsuid=33 ouid=0`,
		},
		{
			name:    "an audited rule that permitted the access",
			profile: "web",
			check: func(c *auth.Credentials) error {
				return CheckPerms(bgCtx, c, OpGetattr, "/srv/audited", Read, linux.FileMode(0644), auth.KUID(33))
			},
			want: `apparmor="AUDIT" operation="getattr" class="file" profile="web" name="/srv/audited" pid=1234 comm="cron" requested_mask="r" fsuid=33 ouid=33`,
		},
		{
			name:    "a kill-mode denial with a custom errno",
			profile: "strict",
			check: func(c *auth.Credentials) error {
				return CheckPerms(bgCtx, c, OpChmod, "/srv/x", Write, linux.FileMode(0644), auth.KUID(0))
			},
			want: `apparmor="KILLED" operation="chmod" class="file" profile="strict" name="/srv/x" pid=1234 comm="cron" requested_mask="w" denied_mask="w" fsuid=33 ouid=0`,
		},
		{
			name:    "a complain-mode profile reports ALLOWED",
			profile: "noisy",
			check: func(c *auth.Credentials) error {
				return CheckPerms(bgCtx, c, OpFlock, "/srv/x", Lock, linux.FileMode(0644), auth.KUID(0))
			},
			want: `apparmor="ALLOWED" operation="file_lock" class="file" profile="noisy" name="/srv/x" pid=1234 comm="cron" requested_mask="k" denied_mask="k" fsuid=33 ouid=0`,
		},
		{
			name:    "a link record names the target",
			profile: "web",
			check: func(c *auth.Credentials) error {
				return CheckLink(bgCtx, c, "/srv/link", "/srv/orig", linux.FileMode(0644), auth.KUID(0))
			},
			want: `apparmor="DENIED" operation="link" class="file" profile="web" name="/srv/link" pid=1234 comm="cron" requested_mask="l" denied_mask="l" fsuid=33 ouid=0 target="/srv/orig"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged = nil
			c := *creds
			c.ConfinementProfile = tc.profile
			if err := tc.check(&c); err == nil && tc.profile != "noisy" && tc.profile != "web" {
				t.Fatalf("check() = nil, want a denial")
			}
			if len(logged) != 1 {
				t.Fatalf("logged %d records, want 1: %v", len(logged), logged)
			}
			if logged[0] != tc.want {
				t.Errorf("record =\n\t%s\nwant\n\t%s", logged[0], tc.want)
			}
		})
	}
}

// bgCtx is the context the record-format tests run under. They run outside a
// task, so pid and comm come from the fake resolver each test installs.
var bgCtx = context.Background()

// TestAuditRecordMatchesRealKernel holds this implementation to records
// captured from a live kernel, not to strings derived from this code.
// testdata/audit_reference.tsv holds each record together with the inputs that
// produced it; its header documents how to regenerate it. If this test and the
// implementation ever disagree, the implementation is wrong.
//
// It has already earned its keep once: the kernel hex-encodes an unprintable
// name in UPPERCASE, and the first version of auditString() used lowercase.
func TestAuditRecordMatchesRealKernel(t *testing.T) {
	data, err := os.ReadFile("testdata/audit_reference.tsv")
	if err != nil {
		t.Fatalf("reading the captured records: %v", err)
	}
	var logged []string
	SetTestLogSink(func(record string) { logged = append(logged, record) })
	defer SetTestLogSink(nil)
	defer SetTaskInfoFunc(nil)
	defer SetPolicy(nil)

	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 9 {
			t.Fatalf("malformed reference line (%d fields): %q", len(f), line)
		}
		profile, op, path, comm, mask, want := f[0], f[1], f[2], f[4], f[5], f[8]
		if mask != "r" {
			t.Fatalf("only requested_mask=r captures exist; got %q", mask)
		}
		pid, err := strconv.Atoi(f[3])
		if err != nil {
			t.Fatalf("bad pid %q: %v", f[3], err)
		}
		fsuid, err := strconv.Atoi(f[6])
		if err != nil {
			t.Fatalf("bad fsuid %q: %v", f[6], err)
		}
		ouid, err := strconv.Atoi(f[7])
		if err != nil {
			t.Fatalf("bad ouid %q: %v", f[7], err)
		}

		SetTaskInfoFunc(func(context.Context) (int32, string, bool) {
			return int32(pid), comm, true
		})
		// The captured profile grants nothing for the captured paths, so an
		// empty profile reproduces each denial.
		SetPolicy(map[string]*Profile{profile: {Name: profile}})
		creds := auth.NewAnonymousCredentials()
		creds.EffectiveKUID = auth.KUID(fsuid)
		creds.ConfinementProfile = profile

		logged = nil
		if err := CheckPerms(bgCtx, creds, Op(op), path, Read, linux.FileMode(0644), auth.KUID(ouid)); err == nil {
			t.Fatalf("CheckPerms(%q) = nil, want the captured denial", path)
		}
		if len(logged) != 1 {
			t.Fatalf("logged %d records for %q, want 1: %v", len(logged), path, logged)
		}
		if logged[0] != want {
			t.Errorf("record differs from the real kernel's:\n got  %s\n want %s", logged[0], want)
		}
		n++
	}
	if n == 0 {
		t.Fatal("the reference data is empty")
	}
}

// TestAuditStringEncoding covers audit_log_untrustedstring()'s two encodings:
// a value of printable ASCII without '"' is quoted, and anything else is bare
// uppercase hex of every byte. A path with a space appears hex-encoded in real
// logs, which is what aa-logprof and aa_parse_record expect to decode.
func TestAuditStringEncoding(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{in: "/etc/fstab", want: ` name="/etc/fstab"`},
		// "/tmp/a b" has a space: every byte becomes lowercase hex.
		{in: "/tmp/a b", want: ` name=2F746D702F612062`},
		// A quote would end the quoted form early, so it is hex too.
		{in: `/tmp/"x`, want: ` name=2F746D702F2278`},
		// Non-ASCII.
		{in: "/tmp/caf\xc3\xa9", want: ""}, // computed below
		{in: "", want: ` name=""`},
	} {
		var b strings.Builder
		auditString(&b, "name", tc.in)
		if tc.want == "" {
			// The non-ASCII case: verify it is bare hex of the bytes.
			want := " name="
			for i := 0; i < len(tc.in); i++ {
				want += fmt.Sprintf("%02X", tc.in[i])
			}
			tc.want = want
		}
		if b.String() != tc.want {
			t.Errorf("auditString(%q) = %q, want %q", tc.in, b.String(), tc.want)
		}
	}
}
