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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
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
		// '**' crosses components, including none.
		{"/var/www/**", "/var/www/a/b/c.php", true},
		{"/var/www/**", "/var/www/", true},
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
		// AppArmor's 'w' grants appending as well.
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
			// A "**" rule matches zero characters, so "/tmp/** rw"
			// permits reading the directory itself, which AppArmor
			// mediates with a trailing slash.
			name: "a ** rule covers the directory itself",
			path: "/tmp/",
			ats:  vfs.MayRead, mode: linux.ModeDirectory | 0755, kuid: 0,
		},
		{
			name: "a directory rule written with a trailing slash matches",
			path: "/etc/php8/",
			ats:  vfs.MayRead, mode: linux.ModeDirectory | 0755, kuid: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(creds, tc.path, tc.ats, tc.mode, tc.kuid)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Check(%q, %v) error = %v, wantErr %v", tc.path, tc.ats, err, tc.wantErr)
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
	if err := Check(creds, "/etc/passwd", vfs.MayRead, 0644, 0); err == nil {
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
			err := CheckPerms(creds, tc.path, Mmap, fileMode, tc.kuid)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("CheckPerms(%q, Mmap) = %v, wantErr %t", tc.path, err, tc.wantErr)
			}
		})
	}
}

// TestParsePermsWriteImpliesAppend checks AppArmor's rule that 'w' grants
// appending, so that a rule written "w" covers an O_APPEND write.
func TestParsePermsWriteImpliesAppend(t *testing.T) {
	if p := ParsePerms("w"); p&Append == 0 {
		t.Errorf(`ParsePerms("w") = %v, want Append set`, p)
	}
	if p := ParsePerms("a"); p&Write != 0 {
		t.Errorf(`ParsePerms("a") = %v, want Write clear`, p)
	}
}

// TestCheckChangeProfile covers aa_change_profile(3): an unconfined task may
// enter any profile, and a confined one only those its own profile's
// change_profile rules name.
func TestCheckChangeProfile(t *testing.T) {
	SetPolicy(map[string]*Profile{
		"docker-hosted": {
			Name: "docker-hosted",
			ChangeProfile: []ChangeRule{
				{Pattern: "cage*"},
				{Pattern: "/usr/bin/cage*"},
				// A deny rule overrides the allow above it.
				{Pattern: "jailroot", Deny: true},
			},
		},
		"cageweb":          {Name: "cageweb"},
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
			to:      "jailroot",
			wantErr: true,
		},
		{name: "unconfined may enter any profile", from: "", to: "cageweb"},
		{name: "a bare change_profile permits any target", from: "anything", to: "unrelated"},
		{name: "entering the same profile is a no-op", from: "cageweb", to: "cageweb"},
		{
			// Would leave the task denied every access.
			name:    "an undefined target",
			from:    "docker-hosted",
			to:      "jailtypo",
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
			err := CheckChangeProfile(tc.from, tc.to)
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
			{Pattern: "/bin/named", Mode: ExecProfile, Target: "jail"},
			{Pattern: "/bin/missing", Mode: ExecProfile, Target: "nosuch"},
			{Pattern: "/bin/bare", Mode: ExecProfile},
			{Pattern: "/bin/kid", Mode: ExecChild, Target: "kid"},
			{Pattern: "/bin/nokid", Mode: ExecChild, Target: "nokid"},
		}},
		"jail":        {Name: "jail"},
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
			// its own profile and the jail was never entered.
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
		{name: "px enters the named profile", from: "outer", path: "/bin/named", want: "jail"},
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
			got, err := TransitionOnExec(tc.from, tc.path)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("TransitionOnExec(%q, %q) error = %v, wantErr %t", tc.from, tc.path, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("TransitionOnExec(%q, %q) = %q, want %q", tc.from, tc.path, got, tc.want)
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
		got, err := TransitionOnExec("p", path)
		if err != nil {
			t.Fatalf("TransitionOnExec(%q) = %v", path, err)
		}
		if got != want {
			t.Errorf("TransitionOnExec(%q) = %q, want %q", path, got, want)
		}
	}
}
