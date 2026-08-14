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

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/config"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

func TestParseAppArmorProfiles(t *testing.T) {
	for _, tc := range []struct {
		name           string
		profile        string
		wantRules      map[string][]confine.Rule
		wantExecAttach map[string]string
		wantProfiles   []string
	}{
		{
			name: "owner and non-owner rules through a multi-valued tunable",
			profile: `
#include <tunables/global>

@{WWW_DIRS} = /var/www/vhosts /mnt/nfs01/siteroots

profile cageweb flags=(attach_disconnected, mediate_deleted) {
  #include <abstractions/base>
  @{WWW_DIRS}/assets/** rk,
  owner @{WWW_DIRS}/?/?/*/** rwkmlix,
}
`,
			wantProfiles: []string{"cageweb"},
			wantRules: map[string][]confine.Rule{
				"cageweb": {
					{Pattern: "/var/www/vhosts/assets/**", Perms: confine.ParsePerms("rk")},
					{Pattern: "/mnt/nfs01/siteroots/assets/**", Perms: confine.ParsePerms("rk")},
					{Pattern: "/var/www/vhosts/?/?/*/**", Perms: confine.ParsePerms("rwkmlix"), Owner: true},
					{Pattern: "/mnt/nfs01/siteroots/?/?/*/**", Perms: confine.ParsePerms("rwkmlix"), Owner: true},
				},
			},
		},
		{
			name: "deny rules are preserved",
			profile: `
profile p {
  /etc/** r,
  deny /etc/apache2/** rwlkx,
}
`,
			wantProfiles: []string{"p"},
			wantRules: map[string][]confine.Rule{
				"p": {
					{Pattern: "/etc/**", Perms: confine.ParsePerms("r")},
					{Pattern: "/etc/apache2/**", Perms: confine.ParsePerms("rwlkx"), Deny: true},
				},
			},
		},
		{
			name: "profile named after a path attaches on exec",
			profile: `
profile /bin/cagebash flags=(attach_disconnected) {
  /etc/passwd r,
}
`,
			wantProfiles:   []string{"/bin/cagebash"},
			wantExecAttach: map[string]string{"/bin/cagebash": "/bin/cagebash"},
			wantRules: map[string][]confine.Rule{
				"/bin/cagebash": {
					{Pattern: "/etc/passwd", Perms: confine.ParsePerms("r")},
				},
			},
		},
		{
			name: "non-file rules are not file rules",
			profile: `
profile p {
  network,
  capability,
  signal (receive),
  unix peer=(label=cage*),
  deny mount,
}
`,
			wantProfiles: []string{"p"},
		},
		{
			name: "rules of an unknown variable are dropped",
			profile: `
profile p {
  owner @{UNDEFINED}/x/** rw,
}
`,
			wantProfiles: []string{"p"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &AppArmorPolicy{}
			if err := ParseAppArmorProfiles(strings.NewReader(tc.profile), tc.name, policy, make(tunables)); err != nil {
				t.Fatalf("ParseAppArmorProfiles: %v", err)
			}
			if !reflect.DeepEqual(policy.Profiles, tc.wantProfiles) {
				t.Errorf("Profiles = %v, want %v", policy.Profiles, tc.wantProfiles)
			}
			if len(policy.ExecAttach) != 0 || len(tc.wantExecAttach) != 0 {
				if !reflect.DeepEqual(policy.ExecAttach, tc.wantExecAttach) {
					t.Errorf("ExecAttach = %v, want %v", policy.ExecAttach, tc.wantExecAttach)
				}
			}
			if len(tc.wantRules) == 0 {
				if len(policy.Rules) != 0 {
					t.Errorf("Rules = %v, want none", policy.Rules)
				}
				return
			}
			if len(policy.Rules) != len(tc.wantRules) {
				t.Fatalf("Rules has %d profiles, want %d", len(policy.Rules), len(tc.wantRules))
			}
			for name, want := range tc.wantRules {
				cp := policy.Rules[name]
				if cp == nil {
					t.Fatalf("Rules[%q] missing", name)
				}
				if !reflect.DeepEqual(cp.Rules, want) {
					t.Errorf("Rules[%q] = %+v, want %+v", name, cp.Rules, want)
				}
			}
		})
	}
}

// TestParseAppArmorProfilesSharedTunables verifies that variables defined in
// one file are visible to profiles parsed later, as they are when
// apparmor_parser processes tunables/global before each profile.
func TestParseAppArmorProfilesSharedTunables(t *testing.T) {
	tun := make(tunables)
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader("@{ROOTS} = /srv/a /srv/b\n"), "tunables", policy, tun); err != nil {
		t.Fatalf("parsing tunables: %v", err)
	}
	if err := ParseAppArmorProfiles(strings.NewReader("profile p {\n  owner @{ROOTS}/*/** rw,\n}\n"), "p", policy, tun); err != nil {
		t.Fatalf("parsing profile: %v", err)
	}
	want := []confine.Rule{
		{Pattern: "/srv/a/*/**", Perms: confine.ParsePerms("rw"), Owner: true},
		{Pattern: "/srv/b/*/**", Perms: confine.ParsePerms("rw"), Owner: true},
	}
	if cp := policy.Rules["p"]; cp == nil {
		t.Fatal(`Rules["p"] missing`)
	} else if !reflect.DeepEqual(cp.Rules, want) {
		t.Errorf("Rules = %+v, want %+v", cp.Rules, want)
	}
}

// TestInitConfinementProfile verifies which profile the container's initial
// process starts in. Attaching a profile the policy does not define would deny
// every access the container makes, so that case must leave it unconfined.
func TestInitConfinementProfile(t *testing.T) {
	confine.SetPolicy(map[string]*confine.Profile{
		"docker-hosted": {Name: "docker-hosted"},
	})
	defer confine.SetPolicy(nil)

	for _, tc := range []struct {
		name    string
		profile string
		want    string
	}{
		{
			name:    "the spec profile attaches when the policy defines it",
			profile: "docker-hosted",
			want:    "docker-hosted",
		},
		{
			name:    "no spec profile leaves init unconfined",
			profile: "",
			want:    "",
		},
		{
			name:    "an undefined profile leaves init unconfined",
			profile: "typo-hosted",
			want:    "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &specs.Spec{Process: &specs.Process{ApparmorProfile: tc.profile}}
			if got := initConfinementProfile(spec); got != tc.want {
				t.Errorf("initConfinementProfile(%q) = %q, want %q", tc.profile, got, tc.want)
			}
		})
	}
}

// TestInitConfinementProfileNoPolicy verifies that a spec profile does not
// attach when no policy was loaded at all, which is the default.
func TestInitConfinementProfileNoPolicy(t *testing.T) {
	spec := &specs.Spec{Process: &specs.Process{ApparmorProfile: "docker-hosted"}}
	if got := initConfinementProfile(spec); got != "" {
		t.Errorf("initConfinementProfile = %q, want unconfined", got)
	}
}

func TestParseChangeProfileRules(t *testing.T) {
	const profile = `
profile docker-hosted {
  file,
  change_profile -> cage*,
  change_profile -> /usr/bin/cage*,
}
`
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(profile), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	cp := policy.Rules["docker-hosted"]
	if cp == nil {
		t.Fatal(`Rules["docker-hosted"] missing`)
	}
	wantTargets := []confine.ChangeRule{
		{Pattern: "cage*"},
		{Pattern: "/usr/bin/cage*"},
	}
	if !reflect.DeepEqual(cp.ChangeProfile, wantTargets) {
		t.Errorf("ChangeProfile = %v, want %v", cp.ChangeProfile, wantTargets)
	}
	// "file," is every access to every path, /{**,}: both "/**" and "/"
	// itself. Without it a profile that relies on it is reduced to its deny
	// rules and denies everything.
	wantRules := []confine.Rule{
		{Pattern: "/**", Perms: confine.ParsePerms("mrwlkix")},
		{Pattern: "/", Perms: confine.ParsePerms("mrwlkix")},
	}
	if !reflect.DeepEqual(cp.Rules, wantRules) {
		t.Errorf("Rules = %+v, want %+v", cp.Rules, wantRules)
	}
}

func TestParseFileClassRules(t *testing.T) {
	const profile = `
profile p {
  file,
  deny file,
  file /etc/passwd r,
  owner file /home/u/** rw,
}
`
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(profile), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	want := []confine.Rule{
		{Pattern: "/**", Perms: confine.ParsePerms("mrwlkix")},
		// Bare "file" is /{**,}: "/**" cannot match "/" itself, so the
		// parser emits "/" alongside it. apparmor_parser compiles it to
		// /([^\x00]*|), which is what lets "ls /" work under a
		// deny-list profile built on bare "file".
		{Pattern: "/", Perms: confine.ParsePerms("mrwlkix")},
		{Pattern: "/**", Perms: confine.ParsePerms("mrwlkix"), Deny: true},
		{Pattern: "/", Perms: confine.ParsePerms("mrwlkix"), Deny: true},
		{Pattern: "/etc/passwd", Perms: confine.ParsePerms("r")},
		{Pattern: "/home/u/**", Perms: confine.ParsePerms("rw"), Owner: true},
	}
	if cp := policy.Rules["p"]; cp == nil {
		t.Fatal(`Rules["p"] missing`)
	} else if !reflect.DeepEqual(cp.Rules, want) {
		t.Errorf("Rules = %+v, want %+v", cp.Rules, want)
	}
}

// TestTunableAssignDoesNotAccumulate covers the growth that made loading a
// full policy directory consume unbounded memory: a tunables file is read once
// per profile that includes it, so an assignment that appended instead of
// replacing grew the variable by one copy per profile, and every rule
// mentioning it expanded by that factor.
func TestTunableAssignDoesNotAccumulate(t *testing.T) {
	tun := make(tunables)
	policy := &AppArmorPolicy{}
	const global = "@{HOME} = /home/ /root/\n"
	for i := 0; i < 50; i++ {
		if err := ParseAppArmorProfiles(strings.NewReader(global), "tunables", policy, tun); err != nil {
			t.Fatalf("parsing tunables: %v", err)
		}
	}
	if got, want := len(tun["HOME"]), 2; got != want {
		t.Errorf("@{HOME} has %d values after 50 reads, want %d", got, want)
	}
	if err := ParseAppArmorProfiles(strings.NewReader("profile p {\n  @{HOME}/** r,\n}\n"), "p", policy, tun); err != nil {
		t.Fatalf("parsing profile: %v", err)
	}
	if got, want := len(policy.Rules["p"].Rules), 2; got != want {
		t.Errorf("rule expanded to %d rules, want %d", got, want)
	}
}

// TestTunableAppend checks that "+=" still adds, and that a repeated append of
// the same value does not grow the variable.
func TestTunableAppend(t *testing.T) {
	tun := make(tunables)
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader("@{D} = /a\n@{D} += /b\n@{D} += /b\n"), "tunables", policy, tun); err != nil {
		t.Fatalf("parsing tunables: %v", err)
	}
	want := []string{"/a", "/b"}
	if !reflect.DeepEqual(tun["D"], want) {
		t.Errorf("@{D} = %v, want %v", tun["D"], want)
	}
}

// TestExpansionIsBounded checks that a rule naming several multi-valued
// variables cannot expand without bound.
func TestExpansionIsBounded(t *testing.T) {
	tun := make(tunables)
	var def strings.Builder
	for _, name := range []string{"A", "B", "C", "D"} {
		def.WriteString("@{" + name + "} =")
		for i := 0; i < 12; i++ {
			fmt.Fprintf(&def, " /v%d", i)
		}
		def.WriteByte('\n')
	}
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(def.String()), "tunables", policy, tun); err != nil {
		t.Fatalf("parsing tunables: %v", err)
	}
	if err := ParseAppArmorProfiles(strings.NewReader("profile p {\n  @{A}@{B}@{C}@{D}/** r,\n}\n"), "p", policy, tun); err != nil {
		t.Fatalf("parsing profile: %v", err)
	}
	// 12^4 is 20736 without a bound.
	if got := len(policy.Rules["p"].Rules); got > maxExpansion {
		t.Errorf("rule expanded to %d rules, want at most %d", got, maxExpansion)
	}
}

func TestParseChangeProfileDeny(t *testing.T) {
	const profile = `
profile p {
  change_profile -> cage*,
  deny change_profile -> cageroot,
  audit change_profile -> audited,
}

profile q {
  deny change_profile,
}

profile r {
  change_profile,
}

profile s {
  deny change_profile /usr/bin/foo -> bar,
}
`
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(profile), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	for name, want := range map[string][]confine.ChangeRule{
		"p": {
			{Pattern: "cage*"},
			{Pattern: "cageroot", Deny: true},
			{Pattern: "audited"},
		},
		// A bare deny refuses every transition.
		"q": {{Pattern: "**", Deny: true}},
		// A bare allow permits every transition.
		"r": {{Pattern: "**"}},
	} {
		cp := policy.Rules[name]
		if cp == nil {
			t.Fatalf("Rules[%q] missing", name)
		}
		if !reflect.DeepEqual(cp.ChangeProfile, want) {
			t.Errorf("Rules[%q].ChangeProfile = %+v, want %+v", name, cp.ChangeProfile, want)
		}
	}
	// A deny rule with an exec condition keeps the condition, which is
	// evaluated when the transition is applied at exec.
	want := []confine.ChangeRule{{Pattern: "bar", Deny: true, Exec: "/usr/bin/foo"}}
	if cp := policy.Rules["s"]; cp == nil {
		t.Error(`Rules["s"] missing`)
	} else if !reflect.DeepEqual(cp.ChangeProfile, want) {
		t.Errorf(`Rules["s"].ChangeProfile = %+v, want %+v`, cp.ChangeProfile, want)
	}
}

// TestNestedProfileScope checks that a child profile does not swallow the rules
// that follow it in its parent, and that a rule outside any profile is recorded
// rather than dropped without a trace.
func TestNestedProfileScope(t *testing.T) {
	const profile = `
/outside/the/profile r,
profile parent {
  /a r,
  profile child {
    /b r,
  }
  /c r,
}
/after/the/profile r,
`
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(profile), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	for name, want := range map[string][]string{
		"parent": {"/a", "/c"},
		"child":  {"/b"},
	} {
		cp := policy.Rules[name]
		if cp == nil {
			t.Fatalf("Rules[%q] missing", name)
		}
		var got []string
		for _, r := range cp.Rules {
			got = append(got, r.Pattern)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Rules[%q] patterns = %v, want %v", name, got, want)
		}
	}
	var atFileScope []string
	for _, u := range policy.Unenforced {
		if u.Profile == "" {
			atFileScope = append(atFileScope, u.Line)
		}
	}
	want := []string{"/outside/the/profile r,", "/after/the/profile r,"}
	if !reflect.DeepEqual(atFileScope, want) {
		t.Errorf("file-scope lines recorded = %v, want %v", atFileScope, want)
	}
}

// TestPolicyMerge covers merging one container's policy into another's, which
// --apparmor-policy-source=container does once per container.
func TestPolicyMerge(t *testing.T) {
	first := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader("profile a {\n  /one r,\n}\n"), "a", first, make(tunables)); err != nil {
		t.Fatalf("parsing a: %v", err)
	}
	second := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader("profile a {\n  /weaker rw,\n}\nprofile b {\n  /two r,\n}\n"), "b", second, make(tunables)); err != nil {
		t.Fatalf("parsing b: %v", err)
	}
	first.merge(second)
	// The already-defined profile keeps its own rules: a container must not
	// be able to redefine a profile another container is running under.
	if got := len(first.Rules["a"].Rules); got != 1 || first.Rules["a"].Rules[0].Pattern != "/one" {
		t.Errorf(`Rules["a"] = %+v, want only /one`, first.Rules["a"].Rules)
	}
	if first.Rules["b"] == nil {
		t.Error(`Rules["b"] missing after merge`)
	}
	if !reflect.DeepEqual(first.Profiles, []string{"a", "b"}) {
		t.Errorf("Profiles = %v, want [a b]", first.Profiles)
	}
}

// TestParseRuleWithTarget covers rules that name a target after an arrow. The
// permissions are the field before it: reading the last field instead took the
// target's letters for permission characters, so "Px -> child" granted 'l' from
// "child" and lost the 'x' the rule is for.
func TestParseRuleWithTarget(t *testing.T) {
	const profile = `
profile p {
  /usr/bin/foo Px -> child,
  /usr/bin/bar px -> other,
  /link l -> /target,
}
`
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(profile), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	want := []confine.Rule{
		{Pattern: "/usr/bin/foo", Perms: confine.ParsePerms("x")},
		{Pattern: "/usr/bin/bar", Perms: confine.ParsePerms("x")},
		{Pattern: "/link", Perms: confine.ParsePerms("l")},
	}
	cp := policy.Rules["p"]
	if cp == nil {
		t.Fatal(`Rules["p"] missing`)
	}
	if !reflect.DeepEqual(cp.Rules, want) {
		t.Errorf("Rules = %+v, want %+v", cp.Rules, want)
	}
}

// TestParseExecTransitions covers the transition each exec modifier asks for,
// and that a rule's transition target is kept separately from its permissions.
func TestParseExecTransitions(t *testing.T) {
	const profile = `
profile p {
  file,
  /bin/inherit mixr,
  /bin/unconfined mrUx,
  /bin/lower mrux,
  /bin/named mrpx -> cage,
  /bin/scrubbed mrPx -> cage,
  /bin/kid mrcx -> kid,
  deny /bin/denied mrix,
  /etc/passwd r,
}
`
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(profile), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	cp := policy.Rules["p"]
	if cp == nil {
		t.Fatal(`Rules["p"] missing`)
	}
	want := []confine.ExecRule{
		// "file," grants exec over everything with no modifier.
		{Pattern: "/**"},
		{Pattern: "/bin/inherit", Mode: confine.ExecInherit},
		{Pattern: "/bin/unconfined", Mode: confine.ExecUnconfined, Scrub: true},
		{Pattern: "/bin/lower", Mode: confine.ExecUnconfined},
		{Pattern: "/bin/named", Mode: confine.ExecProfile, Target: "cage"},
		{Pattern: "/bin/scrubbed", Mode: confine.ExecProfile, Target: "cage", Scrub: true},
		{Pattern: "/bin/kid", Mode: confine.ExecChild, Target: "kid"},
	}
	if !reflect.DeepEqual(cp.ExecRules, want) {
		t.Errorf("ExecRules = %+v, want %+v", cp.ExecRules, want)
	}
	// A rule with no exec permission carries no transition, and a deny rule
	// grants nothing so it carries none either.
	for _, r := range cp.ExecRules {
		if r.Pattern == "/etc/passwd" || r.Pattern == "/bin/denied" {
			t.Errorf("ExecRules contains %q, which grants no exec", r.Pattern)
		}
	}
}

// TestBareExecRejected covers apparmor.d(5): "A bare 'x' is only allowed in
// rules with the deny qualifier". An allow rule carrying one names no
// transition, and picking one would be inventing policy, so it is reported as
// unenforced instead.
func TestBareExecRejected(t *testing.T) {
	policy := &AppArmorPolicy{}
	const profile = `
profile p {
  /bin/plain mrx,
  /bin/fine mrix,
  deny /bin/nope x,
}
`
	if err := ParseAppArmorProfiles(strings.NewReader(profile), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	cp := policy.Rules["p"]
	for _, r := range cp.Rules {
		if r.Pattern == "/bin/plain" {
			t.Error("a bare x allow rule produced a file rule")
		}
	}
	var reported bool
	for _, u := range policy.Unenforced {
		if strings.Contains(u.Line, "/bin/plain") {
			reported = true
		}
	}
	if !reported {
		t.Error("a bare x allow rule was dropped without being reported")
	}
	// The qualified rule is kept, and the deny rule is unaffected.
	var haveFine bool
	for _, r := range cp.ExecRules {
		if r.Pattern == "/bin/fine" && r.Mode == confine.ExecInherit {
			haveFine = true
		}
	}
	if !haveFine {
		t.Error("a qualified exec rule was not kept")
	}
}

// TestPathAndVariableSyntax covers the path and variable rules of
// apparmor.d(5), each of which was found broken against real policy: tunables
// conventionally end in a slash, so a rule written "@{run}/nscd/socket"
// expanded to a path with a doubled slash that matched nothing.
func TestPathAndVariableSyntax(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  string
		profile string
		want    []confine.Rule
	}{
		{
			// "AppArmor will canonicalize the path by collapsing
			// consecutive / characters into a single character".
			name:    "a tunable ending in a slash does not double it",
			policy:  "@{run} = /run/ /var/run/\n" + "profile p {\n  @{run}/nscd/socket rw,\n}\n",
			profile: "p",
			want: []confine.Rule{
				{Pattern: "/run/nscd/socket", Perms: confine.ParsePerms("rw")},
				{Pattern: "/var/run/nscd/socket", Perms: confine.ParsePerms("rw")},
			},
		},
		{
			// "except when slashes appear at the path beginning".
			name:    "a leading double slash is kept",
			policy:  "profile p {\n  //ns/thing r,\n}\n",
			profile: "p",
			want:    []confine.Rule{{Pattern: "//ns/thing", Perms: confine.ParsePerms("r")}},
		},
		{
			// "Rules with embedded spaces or tabs must be quoted
			// with double quotes."
			name:    "a quoted path keeps its spaces",
			policy:  "profile p {\n  \"/var/lib/some dir/file\" r,\n}\n",
			profile: "p",
			want:    []confine.Rule{{Pattern: "/var/lib/some dir/file", Perms: confine.ParsePerms("r")}},
		},
		{
			// "The special @{profile_name} variable is
			// automatically set to the current profile's name."
			name:    "profile_name is set automatically",
			policy:  "profile cageweb {\n  /var/run/@{profile_name}/x r,\n}\n",
			profile: "cageweb",
			want:    []confine.Rule{{Pattern: "/var/run/cageweb/x", Perms: confine.ParsePerms("r")}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &AppArmorPolicy{}
			if err := ParseAppArmorProfiles(strings.NewReader(tc.policy), "t", policy, make(tunables)); err != nil {
				t.Fatalf("ParseAppArmorProfiles: %v", err)
			}
			cp := policy.Rules[tc.profile]
			if cp == nil {
				t.Fatalf("Rules[%q] missing", tc.profile)
			}
			if !reflect.DeepEqual(cp.Rules, tc.want) {
				t.Errorf("Rules = %+v, want %+v", cp.Rules, tc.want)
			}
		})
	}
}

// TestNamedProfileAttachment covers a profile whose attachment path is given
// separately from its name, "profile cage /bin/cagebash {", which attaches on
// exec of that path just as "profile /bin/cagebash {" does.
// TestAttachmentSpecifications covers every form an attachment can take. The
// specification is one AARE expression: alternations and variables give it
// several values, each of which enters the profile on exec, verified against
// a live kernel (profile "attachtest /tmp/at/{a,b}/bintest" attaches a and b,
// not c). A comma is NOT a list separator: the kernel loads
// "/bin/a,/bin/b" without error and attaches NOTHING, because it is one
// expression matching only a path that literally contains a comma. The same
// holds here, so that footgun at least behaves identically.
func TestAttachmentSpecifications(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		want   map[string]string
	}{
		{
			name:   "alternation attaches every expansion",
			policy: "profile cagebash /{bin,usr/bin}/cagebash {\n  /etc/passwd r,\n}\n",
			want: map[string]string{
				"/bin/cagebash":     "cagebash",
				"/usr/bin/cagebash": "cagebash",
			},
		},
		{
			name:   "usrmerge idiom",
			policy: "profile cagebash /{usr/,}bin/cagebash {\n  /etc/passwd r,\n}\n",
			want: map[string]string{
				"/bin/cagebash":     "cagebash",
				"/usr/bin/cagebash": "cagebash",
			},
		},
		{
			name: "variable attachment expands per value",
			policy: "@{paths} = /bin /usr/bin\n" +
				"profile cagebash @{paths}/cagebash {\n  /etc/passwd r,\n}\n",
			want: map[string]string{
				"/bin/cagebash":     "cagebash",
				"/usr/bin/cagebash": "cagebash",
			},
		},
		{
			name:   "path-named profile with alternation attaches every expansion",
			policy: "profile /{bin,usr/bin}/cagedash {\n  /etc/passwd r,\n}\n",
			want: map[string]string{
				"/bin/cagedash":     "/{bin,usr/bin}/cagedash",
				"/usr/bin/cagedash": "/{bin,usr/bin}/cagedash",
			},
		},
		{
			// Kernel-verified: all four attach to cagesh, a fifth
			// binary beside them stays unconfined.
			name: "two brace groups attach their cartesian product",
			policy: "profile cagesh /{bin,usr/bin}/{cagebash,cagedash} {\n" +
				"  /etc/passwd r,\n}\n",
			want: map[string]string{
				"/bin/cagebash":     "cagesh",
				"/bin/cagedash":     "cagesh",
				"/usr/bin/cagebash": "cagesh",
				"/usr/bin/cagedash": "cagesh",
			},
		},
		{
			name:   "comma is not a list separator and attaches nothing real",
			policy: "profile cagebash /bin/cagebash,/usr/bin/cagebash {\n  /etc/passwd r,\n}\n",
			// One literal key containing a comma, which no exec path ever
			// equals: both binaries would run unconfined, exactly as they
			// do on a real kernel.
			want: map[string]string{
				"/bin/cagebash,/usr/bin/cagebash": "cagebash",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &AppArmorPolicy{}
			if err := ParseAppArmorProfiles(strings.NewReader(tc.policy), "t", policy, make(tunables)); err != nil {
				t.Fatalf("ParseAppArmorProfiles: %v", err)
			}
			if !reflect.DeepEqual(policy.ExecAttach, tc.want) {
				t.Errorf("ExecAttach = %v, want %v", policy.ExecAttach, tc.want)
			}
			// Attachment only matters if exec actually lands in the
			// profile: an unconfined task must enter it for every
			// attached path and stay unconfined for near misses.
			auth.SetExecConfinementProfiles(policy.ExecAttach)
			defer auth.SetExecConfinementProfiles(nil)
			for path, profile := range tc.want {
				if strings.Contains(path, ",") {
					// The footgun row: no real path equals it.
					continue
				}
				got, _, err := confine.TransitionOnExec(nil, "", path)
				if err != nil {
					t.Errorf("TransitionOnExec(unconfined, %q) failed: %v", path, err)
				} else if got != profile {
					t.Errorf("TransitionOnExec(unconfined, %q) = %q, want %q", path, got, profile)
				}
			}
			if got, _, _ := confine.TransitionOnExec(nil, "", "/bin/near-miss"); got != "" {
				t.Errorf("TransitionOnExec(unconfined, /bin/near-miss) = %q, want unconfined", got)
			}
		})
	}
}

func TestNamedProfileAttachment(t *testing.T) {
	policy := &AppArmorPolicy{}
	const p = "profile cage /bin/cagebash flags=(attach_disconnected) {\n  /etc/passwd r,\n}\nprofile /bin/cagedash {\n  /etc/passwd r,\n}\nprofile plain {\n  /etc/passwd r,\n}\n"
	if err := ParseAppArmorProfiles(strings.NewReader(p), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	want := map[string]string{
		"/bin/cagebash": "cage",
		"/bin/cagedash": "/bin/cagedash",
	}
	if !reflect.DeepEqual(policy.ExecAttach, want) {
		t.Errorf("ExecAttach = %v, want %v", policy.ExecAttach, want)
	}
}

// TestLinkRules covers link rules as apparmor.d(5) defines them: "permission
// to form a hard link as a link target pair", with the subset condition
// requiring "the permissions to access the link file must be a subset of the
// profiles permissions to access the target file". A bare 'l' permission is
// itself such a rule, with an implied subset and a target of "/**".
func TestLinkRules(t *testing.T) {
	const policyText = `profile p {
  /data/orig r,
  /data/rw rwl,
  /data/other r,
  /links/same rl,
  /links/more rwl,
  /links/nol rw,
  link /links/loose -> /data/orig,
  /links/loose rw,
  link subset /links/strict -> /data/orig,
  /links/strict rw,
  link /links/pair -> /data/orig,
  /links/pair r,
}
`
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(policyText), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	confine.SetPolicy(policy.Rules)
	defer confine.SetPolicy(nil)

	creds := auth.NewAnonymousCredentials()
	creds.ConfinementProfile = "p"
	const mode = linux.FileMode(0644)
	for _, tc := range []struct {
		name    string
		link    string
		target  string
		wantErr bool
	}{
		{
			// The link grants r and l; the original grants r. l is
			// the permission being exercised, so the subset holds.
			name:   "a bare l with the same permissions",
			link:   "/links/same",
			target: "/data/orig",
		},
		{
			// A bare 'l' implies the subset condition, and the link
			// would grant w where the original does not.
			name:    "a bare l with more permissions than the original",
			link:    "/links/more",
			target:  "/data/orig",
			wantErr: true,
		},
		{
			name:   "a bare l no broader than a writable original",
			link:   "/links/more",
			target: "/data/rw",
		},
		{
			// 'l' is required for the name being created.
			name:    "no l on the link",
			link:    "/links/nol",
			target:  "/data/orig",
			wantErr: true,
		},
		{
			// An explicit link rule without 'subset' permits a link
			// with more permissions than the file it points at.
			name:   "a link rule without subset permits a broader link",
			link:   "/links/loose",
			target: "/data/orig",
		},
		{
			name:    "the subset condition denies a broader link",
			link:    "/links/strict",
			target:  "/data/orig",
			wantErr: true,
		},
		{
			// The rule names a pair, so another target is not
			// covered by it.
			name:    "a target the pair does not name",
			link:    "/links/pair",
			target:  "/data/other",
			wantErr: true,
		},
		{
			name:   "the target the pair names",
			link:   "/links/pair",
			target: "/data/orig",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := confine.CheckLink(nil, creds, tc.link, tc.target, mode, auth.KUID(0))
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("CheckLink(%q -> %q) = %v, wantErr %t", tc.link, tc.target, err, tc.wantErr)
			}
		})
	}
}

// TestProfileFlags covers the enforcement modes a profile's flags select, and
// the link rule syntax.
func TestProfileFlags(t *testing.T) {
	for _, tc := range []struct {
		name      string
		policy    string
		profile   string
		wantMode  confine.ProfileMode
		wantSig   int32
		wantErrno int32
	}{
		{
			name:     "unconfined mediates nothing in the sandbox",
			policy:   "profile p flags=(unconfined) {\n  /etc/passwd r,\n}\n",
			profile:  "p",
			wantMode: confine.ModeUnconfined,
		},
		{
			name:     "default_allow inverts to allow-by-default",
			policy:   "profile p flags=(default_allow) {\n  deny /etc/shadow r,\n}\n",
			profile:  "p",
			wantMode: confine.ModeDefaultAllow,
		},
		{
			name:     "kill with an explicit signal",
			policy:   "profile p flags=(kill, kill.signal=term) {\n  /etc/passwd r,\n}\n",
			profile:  "p",
			wantMode: confine.ModeKill,
			wantSig:  int32(linux.SIGTERM),
		},
		{
			name:      "a custom error code",
			policy:    "profile p flags=(error=EPERM) {\n  /etc/passwd r,\n}\n",
			profile:   "p",
			wantMode:  confine.ModeEnforce,
			wantErrno: int32(unix.EPERM),
		},
		{
			name:     "enforce is the default",
			policy:   "profile p {\n  /etc/passwd r,\n}\n",
			profile:  "p",
			wantMode: confine.ModeEnforce,
		},
		{
			// An out of range signal number is not a signal; the
			// profile keeps the default rather than trying to send
			// something that cannot be sent.
			name:     "an invalid kill signal is ignored",
			policy:   "profile p flags=(kill, kill.signal=999) {\n  /etc/passwd r,\n}\n",
			profile:  "p",
			wantMode: confine.ModeKill,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &AppArmorPolicy{}
			if err := ParseAppArmorProfiles(strings.NewReader(tc.policy), "t", policy, make(tunables)); err != nil {
				t.Fatalf("ParseAppArmorProfiles: %v", err)
			}
			cp := policy.Rules[tc.profile]
			if cp == nil {
				t.Fatalf("Rules[%q] missing", tc.profile)
			}
			if cp.Mode != tc.wantMode {
				t.Errorf("Mode = %v, want %v", cp.Mode, tc.wantMode)
			}
			if cp.KillSignal != tc.wantSig {
				t.Errorf("KillSignal = %d, want %d", cp.KillSignal, tc.wantSig)
			}
			if cp.Error != tc.wantErrno {
				t.Errorf("Error = %d, want %d", cp.Error, tc.wantErrno)
			}
		})
	}
}

// TestParseLinkRule covers "link [subset] /source -> /target,", which
// apparmor.d(5) relates to the l permission: "l /foo" is shorthand for
// "link subset /foo -> /**".
func TestParseLinkRule(t *testing.T) {
	const p = "profile p {\n  link subset /data/a -> /data/b,\n  link /data/c -> /data/d,\n  deny link /data/e -> /data/f,\n}\n"
	policy := &AppArmorPolicy{}
	if err := ParseAppArmorProfiles(strings.NewReader(p), "t", policy, make(tunables)); err != nil {
		t.Fatalf("ParseAppArmorProfiles: %v", err)
	}
	want := []confine.Rule{
		{Pattern: "/data/a", Perms: confine.Link},
		{Pattern: "/data/c", Perms: confine.Link},
		{Pattern: "/data/e", Perms: confine.Link, Deny: true},
	}
	if !reflect.DeepEqual(policy.Rules["p"].Rules, want) {
		t.Errorf("Rules = %+v, want %+v", policy.Rules["p"].Rules, want)
	}
}

// stdioFDsFor builds the three stdio descriptors a containerInfo carries, each
// owning its own dup of fd. They must not share one descriptor: fd.New installs
// a finalizer that closes it, so three wrappers around one descriptor close it
// three times, and once the number has been reused - by a socketpair in another
// test in this binary, for instance - the finalizer closes that unrelated
// descriptor instead. That presented as an intermittent "bad file descriptor"
// in tests that run after these.
func stdioFDsFor(t *testing.T, fdNum int) []*fd.FD {
	t.Helper()
	var out []*fd.FD
	for i := 0; i < 3; i++ {
		dup, err := unix.Dup(fdNum)
		if err != nil {
			t.Fatalf("dup of fd %d: %v", fdNum, err)
		}
		f := fd.New(dup)
		t.Cleanup(func() { f.Close() })
		out = append(out, f)
	}
	return out
}

// TestAuditSinkNeverBlocks covers the rule that a task must never wait on
// whoever drains the container's output. A record is written from the task
// goroutine while filesystem locks are held, so a blocking write to a pipe
// nobody is reading makes the mediated operation unfinishable, which wedges the
// sandbox and leaves the container unkillable.
func TestAuditSinkNeverBlocks(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	// (*os.File).Fd() puts the descriptor back into blocking mode, so it is
	// called once and the descriptor used directly from then on; calling it
	// again would undo the O_NONBLOCK the sink sets.
	wfd := int(w.Fd())
	sink := newAuditSink(wfd).write

	// Fill the pipe so that any further write would block.
	buf := make([]byte, 4096)
	for {
		if _, err := unix.Write(wfd, buf); err != nil {
			break
		}
	}

	// Writing a record into the full pipe must return rather than wait for a
	// reader.
	done := make(chan struct{})
	go func() {
		sink(`apparmor="DENIED" operation="open" class="file" profile="p" name="/x"`)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writing an audit record to a full pipe blocked; a task would be stuck here")
	}

	// A reader that has gone away must not block or panic either.
	r.Close()
	done = make(chan struct{})
	go func() {
		sink(`apparmor="DENIED" operation="open" class="file" profile="p" name="/y"`)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writing an audit record to a closed pipe blocked")
	}
}

// TestSetAuditSinkDoesNotTakeLoaderMutex covers a precondition that is not
// checked statically: createContainerProcess() holds l.mu when it installs the
// audit sink, so taking l.mu there deadlocks the sandbox before the container's
// first task runs. checklocks does not catch it, so this does.
//
// +checklocksignore
func TestSetAuditSinkDoesNotTakeLoaderMutex(t *testing.T) {
	defer confine.SetAuditSink(nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	wfd := int(w.Fd())

	info := &containerInfo{
		cid: "test-container",
		conf: &config.Config{
			AppArmorPolicySource: "host",
			AppArmorAuditTarget:  "stderr",
		},
		// stdin, stdout, stderr; only stderr is read from here.
		stdioFDs: stdioFDsFor(t, wfd),
	}
	l := &Loader{}

	l.mu.Lock()
	defer l.mu.Unlock()
	done := make(chan struct{})
	go func() {
		l.setAppArmorAuditSink(info)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("installing the audit sink blocked on l.mu, which its caller already holds")
	}
	l.closeAppArmorAuditSink(info.cid)
}

// TestAuditSinkReleasedWhenProcessesExit is the regression test for a
// production defect that made every confined container unkillable.
//
// The sink holds a dup of one of the container's output streams. The runtime
// stops a container by draining that stream and waiting for EOF, which arrives
// only when every writer is closed, and it issues the delete that used to close
// this dup only after that wait returns. So the runtime waited for the sentry
// and the sentry waited to be told to delete: "runsc delete" was never called,
// the dup never closed, and both KillContainer and KillPodSandbox timed out on
// every retry until the node was drained.
//
// The invariant this pins down is that once the container's processes are gone,
// the sentry holds no writer of its streams. It is asserted the way the runtime
// observes it: by reading to EOF.
func TestAuditSinkReleasedWhenProcessesExit(t *testing.T) {
	defer confine.SetAuditSink(nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	wfd := int(w.Fd())

	stdio := stdioFDsFor(t, wfd)
	info := &containerInfo{
		cid: "test-container",
		conf: &config.Config{
			AppArmorPolicySource: "host",
			AppArmorAuditTarget:  "stderr",
		},
		stdioFDs: stdio,
	}
	l := &Loader{}
	l.setAppArmorAuditSink(info)

	// Arm the release, then run the container's processes to completion.
	exited := make(chan struct{})
	l.watchAppArmorAuditSink(info.cid, func() { <-exited })

	// Everything the container itself held on the stream goes away when its
	// last task exits and its FD table is released. The pipe still has this
	// test's own w and the sink's dup.
	for _, f := range stdio {
		f.Close()
	}
	w.Close()
	close(exited)

	// With no writer left, the drain sees EOF. If the sink still holds its
	// dup, this read blocks exactly as the runtime's copy does.
	type result struct {
		n   int
		err error
	}
	got := make(chan result, 1)
	go func() {
		var buf [64]byte
		n, err := r.Read(buf[:])
		got <- result{n, err}
	}()
	select {
	case res := <-got:
		if res.err != io.EOF {
			t.Errorf("reading the container's stream returned (%d, %v), want (0, EOF)", res.n, res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the container's stream never reached EOF after its processes exited: the sentry is still holding a writer, so the runtime would wait forever for the drain and the container would never terminate")
	}
}

// TestReleasingAuditSinkDoesNotWaitOnLoaderMutex covers why the audit sink has
// a lock of its own. Releasing the descriptor must not queue behind l.mu,
// because l.mu is held across destroySubcontainer()'s wait for the container's
// processes to exit; sharing the lock would make the release wait on the very
// teardown that the unreleased descriptor is blocking.
//
// +checklocksignore
func TestReleasingAuditSinkDoesNotWaitOnLoaderMutex(t *testing.T) {
	defer confine.SetAuditSink(nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	info := &containerInfo{
		cid: "test-container",
		conf: &config.Config{
			AppArmorPolicySource: "host",
			AppArmorAuditTarget:  "stderr",
		},
		stdioFDs: stdioFDsFor(t, int(w.Fd())),
	}
	l := &Loader{}
	l.setAppArmorAuditSink(info)

	l.mu.Lock()
	defer l.mu.Unlock()
	done := make(chan struct{})
	go func() {
		l.closeAppArmorAuditSink(info.cid)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("releasing the audit sink blocked on l.mu; teardown holds it while waiting for the processes whose exit triggers this release")
	}
}

// TestAuditSinkReleasedWhenContainerNeverStarts covers the other end of the
// descriptor's life: a container whose process creation fails has no processes
// to wait for, so nothing would ever trigger the release.
func TestAuditSinkReleasedWhenContainerNeverStarts(t *testing.T) {
	defer confine.SetAuditSink(nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	wfd := int(w.Fd())

	stdio := stdioFDsFor(t, wfd)
	info := &containerInfo{
		cid: "test-container",
		conf: &config.Config{
			AppArmorPolicySource: "host",
			AppArmorAuditTarget:  "stderr",
		},
		stdioFDs: stdio,
	}
	l := &Loader{}
	l.setAppArmorAuditSink(info)

	// createContainerProcess() releases the descriptor on every path that
	// does not reach a running process. watchAppArmorAuditSink() is never
	// called, so the release must not depend on it.
	l.closeAppArmorAuditSink(info.cid)

	for _, f := range stdio {
		f.Close()
	}
	w.Close()

	type result struct {
		n   int
		err error
	}
	got := make(chan result, 1)
	go func() {
		var buf [64]byte
		n, err := r.Read(buf[:])
		got <- result{n, err}
	}()
	select {
	case res := <-got:
		if res.err != io.EOF {
			t.Errorf("reading the container's stream returned (%d, %v), want (0, EOF)", res.n, res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the container's stream never reached EOF after a container that never started: a writer leaked")
	}
}

// TestAuditSinkInstalledBeforePolicyLoads covers the ordering that
// --apparmor-policy-source=container imposes: the container's policy is read
// inside createContainerProcess(), after the audit sink is installed, so the
// sink must not be conditioned on a policy already existing. Gating it on that
// silently discarded every record while still enforcing every rule.
//
// +checklocksignore
func TestAuditSinkInstalledBeforePolicyLoads(t *testing.T) {
	for _, tc := range []struct {
		source     string
		wantRecord bool
	}{
		// No policy is loaded yet in either mode at this point.
		{source: "container", wantRecord: true},
		{source: "host", wantRecord: true},
		// With confinement off the container's streams must be left
		// alone entirely; see TestAuditSinkNeverBlocks for why.
		{source: "none", wantRecord: false},
		{source: "", wantRecord: false},
	} {
		t.Run("source="+tc.source, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("os.Pipe: %v", err)
			}
			defer r.Close()
			defer w.Close()
			wfd := int(w.Fd())

			l := &Loader{}
			info := &containerInfo{
				cid: "test-container",
				conf: &config.Config{
					AppArmorPolicySource: tc.source,
					AppArmorAuditTarget:  "stderr",
				},
				stdioFDs: stdioFDsFor(t, wfd),
			}
			confine.SetAuditSink(nil)
			defer confine.SetAuditSink(nil)
			l.mu.Lock()
			l.setAppArmorAuditSink(info)
			l.mu.Unlock()

			// The policy arrives only now, as it does for a container
			// that supplies its own.
			confine.SetPolicy(map[string]*confine.Profile{"p": {Name: "p"}})
			defer confine.SetPolicy(nil)
			creds := auth.NewAnonymousCredentials()
			creds.ConfinementProfile = "p"
			if err := confine.Check(nil, creds, confine.OpOpen, "/denied", vfs.MayRead, linux.FileMode(0644), auth.KUID(0)); err == nil {
				t.Fatal("Check() = nil, want a denial")
			}

			if err := r.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			buf := make([]byte, 4096)
			n, err := r.Read(buf)
			gotRecord := err == nil && n > 0
			if gotRecord != tc.wantRecord {
				t.Errorf("record on the container's stderr = %t, want %t (read %d bytes, err %v): %q",
					gotRecord, tc.wantRecord, n, err, string(buf[:max(n, 0)]))
			}
			if gotRecord && !strings.Contains(string(buf[:n]), `apparmor="DENIED"`) {
				t.Errorf("record = %q, want an apparmor=\"DENIED\" record", string(buf[:n]))
			}
		})
	}
}

// TestAuditSinkWriteAfterCloseGoesNowhere covers what happens to a record
// written while the sink is being closed.
//
// A descriptor number is free for reuse the moment it is closed, so a task that
// was about to write a record would put container audit text into whatever
// descriptor took the number next: another container's output stream, or a file
// the sandbox has open. The sink must refuse to write once closed.
func TestAuditSinkWriteAfterCloseGoesNowhere(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	dup, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	sink := newAuditSink(dup)
	sink.close()

	// The kernel hands out the lowest free descriptor, so the file opened
	// here usually lands on the number the sink just released. That is
	// exactly the aliasing a write after close would corrupt.
	victim, err := os.CreateTemp(t.TempDir(), "victim")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer victim.Close()
	if got := int(victim.Fd()); got != dup {
		t.Logf("the freed descriptor %d was not reused (got %d); the write is still asserted to go nowhere", dup, got)
	}

	sink.write(`apparmor="DENIED" operation="open" class="file" profile="p" name="/x"`)
	// Idempotent, and still no write.
	sink.close()
	sink.write(`apparmor="DENIED" operation="open" class="file" profile="p" name="/y"`)

	if fi, err := victim.Stat(); err != nil {
		t.Fatalf("Stat: %v", err)
	} else if fi.Size() != 0 {
		var buf [256]byte
		n, _ := victim.ReadAt(buf[:], 0)
		t.Errorf("an audit record was written into an unrelated file after the sink was closed: %q", string(buf[:n]))
	}
}

// TestAuditSinkConcurrentWriteAndClose exercises the same aliasing under the
// race detector, in the shape it takes in the sandbox: many tasks reporting
// denials while the container's processes exit and the sink is released.
func TestAuditSinkConcurrentWriteAndClose(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	// Drain, so writers are not merely filling the pipe.
	go func() {
		var buf [4096]byte
		for {
			if _, err := r.Read(buf[:]); err != nil {
				return
			}
		}
	}()

	dup, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	sink := newAuditSink(dup)

	const writers = 8
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				sink.write(`apparmor="DENIED" operation="open" class="file" profile="p" name="/x"`)
			}
		}()
	}
	// Close underneath them, twice, as teardown and the exit watcher can
	// both reach it.
	sink.close()
	sink.close()
	close(stop)
	wg.Wait()
}
