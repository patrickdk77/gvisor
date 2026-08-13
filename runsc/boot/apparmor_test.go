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
	"reflect"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/confine"
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
	// "file," is every access to every path; without it a profile that
	// relies on it is reduced to its deny rules and denies everything.
	wantRules := []confine.Rule{
		{Pattern: "/**", Perms: confine.ParsePerms("mrwlkix")},
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
		{Pattern: "/**", Perms: confine.ParsePerms("mrwlkix"), Deny: true},
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
  deny change_profile -> jailroot,
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
			{Pattern: "jailroot", Deny: true},
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
	// A deny rule with an exec condition would apply more widely than the
	// profile says, so it is reported as unenforced instead.
	if cp := policy.Rules["s"]; cp != nil && len(cp.ChangeProfile) != 0 {
		t.Errorf(`Rules["s"].ChangeProfile = %+v, want none`, cp.ChangeProfile)
	}
	var found bool
	for _, u := range policy.Unenforced {
		if u.Profile == "s" {
			found = true
		}
	}
	if !found {
		t.Error("a deny change_profile with an exec condition was not reported as unenforced")
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
  /bin/named mrpx -> jail,
  /bin/scrubbed mrPx -> jail,
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
		{Pattern: "/bin/named", Mode: confine.ExecProfile, Target: "jail"},
		{Pattern: "/bin/scrubbed", Mode: confine.ExecProfile, Target: "jail", Scrub: true},
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
