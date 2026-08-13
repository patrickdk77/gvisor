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

// Benchmarks of the enforcement engine.
//
// Every mediated access reaches Check(), so its cost is paid on every open a
// confined task makes, and a production profile holds one to two thousand
// rules once its variables are expanded. The sizes here are chosen to bracket
// that: the shape of the rules is the same at every size, so what changes
// between them is only how many rules a check has to consider.
//
// The DFA and Linear pairs measure one rule set both ways. markFullForTest()
// makes the automaton decline to answer, which is what it does for a profile
// too large to compile, and Check() then matches the rules one at a time; the
// pair is therefore a comparison of the two strategies rather than of two
// profiles.

package confine

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	// benchProfile is the profile the benchmarked task has entered.
	benchProfile = "bench"

	// benchUID is the UID of the benchmarked task, and of the files an
	// owner rule is expected to grant it.
	benchUID = auth.KUID(1000)

	// benchOtherUID owns a file the benchmarked task does not.
	benchOtherUID = auth.KUID(2000)

	// benchMode is the mode of the files being accessed. It is a regular
	// file: a directory is not asked for the write and exec permissions,
	// so it would skip most of the work.
	benchMode = linux.FileMode(0644)
)

const (
	// benchAllowedPath is a tenant's own file, which the first rule of
	// every profile below grants through an owner rule. It is as deep as
	// the paths a hosting profile mediates, since the cost of the
	// automaton is the length of the path.
	benchAllowedPath = "/var/www/vhosts/x/y/site.example/www/index.php"

	// benchNestedPath is benchAllowedPath with one more component, used
	// for the pattern whose wildcards have to be searched twice.
	benchNestedPath = "/var/www/vhosts/x/y/site.example/www/sub/index.php"

	// benchReadOnlyPath is granted read and nothing else, so a write to it
	// is denied by a rule that matched rather than by no rule matching.
	benchReadOnlyPath = "/etc/php8/php.ini"

	// benchNoRulePath is matched by no rule at all, which is the denial
	// that always produces a record.
	benchNoRulePath = "/srv/absent/no-such-file"
)

// benchRules returns n rules of the shapes a production profile has once its
// variables are expanded: deep tenant trees, owner-qualified rules, '**' and
// '?' wildcards and character classes.
//
// The first ten are the rules the benchmark paths are matched by, so that every
// size grants and denies exactly the same paths, and no pattern contains a
// brace alternation, which would stop the whole profile from compiling and
// leave the DFA benchmarks measuring the rule walk.
func benchRules(n int) []Rule {
	rules := []Rule{
		{
			Pattern: "/var/www/vhosts/?/?/*/www/**",
			Perms:   ParsePerms("rwkml"),
			Owner:   true,
		},
		{
			Pattern: "/var/www/vhosts/assets/**",
			Perms:   ParsePerms("rk"),
		},
		{Pattern: "/etc/**", Perms: ParsePerms("r")},
		{
			Pattern: "/etc/apache2/**",
			Perms:   ParsePerms("rwlkx"),
			Deny:    true,
		},
		{Pattern: "/usr/lib/**.so*", Perms: ParsePerms("mr")},
		{Pattern: "/usr/lib*/*", Perms: ParsePerms("mr")},
		{Pattern: "/usr/bin/*", Perms: ParsePerms("ixr")},
		{Pattern: "/proc/[0-9]*/stat", Perms: ParsePerms("r")},
		{Pattern: "/tmp/**", Perms: ParsePerms("rwmlk")},
		{Pattern: "/dev/urandom", Perms: ParsePerms("r")},
	}
	if n < len(rules) {
		panic(fmt.Sprintf("benchRules(%d): the benchmark paths need "+
			"the first %d rules", n, len(rules)))
	}
	// One group per tenant, as a hosting profile has after expansion. The
	// tenants share the first component of their patterns, which is what
	// makes the rule walk consider all of them for one path.
	for i := 0; len(rules) < n; i++ {
		site := fmt.Sprintf("site%04d.example", i)
		dir := "/var/www/vhosts/s/i/" + site
		rules = append(rules,
			Rule{
				Pattern: dir + "/www/**",
				Perms:   ParsePerms("rwkml"),
				Owner:   true,
			},
			Rule{
				Pattern: dir + "/logs/*.log",
				Perms:   ParsePerms("w"),
				Owner:   true,
			},
			Rule{
				Pattern: dir + "/private/**",
				Perms:   ParsePerms("rwx"),
				Deny:    true,
			},
			Rule{
				Pattern: "/home/" + site + "/.config/**",
				Perms:   ParsePerms("r"),
				Owner:   true,
			},
			Rule{
				Pattern: "/srv/" + site + "/tmp/**",
				Perms:   ParsePerms("rw"),
				Owner:   true,
			},
			Rule{
				Pattern: "/etc/nginx/sites/" + site + ".conf",
				Perms:   ParsePerms("r"),
			},
			Rule{
				Pattern: "/var/cache/" + site + "/**",
				Perms:   ParsePerms("rw"),
				Owner:   true,
			},
			Rule{
				Pattern: "/usr/lib/" + site + "/*.so",
				Perms:   ParsePerms("mr"),
			},
		)
	}
	return rules[:n]
}

// benchCreds returns the credentials of a task in label. The engine reads only
// the label and the UID, so there is no need for a user namespace.
func benchCreds(label string) *auth.Credentials {
	return &auth.Credentials{
		ConfinementProfile: label,
		EffectiveKUID:      benchUID,
	}
}

// installBenchProfile installs one profile of n rules. If linear is set the
// automaton is made to decline every path, which is how the rule walk is
// measured against the automaton on the same rules.
func installBenchProfile(tb testing.TB, n int, linear bool) {
	p := &Profile{Name: benchProfile, Rules: benchRules(n)}
	SetPolicy(map[string]*Profile{benchProfile: p})
	tb.Cleanup(func() { SetPolicy(nil) })
	if p.dfa == nil {
		tb.Fatal("the rules did not compile, so a DFA benchmark " +
			"would measure the rule walk instead")
	}
	if linear {
		p.dfa.markFullForTest()
	}
}

// checkCase is one access measured by run().
type checkCase struct {
	// rules is how many rules the profile holds.
	rules int

	// linear forces the rule walk instead of the automaton.
	linear bool

	// path is the path being accessed.
	path string

	// ats is the access requested.
	ats vfs.AccessTypes

	// kuid owns the file.
	kuid auth.KUID

	// wantErr is whether the access must be denied. It is checked on
	// every iteration, so that a benchmark cannot silently end up
	// measuring the other decision.
	wantErr bool
}

// run measures Check() for the case.
func (c checkCase) run(b *testing.B) {
	b.ReportAllocs()
	installBenchProfile(b, c.rules, c.linear)
	creds := benchCreds(benchProfile)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Check(bgCtx, creds, OpFperm, c.path, c.ats, benchMode, c.kuid)
		if gotErr := err != nil; gotErr != c.wantErr {
			b.Fatalf("Check(%q) = %v, wantErr %t",
				c.path, err, c.wantErr)
		}
	}
	b.StopTimer()
}

// benchAllowed is a read of a file the profile's owner rule grants.
func benchAllowed(rules int, linear bool) checkCase {
	return checkCase{
		rules:  rules,
		linear: linear,
		path:   benchAllowedPath,
		ats:    vfs.MayRead,
		kuid:   benchUID,
	}
}

// benchDenied is a write to a path the profile grants only read, which is the
// denial a production profile produces most: a rule matched, but not for the
// permission asked for.
func benchDenied(rules int, linear bool) checkCase {
	return checkCase{
		rules:   rules,
		linear:  linear,
		path:    benchReadOnlyPath,
		ats:     vfs.MayWrite,
		kuid:    benchUID,
		wantErr: true,
	}
}

func BenchmarkCheckAllowed10DFA(b *testing.B) {
	benchAllowed(10, false).run(b)
}

func BenchmarkCheckAllowed10Linear(b *testing.B) {
	benchAllowed(10, true).run(b)
}

func BenchmarkCheckAllowed100DFA(b *testing.B) {
	benchAllowed(100, false).run(b)
}

func BenchmarkCheckAllowed100Linear(b *testing.B) {
	benchAllowed(100, true).run(b)
}

func BenchmarkCheckAllowed1000DFA(b *testing.B) {
	benchAllowed(1000, false).run(b)
}

func BenchmarkCheckAllowed1000Linear(b *testing.B) {
	benchAllowed(1000, true).run(b)
}

func BenchmarkCheckAllowed2000DFA(b *testing.B) {
	benchAllowed(2000, false).run(b)
}

func BenchmarkCheckAllowed2000Linear(b *testing.B) {
	benchAllowed(2000, true).run(b)
}

func BenchmarkCheckDenied10DFA(b *testing.B) {
	benchDenied(10, false).run(b)
}

func BenchmarkCheckDenied10Linear(b *testing.B) {
	benchDenied(10, true).run(b)
}

func BenchmarkCheckDenied100DFA(b *testing.B) {
	benchDenied(100, false).run(b)
}

func BenchmarkCheckDenied100Linear(b *testing.B) {
	benchDenied(100, true).run(b)
}

func BenchmarkCheckDenied1000DFA(b *testing.B) {
	benchDenied(1000, false).run(b)
}

func BenchmarkCheckDenied1000Linear(b *testing.B) {
	benchDenied(1000, true).run(b)
}

func BenchmarkCheckDenied2000DFA(b *testing.B) {
	benchDenied(2000, false).run(b)
}

func BenchmarkCheckDenied2000Linear(b *testing.B) {
	benchDenied(2000, true).run(b)
}

// BenchmarkCheckUnconfined measures the path taken for a task that has entered
// no profile, which is most of them, with a policy installed as there is in
// production. Nothing is evaluated, so this is the floor the mediation of every
// file access adds.
func BenchmarkCheckUnconfined(b *testing.B) {
	b.ReportAllocs()
	installBenchProfile(b, 1000, false)
	creds := benchCreds("")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Check(bgCtx, creds, OpFperm, benchAllowedPath, vfs.MayRead,
			benchMode, benchUID)
		if err != nil {
			b.Fatalf("Check for an unconfined task = %v, want nil",
				err)
		}
	}
	b.StopTimer()
}

// benchStacked measures a label of n stacked profiles, each of which must
// permit the access.
func benchStacked(b *testing.B, n int) {
	b.ReportAllocs()
	profiles := make(map[string]*Profile, n)
	label := ""
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s%d", benchProfile, i)
		profiles[name] = &Profile{
			Name:  name,
			Rules: benchRules(1000),
		}
		label = StackLabel(label, name)
	}
	SetPolicy(profiles)
	b.Cleanup(func() { SetPolicy(nil) })
	for name, p := range profiles {
		if p.dfa == nil {
			b.Fatalf("profile %q did not compile", name)
		}
	}
	creds := benchCreds(label)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Check(bgCtx, creds, OpFperm, benchAllowedPath, vfs.MayRead,
			benchMode, benchUID)
		if err != nil {
			b.Fatalf("Check(%q) = %v, want nil",
				benchAllowedPath, err)
		}
	}
	b.StopTimer()
}

func BenchmarkCheckStacked2(b *testing.B) {
	benchStacked(b, 2)
}

func BenchmarkCheckStacked4(b *testing.B) {
	benchStacked(b, 4)
}

// BenchmarkCheckOwnerOwned measures an owner rule granting a task that owns the
// file.
func BenchmarkCheckOwnerOwned(b *testing.B) {
	checkCase{
		rules: 1000,
		path:  benchAllowedPath,
		ats:   vfs.MayRead,
		kuid:  benchUID,
	}.run(b)
}

// BenchmarkCheckOwnerNotOwned measures the same rule against a task that does
// not own the file. No other rule matches the path, so the access is denied and
// the cost includes the record the denial produces.
func BenchmarkCheckOwnerNotOwned(b *testing.B) {
	checkCase{
		rules:   1000,
		path:    benchAllowedPath,
		ats:     vfs.MayRead,
		kuid:    benchOtherUID,
		wantErr: true,
	}.run(b)
}

// benchNoRule is a read of a path no rule matches, which is always recorded and
// so always formats a record.
func benchNoRule() checkCase {
	return checkCase{
		rules:   1000,
		path:    benchNoRulePath,
		ats:     vfs.MayRead,
		kuid:    benchUID,
		wantErr: true,
	}
}

// BenchmarkCheckDeniedNoRuleSink measures that denial with a sink installed
// that does nothing, so the cost of formatting the record is measured without
// the cost of writing it anywhere.
func BenchmarkCheckDeniedNoRuleSink(b *testing.B) {
	SetTestLogSink(func(string) {})
	b.Cleanup(func() { SetTestLogSink(nil) })
	benchNoRule().run(b)
}

// BenchmarkCheckDeniedNoRuleNoSink measures the same denial with no sink.
// audit() builds the record before emit() looks for a sink, so this is expected
// to cost the same as the benchmark above: a denial pays for its record whether
// or not anything is listening.
func BenchmarkCheckDeniedNoRuleNoSink(b *testing.B) {
	SetTestLogSink(nil)
	benchNoRule().run(b)
}

// BenchmarkMatchPattern measures the pattern matcher on its own, which is what
// the rule walk, the link rules, GrantedPerms() and the change_profile and exec
// rules all call and the automaton replaces.
func BenchmarkMatchPattern(b *testing.B) {
	for _, tc := range []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{
			name: "literal", pattern: "/etc/ld.so.cache",
			path: "/etc/ld.so.cache", want: true,
		},
		{
			name: "literal-miss", pattern: "/etc/ld.so.cache",
			path: "/etc/ld.so.conf", want: false,
		},
		{
			name: "subtree", pattern: "/var/www/vhosts/**",
			path: benchAllowedPath, want: true,
		},
		{
			name:    "components-miss",
			pattern: "/var/www/?/?/*/www/**",
			path:    benchAllowedPath, want: false,
		},
		{
			name:    "components-match",
			pattern: "/var/www/vhosts/?/?/*/www/**",
			path:    benchAllowedPath, want: true,
		},
		{
			name: "suffix-star", pattern: "/usr/lib/**.so*",
			path: "/usr/lib/x86_64-linux-gnu/libc.so.6",
			want: true,
		},
		{
			name: "class", pattern: "/proc/[0-9]*/stat",
			path: "/proc/12345/stat", want: true,
		},
		{
			name: "negated-class", pattern: "/proc/[^0-9]*/stat",
			path: "/proc/12345/stat", want: false,
		},
		{
			name:    "alternation",
			pattern: "/etc/{php7,php8,php8.2}/conf.d/*.ini",
			path:    "/etc/php8.2/conf.d/opcache.ini", want: true,
		},
		{
			name:    "nested-doublestar",
			pattern: "/var/**/www/**/index.php",
			path:    benchNestedPath, want: true,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				got := MatchPattern(tc.pattern, tc.path)
				if got != tc.want {
					b.Fatalf("MatchPattern(%q, %q) = %v, "+
						"want %v", tc.pattern, tc.path,
						got, tc.want)
				}
			}
			b.StopTimer()
		})
	}
}

// benchCold measures the first Check() against a policy that has just been
// installed. The states of the automaton are built as paths reach them, so this
// is what the first task to touch a path pays and what a profile of many rules
// makes expensive; the warm benchmarks below are the steady state that follows.
//
// The timer is stopped while the policy is installed, so the result includes
// one stop and start of the timer per iteration.
func benchCold(b *testing.B, n int) {
	b.ReportAllocs()
	creds := benchCreds(benchProfile)
	b.Cleanup(func() { SetPolicy(nil) })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		p := &Profile{Name: benchProfile, Rules: benchRules(n)}
		SetPolicy(map[string]*Profile{benchProfile: p})
		if p.dfa == nil {
			b.Fatal("the rules did not compile")
		}
		b.StartTimer()
		err := Check(bgCtx, creds, OpFperm, benchAllowedPath, vfs.MayRead,
			benchMode, benchUID)
		if err != nil {
			b.Fatalf("Check(%q) = %v, want nil",
				benchAllowedPath, err)
		}
	}
	b.StopTimer()
}

func BenchmarkCheckCold1000(b *testing.B) {
	benchCold(b, 1000)
}

// BenchmarkCheckWarm1000 is the steady state to compare
// BenchmarkCheckCold1000 against: the same profile and path, with the states
// the path needs already built.
func BenchmarkCheckWarm1000(b *testing.B) {
	benchAllowed(1000, false).run(b)
}

func BenchmarkCheckCold2000(b *testing.B) {
	benchCold(b, 2000)
}

// BenchmarkCheckWarm2000 is the steady state to compare
// BenchmarkCheckCold2000 against.
func BenchmarkCheckWarm2000(b *testing.B) {
	benchAllowed(2000, false).run(b)
}
