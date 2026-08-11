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
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sync"
)

// dfaTestRules covers each pattern shape the compiler has to handle, with
// overlapping patterns so that a path reaches several rules at once.
var dfaTestRules = []Rule{
	{Pattern: "/etc/passwd", Perms: ParsePerms("r")},
	{Pattern: "/etc/**", Perms: ParsePerms("r")},
	{Pattern: "/etc/shadow", Perms: ParsePerms("rw"), Deny: true},
	{Pattern: "/bin/", Perms: ParsePerms("r")},
	{Pattern: "/bin/*", Perms: ParsePerms("rx")},
	{Pattern: "/usr/lib*/*", Perms: ParsePerms("mr")},
	{Pattern: "/usr/lib/**", Perms: ParsePerms("mr")},
	{Pattern: "/var/www/?/?/*/**", Perms: ParsePerms("rw"), Owner: true},
	{Pattern: "/var/www/assets/**", Perms: ParsePerms("rk")},
	{Pattern: "/proc/[0-9]*/mem", Perms: ParsePerms("rw"), Deny: true},
	{Pattern: "/sys/[^f]*/**", Perms: ParsePerms("w"), Deny: true},
	{Pattern: "/**", Perms: ParsePerms("r")},
	{Pattern: "/tmp/x?z", Perms: ParsePerms("rw")},
	{Pattern: "/opt/a[bc]d/**", Perms: ParsePerms("rwx")},
}

// dfaTestPaths are matched against every rule. They are built to land on both
// sides of each pattern's boundaries.
var dfaTestPaths = []string{
	"/", "/etc", "/etc/", "/etc/passwd", "/etc/passwdx", "/etc/shadow",
	"/etc/apache2/sites/a.conf", "/bin", "/bin/", "/bin/sh", "/bin/sub/dir",
	"/usr/lib/libc.so", "/usr/lib64/libc.so", "/usr/lib/x86_64/libc.so",
	"/usr/libexec/thing", "/var/www/a/b/site/index.html",
	"/var/www/a/b/site/", "/var/www/aa/b/site/x", "/var/www/assets/i.html",
	"/proc/1/mem", "/proc/self/mem", "/proc/12/mem", "/sys/devices/cpu/online",
	"/sys/fs/cgroup/x", "/tmp/xyz", "/tmp/xz", "/tmp/xyyz",
	"/opt/abd/x", "/opt/azd/x", "/opt/abd/", "/a/b/c/d/e",
	"", "//", "/etc//passwd", "/\x00/x", "/\xff\xfe",
}

// TestDFAMatchesLinear holds the compiled automaton against matching the rules
// one at a time. The two must agree exactly: the automaton is what runs, and
// the rule walk is the readable definition of what a profile means.
func TestDFAMatchesLinear(t *testing.T) {
	p := &Profile{Name: "p", Rules: dfaTestRules}
	p.index()
	if p.dfa == nil {
		t.Fatal("rules did not compile")
	}
	for _, path := range dfaTestPaths {
		for _, owned := range []bool{true, false} {
			var wantG, wantD Perm
			for i := range p.Rules {
				r := &p.Rules[i]
				if !MatchPattern(r.Pattern, path) {
					continue
				}
				switch {
				case r.Deny:
					wantD |= r.Perms
				case r.Owner && !owned:
				default:
					wantG |= r.Perms
				}
			}
			a, ok := p.dfa.match(path)
			if !ok {
				t.Fatalf("path %q: automaton could not answer", path)
			}
			gotG := a.allowAny
			if owned {
				gotG |= a.allowOwner
			}
			if gotG != wantG || a.deny != wantD {
				t.Errorf("path %q owned=%t: automaton granted=%b denied=%b, rule walk granted=%b denied=%b",
					path, owned, gotG, a.deny, wantG, wantD)
			}
		}
	}
}

// TestDFAIsLazy checks that compiling a profile builds only the start state, so
// that policy load does not pay for states no path reaches. Compiling a real
// profile in full took seconds and megabytes.
func TestDFAIsLazy(t *testing.T) {
	p := &Profile{Name: "p", Rules: dfaTestRules}
	p.index()
	if got := p.dfa.numStates(); got != 2 {
		t.Errorf("a freshly compiled profile has %d states, want 2 (dead and start)", got)
	}
	if _, ok := p.dfa.match("/usr/lib/libc.so"); !ok {
		t.Fatal("automaton could not answer")
	}
	if p.dfa.numStates() <= 2 {
		t.Error("matching a path built no states")
	}
}

// TestDFAFallsBackWhenFull checks that reaching the state ceiling makes the
// automaton decline to answer, so that Check matches the rules instead of
// returning a wrong result or growing without bound.
func TestDFAFallsBackWhenFull(t *testing.T) {
	p := &Profile{Name: "p", Rules: dfaTestRules}
	p.index()
	p.dfa.markFullForTest()
	if _, ok := p.dfa.match("/etc/passwd"); ok {
		t.Error("a full automaton answered instead of declining")
	}
	// Check must still reach the right answer through the rule walk.
	SetPolicy(map[string]*Profile{"p": p})
	defer SetPolicy(nil)
	p.dfa.markFullForTest()
	if err := p.checkLinear("/etc/passwd", Read, false); err != nil {
		t.Errorf("checkLinear(/etc/passwd, Read) = %v, want nil", err)
	}
	if err := p.checkLinear("/etc/shadow", Read, false); err == nil {
		t.Error("checkLinear(/etc/shadow, Read) = nil, want a denial")
	}
}

// TestDFAByteClasses checks that a negated character class does not force every
// byte into its own equivalence class, which overflowed the class count and made
// the transition table 256 wide.
func TestDFAByteClasses(t *testing.T) {
	p := &Profile{Name: "p", Rules: []Rule{
		{Pattern: "/sys/[^f]*/**", Perms: ParsePerms("r")},
		{Pattern: "/proc/[^1-9]*/x", Perms: ParsePerms("r")},
	}}
	p.index()
	if p.dfa == nil {
		t.Fatal("rules did not compile")
	}
	// The patterns distinguish '/', 'f', '1'-'9', and the literal letters of
	// "sys", "proc" and "x"; everything else shares a class.
	if got := p.dfa.numClasses; got < 2 || got > 32 {
		t.Errorf("numClasses = %d, want a small number of classes", got)
	}
}

// TestDFAConcurrentMatch exercises building states from several goroutines,
// which is how tasks in one profile reach the automaton.
func TestDFAConcurrentMatch(t *testing.T) {
	p := &Profile{Name: "p", Rules: dfaTestRules}
	p.index()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				path := fmt.Sprintf("/var/www/a/b/site/%d/%d", g, i)
				if _, ok := p.dfa.match(path); !ok {
					t.Errorf("automaton could not answer for %q", path)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestDFALongPath checks a path far longer than any pattern, which must reach
// the dead state rather than run off the transition table.
func TestDFALongPath(t *testing.T) {
	p := &Profile{Name: "p", Rules: []Rule{
		{Pattern: "/etc/passwd", Perms: ParsePerms("r")},
	}}
	p.index()
	a, ok := p.dfa.match("/etc/passwd" + strings.Repeat("x", 4096))
	if !ok {
		t.Fatal("automaton could not answer")
	}
	if a.allowAny != 0 {
		t.Errorf("granted %b for a path no rule matches", a.allowAny)
	}
}
