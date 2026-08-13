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

// The engine here is reached by every task in a sandbox on every file access,
// its policy is installed once during startup, and its automaton builds states
// the first time a path reaches them, under a lock. That combination is what
// these tests stress: many tasks driving lazy state construction of one
// profile at once, a profile large enough that the state ceiling is reached and
// matching falls back to walking the rules, paths and patterns at the sizes
// real policy and real workloads produce, a policy being replaced while checks
// run, a flood of denials through the record path, and a stacked label whose
// every profile is evaluated.
//
// Run these with the race detector, which is what makes the concurrency ones
// worth anything:
//
//	bazel test --config=race //pkg/sentry/confine:confine_test \
//	    --test_filter=TestStress
//
// Every phase is bounded by an explicit deadline and fails with a message
// saying so. A test in this package must never hang: the engine holds a lock
// while it builds automaton states, so a hang here looks exactly like the
// production symptom being investigated, and a test that hangs reports it as
// a timeout with no detail instead of a failure that names the phase.
//
// These tests share the package's global policy and audit sink, so none of
// them calls t.Parallel().

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	gverrors "gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// stressUID is the UID the stressing tasks run as, so that an 'owner'
	// rule grants for a file it owns.
	stressUID = auth.KUID(1000)

	// stressOtherUID owns the files the stressing tasks do not, which is
	// what makes an 'owner' rule deny.
	stressOtherUID = auth.KUID(2000)

	// stressMaxReported caps how many worker failures are printed, since a
	// wrong answer under contention tends to repeat for every path.
	stressMaxReported = 8
)

// stressLimit is how long one phase may run before it is called a hang. The
// phases below take well under a second on an idle machine, so the limit is
// generous enough that only a stuck check reaches it.
func stressLimit() time.Duration {
	if testing.Short() {
		return 15 * time.Second
	}
	return 30 * time.Second
}

// stressWorkers is how many goroutines drive the engine at once. It
// oversubscribes the available parallelism so that a goroutine is preempted
// while it waits for the automaton's lock, which is what interleaves lazy
// state construction with matching.
func stressWorkers() int {
	n := 4 * runtime.GOMAXPROCS(0)
	if n < 8 {
		n = 8
	}
	if n > 16 {
		n = 16
	}
	return n
}

// stressPasses is how many times each worker walks the corpus.
func stressPasses() int {
	if testing.Short() {
		return 1
	}
	return 2
}

// stressFailures collects failures reported from worker goroutines.
//
// A worker must not call t.Errorf: when a phase misses its deadline the test
// goroutine returns while the workers are still running, and touching t after
// a test has completed panics, which would bury the deadline failure that is
// the actual finding.
type stressFailures struct {
	mu    sync.Mutex
	total int
	msgs  []string
}

// errorf records one failure.
func (f *stressFailures) errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.total++
	if len(f.msgs) < stressMaxReported {
		f.msgs = append(f.msgs, fmt.Sprintf(format, args...))
	}
}

// report fails the test with what the workers found.
func (f *stressFailures) report(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.msgs {
		t.Error(m)
	}
	if f.total > len(f.msgs) {
		t.Errorf("and %d further failures that were not reported",
			f.total-len(f.msgs))
	}
}

// stressWait waits for the workers of one phase, and fails the test rather
// than hanging if they do not finish in time.
func stressWait(t *testing.T, wg *sync.WaitGroup, what string) {
	t.Helper()
	limit := stressLimit()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not finish within %v, so a check is stuck. "+
			"The engine holds the automaton's lock while it builds "+
			"states, so treat this as a hang in the engine and not "+
			"as a slow machine; the goroutines are left running "+
			"deliberately so a stack dump names the lock.",
			what, limit)
	}
}

// stressRun runs one bounded phase that needs no concurrency of its own, so
// that a single check which never returns is reported as a hang in that phase
// instead of stopping the whole test binary. fn must not use *testing.T, for
// the reason stressFailures explains.
func stressRun(t *testing.T, what string, fn func()) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn()
	}()
	stressWait(t, &wg, what)
}

// stressCreds is the credentials of a task in the named profile.
func stressCreds(profile string, uid auth.KUID) *auth.Credentials {
	creds := auth.NewAnonymousCredentials()
	creds.EffectiveKUID = uid
	creds.ConfinementProfile = profile
	return creds
}

// stressApps is how many programs the generated profile covers. Each one
// contributes the eight rules below, which is what a profile set for a
// multi-tenant host looks like: a few shapes repeated per tenant.
const stressApps = 188

// stressRules builds a profile of at least n rules, using the pattern shapes
// real policy contains: a literal prefix with a wildcard component, a '**'
// subtree, a suffix wildcard, an 'owner' rule, a 'deny' rule, a character
// class, and a rule whose '?' components must not match a longer one.
func stressRules() []Rule {
	rules := make([]Rule, 0, 8*stressApps)
	for i := 0; i < stressApps; i++ {
		app := fmt.Sprintf("app%04d", i)
		rules = append(rules,
			Rule{Pattern: "/opt/" + app + "/bin/*", Perms: ParsePerms("rix")},
			Rule{Pattern: "/opt/" + app + "/lib/**", Perms: ParsePerms("mr")},
			Rule{Pattern: "/opt/" + app + "/etc/*.conf", Perms: ParsePerms("r")},
			Rule{Pattern: "/opt/" + app + "/etc/secret*", Perms: ParsePerms("rw"), Deny: true},
			Rule{Pattern: "/var/log/" + app + "/*.log", Perms: ParsePerms("rw"), Owner: true},
			Rule{Pattern: "/var/cache/" + app + "/**", Perms: ParsePerms("rwk")},
			Rule{Pattern: "/run/" + app + "/[0-9]*/sock", Perms: ParsePerms("rw")},
			Rule{Pattern: "/srv/" + app + "/?/?/pub/**", Perms: ParsePerms("r")},
		)
	}
	return rules
}

// stressAccess is one access a worker makes.
type stressAccess struct {
	path string
	ats  vfs.AccessTypes
	mode linux.FileMode
	kuid auth.KUID
}

// stressCorpus builds n accesses over the profile stressRules() produces. The
// paths are distinct so that each one reaches states no other path has built,
// which is the contention this stresses, and they land on both sides of every
// rule: permitted, denied by a deny rule, denied for want of ownership, and
// matched by no rule at all.
func stressCorpus(n int) []stressAccess {
	shapes := []struct {
		format string
		ats    vfs.AccessTypes
		mode   linux.FileMode
		kuid   auth.KUID
	}{
		{"/opt/%s/bin/tool%d", vfs.MayRead | vfs.MayExec, 0755, 0},
		{"/opt/%s/lib/v%d/libx.so", vfs.MayRead, 0644, 0},
		{"/opt/%s/etc/site%d.conf", vfs.MayRead, 0644, 0},
		// Denied by the deny rule, whichever allow rule matches.
		{"/opt/%s/etc/secret%d.conf", vfs.MayRead, 0600, 0},
		// Granted by an owner rule, to the owner.
		{"/var/log/%s/access%d.log", vfs.MayWrite, 0644, stressUID},
		// The same rule, to a task that does not own the file.
		{"/var/log/%s/other%d.log", vfs.MayWrite, 0644, stressOtherUID},
		{"/var/cache/%s/%d/blob", vfs.MayRead | vfs.MayWrite, 0644, stressUID},
		// A directory, which is mediated with a trailing slash.
		{"/var/cache/%s/%d/", vfs.MayRead, linux.ModeDirectory | 0755, stressUID},
		{"/run/%s/%d/sock", vfs.MayRead | vfs.MayWrite, 0666, 0},
		{"/srv/%s/a/b/pub/page%d.html", vfs.MayRead, 0644, 0},
		// The '?' components of that rule must not match "aa".
		{"/srv/%s/aa/b/pub/page%d.html", vfs.MayRead, 0644, 0},
		// No rule matches this at all.
		{"/nowhere/%s/%d", vfs.MayRead, 0644, 0},
	}
	out := make([]stressAccess, 0, n)
	for i := 0; len(out) < n; i++ {
		s := shapes[i%len(shapes)]
		app := fmt.Sprintf("app%04d", i%stressApps)
		out = append(out, stressAccess{
			path: fmt.Sprintf(s.format, app, i),
			ats:  s.ats,
			mode: s.mode,
			kuid: s.kuid,
		})
	}
	return out
}

// stressAnswer is what one check decided, which is all a worker compares: the
// engine's answer must not depend on how many tasks asked at once.
type stressAnswer struct {
	denied bool
	errno  int32
}

// stressCheck makes one access.
func stressCheck(creds *auth.Credentials, c *stressAccess) stressAnswer {
	err := Check(bgCtx, creds, OpFperm, c.path, c.ats, c.mode, c.kuid)
	return stressAnswer{denied: err != nil, errno: errnoOf(err)}
}

// stressRuleWalk is what a profile's rules grant and deny for path, matched
// one rule at a time. It is the readable definition of what a profile means,
// and is used here as a second opinion on the automaton at a rule count the
// hand-written cases in dfa_test.go do not reach.
func stressRuleWalk(rules []Rule, path string, owned bool) (granted, denied Perm) {
	for i := range rules {
		r := &rules[i]
		if !MatchPattern(r.Pattern, path) {
			continue
		}
		switch {
		case r.Deny:
			denied |= r.Perms
		case r.Owner && !owned:
		default:
			granted |= r.Perms
		}
	}
	return granted, denied
}

// TestStressConcurrentCheck drives one large profile from many goroutines over
// paths none of them has used before, so that the automaton's states are built
// under contention. Every answer must equal the answer a single-threaded run
// gives for the same access: a state built while another task is matching must
// not be visible half-built, and a task must not be given the answer that
// belongs to another path.
//
// No data race is possible by design, and the race detector is what holds that
// claim up. The pieces are:
//
//   - policy.profiles is replaced as a whole under policy.mu, and profileFor
//     takes it for reading, so a check either sees the whole policy or the
//     previous one.
//   - a *Profile's own fields are written by index() before SetPolicy
//     publishes it, and are read-only afterwards, so profile.dfa needs no
//     lock of its own.
//   - every field of the automaton that lazy construction writes is annotated
//     +checklocks:mu, dfa.match takes mu for reading to walk and for writing
//     to build, and a set built by the builder is copied out before it is
//     stored, so no two goroutines touch the same scratch.
func TestStressConcurrentCheck(t *testing.T) {
	rules := stressRules()
	if len(rules) < 1500 {
		t.Fatalf("the generated profile has %d rules, want at least 1500: "+
			"the point of this test is a profile large enough that "+
			"lazy state construction matters", len(rules))
	}
	// Two profiles with identical rules and separate automata: one is
	// warmed single-threaded and is the answer to beat, the other is left
	// cold for the workers to build.
	hot := &Profile{Name: "stress", Rules: rules}
	golden := &Profile{Name: "stress-golden", Rules: rules}
	SetPolicy(map[string]*Profile{
		"stress":        hot,
		"stress-golden": golden,
	})
	defer SetPolicy(nil)
	if hot.dfa == nil || golden.dfa == nil {
		t.Fatalf("a profile of %d rules did not compile to an automaton, "+
			"so this test would only exercise the rule walk", len(rules))
	}

	size := 1200
	oracle := 200
	if !testing.Short() {
		size = 4000
		oracle = 1000
	}
	corpus := stressCorpus(size)

	// The single-threaded answers.
	want := make([]stressAnswer, len(corpus))
	stressRun(t, "the single-threaded pass", func() {
		creds := stressCreds("stress-golden", stressUID)
		for i := range corpus {
			want[i] = stressCheck(creds, &corpus[i])
		}
	})

	// A second opinion on part of the corpus, in case both profiles agree
	// on a wrong answer: the automaton against the rules walked one at a
	// time.
	mismatch := &stressFailures{}
	stressRun(t, "the rule walk oracle", func() {
		for i := 0; i < oracle && i < len(corpus); i++ {
			c := &corpus[i]
			owned := c.kuid == stressUID
			wantG, wantD := stressRuleWalk(rules, c.path, owned)
			a, ok := golden.dfa.match(c.path)
			if !ok {
				mismatch.errorf("the automaton declined %q, "+
					"but the profile is nowhere near the "+
					"state ceiling", c.path)
				continue
			}
			gotG := a.allowAny
			if owned {
				gotG |= a.allowOwner
			}
			if gotG != wantG || a.deny != wantD {
				mismatch.errorf("path %q owned=%t: automaton "+
					"granted=%b denied=%b, rule walk "+
					"granted=%b denied=%b",
					c.path, owned, gotG, a.deny, wantG, wantD)
			}
		}
	})
	mismatch.report(t)

	// The cold profile must have built nothing yet, or the workers would
	// not be the ones building it.
	if got := hot.dfa.numStates(); got != 2 {
		t.Errorf("the cold profile has %d states before any check, want 2 "+
			"(dead and start)", got)
	}

	workers := stressWorkers()
	passes := stressPasses()
	fails := &stressFailures{}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Each task has its own credentials, as tasks do.
			creds := stressCreds("stress", stressUID)
			for pass := 0; pass < passes; pass++ {
				for i := range corpus {
					// Start each worker at a different
					// point, and send half of them
					// backwards, so that the order states
					// are first needed in differs per
					// worker.
					j := (i + w*97) % len(corpus)
					if w%2 == 1 {
						j = len(corpus) - 1 - j
					}
					got := stressCheck(creds, &corpus[j])
					if got != want[j] {
						fails.errorf("worker %d pass %d: "+
							"Check(%q) = {denied:%t "+
							"errno:%d}, single-threaded "+
							"run gave {denied:%t errno:%d}",
							w, pass, corpus[j].path,
							got.denied, got.errno,
							want[j].denied, want[j].errno)
						return
					}
				}
			}
		}(w)
	}
	stressWait(t, &wg, fmt.Sprintf("%d workers making %d checks each",
		workers, passes*len(corpus)))
	fails.report(t)

	// The workers must actually have built states, or the test proved
	// nothing about building them under contention.
	built := hot.dfa.numStates()
	if built <= 2 {
		t.Errorf("the workers built no automaton states (%d), so nothing "+
			"was constructed under contention", built)
	}
	if got := golden.dfa.numStates(); built != got {
		t.Errorf("the concurrently built automaton has %d states and the "+
			"single-threaded one has %d: the same paths must reach "+
			"the same states whatever the order", built, got)
	}
	if built > maxDFAStates {
		t.Errorf("the automaton has %d states, past the %d ceiling",
			built, maxDFAStates)
	}
	t.Logf("%d workers x %d checks over %d rules built %d states",
		workers, passes*len(corpus), len(rules), built)
}

// stressCeilingPattern is a pattern whose automaton needs one state for every
// subset of a window of the path: after the '**', which keeps every offset
// live, the state has to remember which of the last 18 bytes was an 'a',
// because any of them could be the one the '?' run counts from. Walking
// arbitrary bytes through it therefore builds states until the ceiling is
// reached, which is the only way to exercise the fallback for real rather than
// by asking the automaton to pretend.
func stressCeilingPattern() string {
	return "/ceiling/**a" + strings.Repeat("?", 18) + "z"
}

// stressCeilingRules is the exploding pattern with ordinary rules beside it,
// since what matters after the fallback is that those still answer correctly.
func stressCeilingRules() []Rule {
	return []Rule{
		{Pattern: stressCeilingPattern(), Perms: ParsePerms("r")},
		{Pattern: "/etc/**", Perms: ParsePerms("r")},
		{Pattern: "/etc/shadow", Perms: ParsePerms("rw"), Deny: true, Audit: true},
		{Pattern: "/var/log/*.log", Perms: ParsePerms("rw"), Owner: true},
		{Pattern: "/opt/app/bin/*", Perms: ParsePerms("rix")},
		{Pattern: "/var/cache/**", Perms: ParsePerms("rwk")},
	}
}

// stressCeilingCorpus is a corpus for the profile above, including paths that
// sit either side of the exploding pattern's window: a match needs an 'a'
// exactly 19 bytes before the final 'z'.
func stressCeilingCorpus() []stressAccess {
	const window = 18
	matches := "/ceiling/junk/a" + strings.Repeat("q", window) + "z"
	shortBy := "/ceiling/junk/a" + strings.Repeat("q", window-1) + "z"
	longBy := "/ceiling/junk/a" + strings.Repeat("q", window+1) + "z"
	out := []stressAccess{
		{matches, vfs.MayRead, 0644, 0},
		{shortBy, vfs.MayRead, 0644, 0},
		{longBy, vfs.MayRead, 0644, 0},
		{"/ceiling/", vfs.MayRead, linux.ModeDirectory | 0755, 0},
		{"/etc/passwd", vfs.MayRead, 0644, 0},
		{"/etc/shadow", vfs.MayRead, 0640, 0},
		{"/etc/deep/nested/file.conf", vfs.MayRead, 0644, 0},
		{"/etc/passwd", vfs.MayWrite, 0644, 0},
		{"/var/log/own.log", vfs.MayWrite, 0644, stressUID},
		{"/var/log/other.log", vfs.MayWrite, 0644, stressOtherUID},
		{"/opt/app/bin/tool", vfs.MayRead | vfs.MayExec, 0755, 0},
		{"/opt/app/bin/sub/tool", vfs.MayExec, 0755, 0},
		{"/nowhere/at/all", vfs.MayRead, 0644, 0},
		{"", vfs.MayRead, 0644, 0},
		{"/", vfs.MayRead, linux.ModeDirectory | 0755, 0},
	}
	// Enough distinct cache paths that the concurrent phase below has
	// something to build states for as well.
	for i := 0; i < 200; i++ {
		out = append(out, stressAccess{
			path: fmt.Sprintf("/var/cache/entry%d/blob", i),
			ats:  vfs.MayRead | vfs.MayWrite,
			mode: 0644,
			kuid: stressUID,
		})
	}
	return out
}

// dfaFootprint is the size of the tables the automaton retains, which is what
// "memory does not grow without bound" has to mean for a cache with a ceiling:
// once the ceiling is reached nothing more is retained, whatever else is asked
// of it. The constants are the per-slice and per-map-entry overheads, which
// only have to be consistent between two readings.
func dfaFootprint(d *dfa) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	n := len(d.trans) * 4
	for _, s := range d.sets {
		n += 24 + len(s)*4
	}
	for k := range d.ids {
		n += 16 + len(k)
	}
	return n
}

// stressDriveToCeiling walks pseudo-random bytes through the automaton until
// it declines to answer, which it only does once the state ceiling has been
// reached. It returns whether that happened. The bytes are generated rather
// than listed because what forces the ceiling is the number of distinct
// windows seen, not any particular path.
func stressDriveToCeiling(d *dfa) (rounds, bytes int, reached bool) {
	const (
		chunk     = 16 * 1024
		maxRounds = 64
	)
	x := uint32(0x9e3779b9)
	var b strings.Builder
	for round := 1; round <= maxRounds; round++ {
		b.Reset()
		b.WriteString("/ceiling/")
		for i := 0; i < chunk; i++ {
			// xorshift32, so that the sequence is the same on
			// every machine and a failure is reproducible.
			x ^= x << 13
			x ^= x >> 17
			x ^= x << 5
			if x&1 == 0 {
				b.WriteByte('a')
			} else {
				b.WriteByte('b')
			}
		}
		if _, ok := d.match(b.String()); !ok {
			return round, round * chunk, true
		}
	}
	return maxRounds, maxRounds * chunk, false
}

// TestStressDFAStateCeiling covers what happens at and after maxDFAStates. The
// automaton caches states as paths reach them and stops at the ceiling, after
// which it declines to answer and the profile is matched rule by rule. Two
// things have to hold: the answers must not change when that happens, since
// the ceiling is reached by whichever workload gets there first and not by
// anything the operator chose, and nothing may keep growing afterwards.
func TestStressDFAStateCeiling(t *testing.T) {
	rules := stressCeilingRules()
	corpus := stressCeilingCorpus()

	// The answers to beat, from a profile whose automaton is well short of
	// the ceiling.
	golden := &Profile{Name: "ceiling-golden", Rules: rules}
	full := &Profile{Name: "ceiling", Rules: rules}
	SetPolicy(map[string]*Profile{
		"ceiling":        full,
		"ceiling-golden": golden,
	})
	defer SetPolicy(nil)
	if full.dfa == nil || golden.dfa == nil {
		t.Fatal("the rules did not compile to an automaton")
	}
	want := make([]stressAnswer, len(corpus))
	stressRun(t, "the pass over the compiled profile", func() {
		creds := stressCreds("ceiling-golden", stressUID)
		for i := range corpus {
			want[i] = stressCheck(creds, &corpus[i])
		}
	})

	// The corpus must also agree with the rules walked one at a time,
	// since that walk is what the fallback runs.
	oracle := &stressFailures{}
	stressRun(t, "the rule walk oracle", func() {
		for i := range corpus {
			c := &corpus[i]
			owned := c.kuid == stressUID
			wantG, wantD := stressRuleWalk(rules, c.path, owned)
			a, ok := golden.dfa.match(c.path)
			if !ok {
				oracle.errorf("the automaton declined %q", c.path)
				continue
			}
			gotG := a.allowAny
			if owned {
				gotG |= a.allowOwner
			}
			if gotG != wantG || a.deny != wantD {
				oracle.errorf("path %q owned=%t: automaton "+
					"granted=%b denied=%b, rule walk "+
					"granted=%b denied=%b",
					c.path, owned, gotG, a.deny, wantG, wantD)
			}
		}
	})
	oracle.report(t)

	// A profile that behaves as though the ceiling had been reached with
	// nothing built, which is the worst case for the fallback: every check
	// walks the rules.
	t.Run("simulated", func(t *testing.T) {
		full.dfa.markFullForTest()
		fails := &stressFailures{}
		stressRun(t, "the pass over the fallback", func() {
			creds := stressCreds("ceiling", stressUID)
			for i := range corpus {
				// The empty path is answered by the start state
				// and needs no transition, so it is the one
				// path the automaton can still decide with
				// nothing built.
				if _, ok := full.dfa.match(corpus[i].path); ok && corpus[i].path != "" {
					fails.errorf("the automaton answered "+
						"%q after the ceiling was "+
						"reached", corpus[i].path)
				}
				if got := stressCheck(creds, &corpus[i]); got != want[i] {
					fails.errorf("after the fallback, "+
						"Check(%q) = {denied:%t errno:%d}, "+
						"the compiled profile gave "+
						"{denied:%t errno:%d}",
						corpus[i].path, got.denied, got.errno,
						want[i].denied, want[i].errno)
				}
			}
		})
		fails.report(t)

		// The fallback is also reached from several tasks at once, and
		// reads the same indexes, so it gets the same treatment.
		workers := stressWorkers()
		conc := &stressFailures{}
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				creds := stressCreds("ceiling", stressUID)
				for i := range corpus {
					j := (i + w*7) % len(corpus)
					if got := stressCheck(creds, &corpus[j]); got != want[j] {
						conc.errorf("worker %d: "+
							"Check(%q) through the "+
							"fallback = {denied:%t "+
							"errno:%d}, want "+
							"{denied:%t errno:%d}",
							w, corpus[j].path,
							got.denied, got.errno,
							want[j].denied, want[j].errno)
						return
					}
				}
			}(w)
		}
		stressWait(t, &wg, "the concurrent pass over the fallback")
		conc.report(t)
	})

	if testing.Short() {
		// Reaching the ceiling for real costs a second and a few tens
		// of megabytes, which is more than a default run should spend.
		t.Log("skipping the real state ceiling in short mode")
		return
	}

	t.Run("reached", func(t *testing.T) {
		// Only the new profile is installed: passing the profiles
		// already in force back to SetPolicy() would re-index them
		// while they are published, which is the one thing
		// TestStressSetPolicyDuringCheck documents as unsafe. The
		// answers to compare against were taken above.
		p := &Profile{Name: "ceiling-real", Rules: rules}
		SetPolicy(map[string]*Profile{"ceiling-real": p})
		if p.dfa == nil {
			t.Fatal("the rules did not compile to an automaton")
		}
		var (
			rounds, bytes int
			reached       bool
		)
		start := time.Now()
		stressRun(t, "driving the automaton to its state ceiling", func() {
			rounds, bytes, reached = stressDriveToCeiling(p.dfa)
		})
		states := p.dfa.numStates()
		if !reached {
			t.Fatalf("the automaton still answers after %d bytes and "+
				"%d states, so the ceiling of %d was not reached "+
				"and the fallback below is untested; the pattern "+
				"%q is meant to force it",
				bytes, states, maxDFAStates, stressCeilingPattern())
		}
		t.Logf("the ceiling was reached after %d rounds (%d bytes) in %v, "+
			"with %d states retaining about %d KiB",
			rounds, bytes, time.Since(start), states,
			dfaFootprint(p.dfa)/1024)
		if states > maxDFAStates {
			t.Errorf("the automaton kept %d states, past its ceiling of %d",
				states, maxDFAStates)
		}

		// Answers must be unchanged now that most checks fall back to
		// the rules, and at least one of them must be falling back or
		// this proves nothing.
		declined := 0
		fails := &stressFailures{}
		stressRun(t, "the pass after the ceiling", func() {
			creds := stressCreds("ceiling-real", stressUID)
			for i := range corpus {
				if _, ok := p.dfa.match(corpus[i].path); !ok {
					declined++
				}
				if got := stressCheck(creds, &corpus[i]); got != want[i] {
					fails.errorf("after the ceiling, Check(%q) "+
						"= {denied:%t errno:%d}, the "+
						"compiled profile gave {denied:%t "+
						"errno:%d}", corpus[i].path,
						got.denied, got.errno,
						want[i].denied, want[i].errno)
				}
			}
		})
		fails.report(t)
		if declined == 0 {
			t.Error("no path fell back to the rule walk after the " +
				"ceiling was reached, so the answers above did " +
				"not exercise it")
		}

		// Nothing may keep growing once the ceiling is reached. The
		// automaton's own tables are the exact statement of that; the
		// heap is a loose sanity check on everything else the check
		// path allocates, with a bound wide enough not to be a
		// measurement of the allocator.
		footprint := dfaFootprint(p.dfa)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		const afterCeiling = 100000
		stressRun(t, "the flood of distinct paths after the ceiling", func() {
			creds := stressCreds("ceiling-real", stressUID)
			for i := 0; i < afterCeiling; i++ {
				c := stressAccess{
					path: fmt.Sprintf("/ceiling/x%d/ab", i),
					ats:  vfs.MayRead,
					mode: 0644,
				}
				stressCheck(creds, &c)
			}
		})
		runtime.GC()
		runtime.ReadMemStats(&after)
		if got := p.dfa.numStates(); got != states {
			t.Errorf("the automaton grew from %d to %d states after "+
				"reaching its ceiling", states, got)
		}
		if got := dfaFootprint(p.dfa); got != footprint {
			t.Errorf("the automaton's tables grew from %d to %d bytes "+
				"after reaching its ceiling", footprint, got)
		}
		const heapSlack = 32 << 20
		if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > heapSlack {
			t.Errorf("the live heap grew by %d bytes over %d checks "+
				"past the state ceiling, more than the %d that "+
				"leaves room for allocator noise: something on "+
				"the fallback path is retained",
				grew, afterCeiling, heapSlack)
		}
	})
}

// stressShapeRules are patterns at the sizes that break a matcher: a subtree
// star that must swallow a very long path, a component star against a path
// near the maximum length, runs of consecutive wildcards, and a long run of
// '?'.
var stressShapeRules = []Rule{
	{Pattern: "/deep/**", Perms: ParsePerms("r")},
	{Pattern: "/long/*", Perms: ParsePerms("r")},
	{Pattern: "/a/*/*/*/*/*/*/*/*/x", Perms: ParsePerms("r")},
	{Pattern: "/b/**/**/x", Perms: ParsePerms("r")},
	{Pattern: "/c/**********x", Perms: ParsePerms("r")},
	{Pattern: "/d/????????????????????*", Perms: ParsePerms("r")},
	{Pattern: "/e/**/**/**/**/**/**/**/**/f", Perms: ParsePerms("r")},
}

// TestStressPathShapes matches paths at the sizes a real workload produces
// against patterns with more wildcards than a real profile has. The automaton
// walks a path one byte at a time, so its cost is the length of the path; the
// point here is that nothing else about it depends on the length, the number
// of components, or how many wildcards are adjacent.
func TestStressPathShapes(t *testing.T) {
	p := &Profile{Name: "shapes", Rules: stressShapeRules}
	SetPolicy(map[string]*Profile{"shapes": p})
	defer SetPolicy(nil)
	if p.dfa == nil {
		t.Fatal("the shape rules did not compile to an automaton")
	}

	// PATH_MAX includes the terminating NUL, so 4095 bytes is the longest
	// path Linux accepts and 4096 is the first it does not. The engine has
	// no limit of its own, and must answer for either.
	const pathMax = 4096
	const prefix = len("/long/")
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"a thousand components", "/deep" + strings.Repeat("/abc", 1000), true},
		{"one byte short of PATH_MAX",
			"/long/" + strings.Repeat("x", pathMax-1-prefix), true},
		{"exactly PATH_MAX",
			"/long/" + strings.Repeat("x", pathMax-prefix), true},
		{"one byte past PATH_MAX",
			"/long/" + strings.Repeat("x", pathMax+1-prefix), true},
		{"sixteen times PATH_MAX",
			"/long/" + strings.Repeat("x", 16*pathMax), true},
		{"a component star does not cross a slash", "/long/a/b", false},
		{"eight star components", "/a/1/2/3/4/5/6/7/8/x", true},
		{"one component too few", "/a/1/2/3/4/5/6/7/x", false},
		{"two subtree stars need two components", "/b/p/q/x", true},
		{"and are not satisfied by one", "/b/p/x", false},
		{"but swallow more", "/b/p/q/r/s/x", true},
		{"ten adjacent stars", "/c/anything-here-x", true},
		{"which may match nothing", "/c/x", true},
		{"and cross slashes", "/c/a/b/x", true},
		{"but still need the suffix", "/c/anythingy", false},
		{"twenty question marks", "/d/" + strings.Repeat("y", 20) + "tail", true},
		{"one character short of them", "/d/" + strings.Repeat("y", 19), false},
		{"eight subtree components", "/e/1/2/3/4/5/6/7/8/f", true},
		{"one short of them", "/e/1/2/3/4/5/6/7/f", false},
		{"the empty path", "", false},
		{"the root", "/", false},
		{"an empty component", "//", false},
		{"a NUL byte", "/long/a\x00b", true},
		{"high bytes", "/deep/\xff\xfe\xfd", true},
		{"nothing but separators", strings.Repeat("/", 512), false},
		{"one long component", "/deep/" + strings.Repeat("z", 8192), true},
		{"many short components", strings.Repeat("/ab", 1365) + "/c", false},
	}

	fails := &stressFailures{}
	stressRun(t, "matching the path shapes", func() {
		creds := stressCreds("shapes", stressUID)
		for _, tc := range cases {
			a, ok := p.dfa.match(tc.path)
			if !ok {
				fails.errorf("%s: the automaton declined a path "+
					"of %d bytes", tc.name, len(tc.path))
				continue
			}
			if got := a.allowAny&Read != 0; got != tc.want {
				fails.errorf("%s: the automaton grants read = %t "+
					"for a path of %d bytes, want %t",
					tc.name, got, len(tc.path), tc.want)
			}
			// The rules walked one at a time must say the same. The
			// recursive matcher backtracks over adjacent wildcards,
			// so this is only affordable because the paths that are
			// long here are matched by patterns with one wildcard;
			// a long path against "/c/**********x" would cost
			// O(len**5). That is a property of the fallback, which
			// is reached whenever a profile has no automaton or has
			// passed its state ceiling.
			wantG, _ := stressRuleWalk(stressShapeRules, tc.path, false)
			if got := wantG&Read != 0; got != tc.want {
				fails.errorf("%s: the rule walk grants read = %t "+
					"for a path of %d bytes, want %t",
					tc.name, got, len(tc.path), tc.want)
			}
			// And the engine's own answer must follow from that.
			err := Check(bgCtx, creds, OpFperm, tc.path, vfs.MayRead, 0644, 0)
			if allowed := err == nil; allowed != tc.want {
				fails.errorf("%s: Check on a path of %d bytes = %v, "+
					"want allowed = %t",
					tc.name, len(tc.path), err, tc.want)
			}
		}
	})
	fails.report(t)

	// The same shapes from many tasks at once, since a long path is also
	// the one whose states cost the most to build.
	workers := stressWorkers()
	conc := &stressFailures{}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			creds := stressCreds("shapes", stressUID)
			for i := range cases {
				tc := cases[(i+w)%len(cases)]
				err := Check(bgCtx, creds, OpFperm, tc.path, vfs.MayRead,
					0644, 0)
				if allowed := err == nil; allowed != tc.want {
					conc.errorf("worker %d: Check(%s) = %v, "+
						"want allowed = %t", w, tc.name,
						err, tc.want)
					return
				}
			}
		}(w)
	}
	stressWait(t, &wg, "the concurrent pass over the path shapes")
	conc.report(t)
}

// stressExpandAlternation expands a pattern's brace alternations into the
// patterns a rule may hold, which is what the policy parser does before a rule
// is stored: patternItems() refuses a pattern that still contains a brace, so
// an unexpanded alternation costs the whole profile its automaton.
func stressExpandAlternation(pattern string) []string {
	i := strings.IndexByte(pattern, '{')
	if i < 0 {
		return []string{pattern}
	}
	depth := 0
	for j := i; j < len(pattern); j++ {
		switch pattern[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth != 0 {
				continue
			}
			var out []string
			for _, alt := range splitAlternatives(pattern[i+1 : j]) {
				out = append(out, stressExpandAlternation(
					pattern[:i]+alt+pattern[j+1:])...)
			}
			return out
		}
	}
	// Unbalanced brace, which the matcher treats literally.
	return []string{pattern}
}

// TestStressExpandedAlternations covers the profiles a nested alternation
// produces once it has been expanded into rules, which is the form the engine
// sees. A four-deep alternation is a few dozen rules that share almost every
// byte of their patterns, so they collapse into one another in the automaton,
// and the expanded rules must grant exactly what the alternation names.
func TestStressExpandedAlternations(t *testing.T) {
	for n, pattern := range []string{
		"/srv/{a,{b,c}}/{d,{e,{f,g}}}/{h,i,j}/**",
		"/x/{a,b,c}/{d,e,f}/{g,h,i}/{j,k,l}/**",
		"/y/{lib,lib64,libexec}/{python3.{9,10,11},perl5}/**",
	} {
		t.Run(fmt.Sprintf("pattern%d", n), func(t *testing.T) {
			expanded := stressExpandAlternation(pattern)
			if len(expanded) < 2 {
				t.Fatalf("the pattern expanded to %d rules, so it "+
					"holds no alternation", len(expanded))
			}
			rules := make([]Rule, 0, len(expanded))
			for _, e := range expanded {
				rules = append(rules, Rule{
					Pattern: e,
					Perms:   ParsePerms("r"),
				})
			}
			p := &Profile{Name: "alt", Rules: rules}
			p.index()
			if p.dfa == nil {
				t.Fatalf("%d expanded rules did not compile to an "+
					"automaton", len(rules))
			}

			// The unexpanded pattern must not compile, which is the
			// invariant that makes expanding it the parser's job.
			unexpanded := &Profile{Name: "alt-raw", Rules: []Rule{
				{Pattern: pattern, Perms: ParsePerms("r")},
			}}
			unexpanded.index()
			if unexpanded.dfa != nil {
				t.Errorf("a rule still holding an alternation "+
					"compiled to an automaton; patternItems "+
					"is meant to refuse %q so that the "+
					"profile is matched rule by rule",
					pattern)
			}

			// Every expansion, and the paths just off each one,
			// against the matcher applied to the original pattern.
			var paths []string
			for _, e := range expanded {
				base := strings.TrimSuffix(e, "**")
				paths = append(paths,
					base+"file",
					base+"sub/file",
					base,
					strings.TrimSuffix(base, "/"),
					base+"..",
				)
			}
			paths = append(paths,
				"/srv/z/d/h/file", "/x/a/d/g/z/file",
				"/y/lib/python3.12/x", "/y/lib/python3.9/x",
			)
			fails := &stressFailures{}
			stressRun(t, "matching the expanded alternation", func() {
				for _, path := range paths {
					want := MatchPattern(pattern, path)
					a, ok := p.dfa.match(path)
					if !ok {
						fails.errorf("the automaton "+
							"declined %q", path)
						continue
					}
					if got := a.allowAny&Read != 0; got != want {
						fails.errorf("path %q: the %d "+
							"expanded rules grant "+
							"read = %t, the "+
							"alternation %q matches "+
							"= %t", path,
							len(rules), got, pattern,
							want)
					}
				}
			})
			fails.report(t)
			t.Logf("%d expansions, %d paths, %d states",
				len(expanded), len(paths), p.dfa.numStates())
		})
	}
}

// TestStressSetPolicyDuringCheck replaces the policy while checks are running.
//
// SetPolicy() is documented to run before application tasks do, and nothing in
// the sandbox calls it later, so this is not a supported operation; it is
// covered because the storage was written to survive it ("guarded so that a
// restore or a future reload cannot race with an access") and because a restore
// is exactly a second install. What holds is:
//
//   - policy.profiles is replaced as a whole under policy.mu, so a check sees
//     either the whole new policy or the whole old one, never a mixture.
//   - SetPolicy() indexes each profile before it takes the lock, so the
//     compiled automaton of a profile is published by the same release of
//     policy.mu that publishes the map.
//
// What does not hold, and is not tested because it cannot be made to pass:
// re-installing a *Profile that the current policy already holds. index()
// writes p.dfa, p.byFirst and p.wild with no lock at all, while a task that
// already found that profile is reading them, which is a data race the race
// detector will report and which can hand a check a half-built index. A caller
// that has to reload must build fresh Profile values, as this test does.
func TestStressSetPolicyDuringCheck(t *testing.T) {
	// Both policies define the same profile name, so a check never sees an
	// undefined profile; they differ in which subtree they grant.
	shared := Rule{Pattern: "/shared/**", Perms: ParsePerms("rw")}
	rulesA := []Rule{shared, {Pattern: "/only-a/**", Perms: ParsePerms("r")}}
	rulesB := []Rule{shared, {Pattern: "/only-b/**", Perms: ParsePerms("r")}}
	install := func(rules []Rule) {
		// A fresh Profile each time: see the comment above.
		SetPolicy(map[string]*Profile{
			"churn": {Name: "churn", Rules: rules},
		})
	}
	install(rulesA)
	defer SetPolicy(nil)

	eacces := int32(linuxerr.EACCES.Errno())
	checks := 500
	if !testing.Short() {
		checks = 3000
	}

	var (
		stop     atomic.Bool
		installs atomic.Int64
	)
	fails := &stressFailures{}
	// The workers are waited for on their own, so that the churner can be
	// told to stop once they are done; phase is what the deadline covers,
	// and completes only when the churner has stopped too. Every Add on a
	// group happens before the goroutine that waits on it is started, or
	// the wait could return before a worker was counted.
	var workersWG, churnWG, phase sync.WaitGroup

	// The churner starts first, so that a check is overlapping a reload
	// from the beginning.
	churnWG.Add(1)
	go func() {
		defer churnWG.Done()
		for i := 0; !stop.Load(); i++ {
			if i%2 == 0 {
				install(rulesA)
			} else {
				install(rulesB)
			}
			installs.Add(1)
		}
	}()

	workers := stressWorkers()
	workersWG.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer workersWG.Done()
			creds := stressCreds("churn", stressUID)
			for i := 0; i < checks; i++ {
				// Granted by both policies, so no reload may
				// make it fail.
				err := Check(bgCtx, creds, OpFperm,
					fmt.Sprintf("/shared/w%d/f%d", w, i),
					vfs.MayRead, 0644, 0)
				if err != nil {
					fails.errorf("worker %d: a path both "+
						"policies grant was denied "+
						"during a reload: %v", w, err)
					return
				}
				// Granted by no policy, so no reload may make
				// it pass.
				err = Check(bgCtx, creds, OpFperm,
					fmt.Sprintf("/nowhere/w%d/f%d", w, i),
					vfs.MayRead, 0644, 0)
				if err == nil {
					fails.errorf("worker %d: a path no "+
						"policy grants was allowed "+
						"during a reload", w)
					return
				}
				if got := errnoOf(err); got != eacces {
					fails.errorf("worker %d: a denial during "+
						"a reload returned errno %d, "+
						"want %d", w, got, eacces)
					return
				}
				// Granted by one policy only, so either answer
				// is right and no other is.
				for _, path := range []string{"/only-a/f", "/only-b/f"} {
					err := Check(bgCtx, creds, OpFperm, path,
						vfs.MayRead, 0644, 0)
					if err == nil {
						continue
					}
					if got := errnoOf(err); got != eacces {
						fails.errorf("worker %d: "+
							"Check(%q) during a "+
							"reload returned errno "+
							"%d, want either nil or "+
							"%d", w, path, got, eacces)
						return
					}
				}
			}
		}(w)
	}

	// The churner only stops once every worker is done, so the phase is
	// over when it has.
	phase.Add(1)
	go func() {
		defer phase.Done()
		workersWG.Wait()
		stop.Store(true)
		churnWG.Wait()
	}()

	stressWait(t, &phase, "checks running against a policy being replaced")
	fails.report(t)
	if n := installs.Load(); n < 2 {
		t.Errorf("the policy was installed %d times, so no reload "+
			"overlapped a check", n)
	}
	t.Logf("%d workers made %d checks each while the policy was installed "+
		"%d times", workers, 4*checks, installs.Load())
}

// floodSink counts the audit records a flood of denials produces, per cohort
// of paths, so that the count can be held against the number of denials that
// are meant to be recorded.
type floodSink struct {
	total   atomic.Int64
	none    atomic.Int64
	audited atomic.Int64
	silent  atomic.Int64
	allowed atomic.Int64
	other   atomic.Int64

	mu     sync.Mutex
	sample []string
}

// record is installed as the audit sink. It is called from every task that is
// denied, concurrently, which is the property being stressed.
func (s *floodSink) record(rec string) {
	s.total.Add(1)
	switch {
	case strings.Contains(rec, `name="/flood/none/`):
		s.none.Add(1)
	case strings.Contains(rec, `name="/flood/audited/`):
		s.audited.Add(1)
	case strings.Contains(rec, `name="/flood/silent/`):
		s.silent.Add(1)
	case strings.Contains(rec, `name="/flood/allow/`):
		s.allowed.Add(1)
	default:
		s.other.Add(1)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sample) < 4 {
		s.sample = append(s.sample, rec)
	}
}

// TestStressDenialFlood floods the engine with denials with a sink installed,
// which is the shape of a profile that is not yet right for its workload: a
// task retries, every access is refused, and every refusal is formatted and
// written. Two things are checked: the count of records is exactly the count
// of denials that apparmor.d(5) says are recorded, so nothing is lost when
// many tasks are denied at once, and the denials that are silent by design
// stay silent.
//
// The deny rules below do not overlap. A path matched by both a silent deny
// rule and an audited one is recorded by the automaton, which unions the
// audited permissions of every matching rule, and not by the rule walk, which
// stops at the first matching deny rule and takes only that rule's qualifier.
// That difference is not this test's subject, so the profile avoids it.
func TestStressDenialFlood(t *testing.T) {
	p := &Profile{Name: "flood", Rules: []Rule{
		{Pattern: "/flood/allow/**", Perms: ParsePerms("r")},
		// Denied without a record, which is what a plain deny rule
		// means: "denied without logging".
		{Pattern: "/flood/silent/**", Perms: ParsePerms("r"), Deny: true},
		// Denied with one.
		{Pattern: "/flood/audited/**", Perms: ParsePerms("r"),
			Deny: true, Audit: true},
		// Paths under /flood/none/ match nothing, and a denial no rule
		// asked for is always recorded.
	}}
	SetPolicy(map[string]*Profile{"flood": p})
	defer SetPolicy(nil)
	if p.dfa == nil {
		t.Fatal("the flood rules did not compile to an automaton")
	}

	cohorts := []struct {
		dir      string
		wantDeny bool
	}{
		{"allow", false},
		{"silent", true},
		{"audited", true},
		{"none", true},
	}
	perWorker := 250
	if !testing.Short() {
		perWorker = 1000
	}
	workers := stressWorkers()

	// Both the automaton and the rule walk have to hold up, since the
	// second is what runs once a profile passes its state ceiling.
	for _, phase := range []string{"automaton", "rule walk"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "rule walk" {
				p.dfa.markFullForTest()
			}
			sink := &floodSink{}
			SetTestLogSink(sink.record)
			defer SetTestLogSink(nil)

			fails := &stressFailures{}
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					creds := stressCreds("flood", stressUID)
					for i := 0; i < perWorker; i++ {
						for _, c := range cohorts {
							path := fmt.Sprintf(
								"/flood/%s/w%d/f%d",
								c.dir, w, i)
							err := Check(bgCtx, creds, OpFperm,
								path, vfs.MayRead,
								0644, 0)
							if denied := err != nil; denied != c.wantDeny {
								fails.errorf(
									"Check(%q) = %v, "+
										"want denied = %t",
									path, err, c.wantDeny)
								return
							}
						}
					}
				}(w)
			}
			stressWait(t, &wg, fmt.Sprintf("%d workers making %d "+
				"denials each", workers, perWorker*3))
			fails.report(t)

			denials := int64(workers * perWorker)
			for _, tc := range []struct {
				what string
				got  int64
				want int64
			}{
				{"records for paths no rule matches", sink.none.Load(), denials},
				{"records for an audited deny rule", sink.audited.Load(), denials},
				{"records for a silent deny rule", sink.silent.Load(), 0},
				{"records for a permitted access", sink.allowed.Load(), 0},
				{"records naming something else", sink.other.Load(), 0},
				{"records in total", sink.total.Load(), 2 * denials},
			} {
				if tc.got != tc.want {
					t.Errorf("%s: %d, want %d", tc.what, tc.got, tc.want)
				}
			}
			for _, rec := range sink.sample {
				for _, want := range []string{
					`apparmor="DENIED"`,
					`operation="file_perm"`,
					`profile="flood"`,
					`requested_mask="r"`,
					`denied_mask="r"`,
				} {
					if !strings.Contains(rec, want) {
						t.Errorf("a record produced under "+
							"load lacks %s: %s",
							want, rec)
					}
				}
				if strings.Contains(rec, "error=") {
					t.Errorf("a record carries error=, "+
						"which audit_pre() only prints "+
						"with info=: %s", rec)
				}
			}
		})
	}

	// With no sink installed a record is dropped, which SetAuditSink()
	// documents ("Records are dropped while no sink is installed"). The
	// denial itself must be unaffected, since that is what the operator is
	// relying on when they send records nowhere.
	SetTestLogSink(nil)
	fails := &stressFailures{}
	stressRun(t, "denials with no sink installed", func() {
		creds := stressCreds("flood", stressUID)
		for i := 0; i < 1000; i++ {
			path := fmt.Sprintf("/flood/none/nosink/%d", i)
			if err := Check(bgCtx, creds, OpFperm, path, vfs.MayRead,
				0644, 0); err == nil {
				fails.errorf("Check(%q) with no sink installed "+
					"was allowed", path)
				return
			}
		}
	})
	fails.report(t)
}

// stressStackRules is the rules of one profile of the stacked label below.
func stressStackRules(name string) []Rule {
	switch name {
	case "stack-a":
		return []Rule{
			// Broad, so that this profile is rarely the one that
			// refuses.
			{Pattern: "/stack/**", Perms: ParsePerms("rwk")},
			{Pattern: "/stack/a-only/**", Perms: ParsePerms("rw")},
		}
	case "stack-b":
		return []Rule{
			{Pattern: "/stack/pub/**", Perms: ParsePerms("rwk")},
			{Pattern: "/stack/priv/**", Perms: ParsePerms("rw"), Owner: true},
			// Audited, so that a denial by this rule still produces
			// exactly one record.
			{Pattern: "/stack/pub/forbidden/**", Perms: ParsePerms("w"),
				Deny: true, Audit: true},
			{Pattern: "/stack/a-only/**", Perms: ParsePerms("r")},
		}
	default:
		return []Rule{
			{Pattern: "/stack/pub/*/*/leaf*", Perms: ParsePerms("rw")},
			{Pattern: "/stack/pub/[0-9]*/**", Perms: ParsePerms("r")},
			{Pattern: "/stack/priv/**", Perms: ParsePerms("rwk")},
			{Pattern: "/stack/a-only/**", Perms: ParsePerms("rw")},
		}
	}
}

// TestStressStackedLabels drives a label of three stacked profiles from many
// goroutines. Every profile of a label is evaluated on every access, so one
// check builds states in three automata and takes policy.mu three times, and
// the label grants only what all three grant. The answers must be the
// intersection of what the profiles decide on their own, however many tasks
// are asking, and a refusal must still produce exactly one record.
func TestStressStackedLabels(t *testing.T) {
	names := []string{"stack-a", "stack-b", "stack-c"}
	profiles := map[string]*Profile{}
	for _, name := range names {
		profiles[name] = &Profile{Name: name, Rules: stressStackRules(name)}
	}
	SetPolicy(profiles)
	defer SetPolicy(nil)
	label := ""
	for _, name := range names {
		label = StackLabel(label, name)
		if profiles[name].dfa == nil {
			t.Fatalf("the rules of %q did not compile to an automaton",
				name)
		}
	}
	if got := len(SplitLabel(label)); got != len(names) {
		t.Fatalf("the label %q holds %d profiles, want %d", label, got,
			len(names))
	}

	size := 600
	if !testing.Short() {
		size = 2000
	}
	corpus := make([]stressAccess, 0, size)
	shapes := []struct {
		format string
		ats    vfs.AccessTypes
		kuid   auth.KUID
	}{
		// Granted by all three.
		{"/stack/pub/%d/x/leaf%d", vfs.MayRead, 0},
		{"/stack/pub/%d/x/leaf%d", vfs.MayWrite, 0},
		// stack-c only grants read below a numeric component.
		{"/stack/pub/%d/deep/nested/file%d", vfs.MayRead, 0},
		{"/stack/pub/%d/deep/nested/file%d", vfs.MayWrite, 0},
		// Refused by stack-b's audited deny rule for write.
		{"/stack/pub/forbidden/%d/f%d", vfs.MayWrite, 0},
		{"/stack/pub/forbidden/%d/f%d", vfs.MayRead, 0},
		// stack-b grants the owner only.
		{"/stack/priv/%d/f%d", vfs.MayWrite, stressUID},
		{"/stack/priv/%d/f%d", vfs.MayWrite, stressOtherUID},
		// Granted by stack-a and stack-c but read-only by stack-b.
		{"/stack/a-only/%d/f%d", vfs.MayRead, 0},
		{"/stack/a-only/%d/f%d", vfs.MayWrite, 0},
		// Named by no profile.
		{"/elsewhere/%d/f%d", vfs.MayRead, 0},
	}
	for i := 0; len(corpus) < size; i++ {
		s := shapes[i%len(shapes)]
		corpus = append(corpus, stressAccess{
			path: fmt.Sprintf(s.format, i%97, i),
			ats:  s.ats,
			mode: 0644,
			kuid: s.kuid,
		})
	}

	// What each profile decides on its own, single-threaded, and what the
	// stack therefore has to decide: the first profile of the label that
	// refuses.
	want := make([]stressAnswer, len(corpus))
	perProfile := make([][]stressAnswer, len(names))
	stressRun(t, "the single-threaded pass over each profile", func() {
		for n, name := range names {
			perProfile[n] = make([]stressAnswer, len(corpus))
			creds := stressCreds(name, stressUID)
			for i := range corpus {
				perProfile[n][i] = stressCheck(creds, &corpus[i])
			}
		}
		for i := range corpus {
			want[i] = stressAnswer{}
			for n := range names {
				if perProfile[n][i].denied {
					want[i] = perProfile[n][i]
					break
				}
			}
		}
	})
	denied := 0
	for i := range want {
		if want[i].denied {
			denied++
		}
	}
	if denied == 0 || denied == len(want) {
		t.Fatalf("%d of %d accesses are refused by the stack, so the "+
			"corpus does not exercise both answers", denied, len(want))
	}

	// Fresh profiles, so that the workers are the ones building the states
	// of all three automata.
	cold := map[string]*Profile{}
	for _, name := range names {
		cold[name] = &Profile{Name: name, Rules: stressStackRules(name)}
	}
	SetPolicy(cold)
	for _, name := range names {
		if got := cold[name].dfa.numStates(); got != 2 {
			t.Errorf("the cold profile %q has %d states before any "+
				"check, want 2", name, got)
		}
	}

	var records atomic.Int64
	SetTestLogSink(func(string) { records.Add(1) })
	defer SetTestLogSink(nil)

	workers := stressWorkers()
	passes := stressPasses()
	fails := &stressFailures{}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			creds := stressCreds(label, stressUID)
			for pass := 0; pass < passes; pass++ {
				for i := range corpus {
					j := (i + w*31) % len(corpus)
					got := stressCheck(creds, &corpus[j])
					if got != want[j] {
						fails.errorf("worker %d: the "+
							"stacked label answered "+
							"{denied:%t errno:%d} for "+
							"%q with %v, the profiles "+
							"on their own give "+
							"{denied:%t errno:%d}",
							w, got.denied, got.errno,
							corpus[j].path,
							corpus[j].ats,
							want[j].denied,
							want[j].errno)
						return
					}
				}
			}
		}(w)
	}
	stressWait(t, &wg, fmt.Sprintf("%d workers checking a label of %d "+
		"stacked profiles", workers, len(names)))
	fails.report(t)

	// Every refusal is recorded once: checkRecord() stops at the first
	// profile of the label that refuses, and none of these profiles
	// silences a denial.
	wantRecords := int64(workers * passes * denied)
	if got := records.Load(); got != wantRecords {
		t.Errorf("a stacked label produced %d records for %d refusals; "+
			"each refusal is recorded once, by the profile that "+
			"refused", got, wantRecords)
	}
	for _, name := range names {
		built := cold[name].dfa.numStates()
		if built <= 2 {
			t.Errorf("the workers built no states in %q, so its "+
				"automaton was not exercised", name)
		}
		if built > maxDFAStates {
			t.Errorf("the automaton of %q has %d states, past the %d "+
				"ceiling", name, built, maxDFAStates)
		}
	}
}

// errnoOf returns the errno of a denial, for comparing against a profile's
// error= flag; zero for nil. The record format no longer reports an errno, so
// this lives with the tests that still compare them.
func errnoOf(err error) int32 {
	if err == nil {
		return 0
	}
	var kill *KillError
	if errors.As(err, &kill) {
		err = kill.Err
	}
	var e *gverrors.Error
	if errors.As(err, &e) {
		return int32(e.Errno())
	}
	return 0
}
