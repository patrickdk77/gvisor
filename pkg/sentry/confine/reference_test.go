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
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"
)

// AppArmor's own parser is the only authority on what a pattern matches. Reading
// the prose in apparmor.d(5) is not enough: apparmor_parser compiles a wildcard
// that is a whole path component differently from one that is part of a
// component, so "/dir/*" cannot match "/dir/" while "/dir/*.php" can match
// "/dir/.php". Getting that wrong makes a rule cover paths the real
// implementation would not, and an owner or deny rule that covers too much
// denies accesses a working profile permits.
//
// testdata/aare_reference.tsv holds, for each pattern, the regexp
// apparmor_parser compiles it to. It was produced by:
//
//	apparmor_parser -QT --dump=rule-exprs <profile>
//
// over the patterns of a real multi-tenant web hosting profile set, so the
// corpus is what production policy actually contains rather than what is easy
// to implement. Regenerate it the same way when adding patterns.
const referenceFile = "testdata/aare_reference.tsv"

// referencePattern is one pattern and the regexp AppArmor compiles it to.
type referencePattern struct {
	pattern string
	regexp  *regexp.Regexp
	source  string
}

func loadReference(t *testing.T) []referencePattern {
	t.Helper()
	f, err := os.Open(referenceFile)
	if err != nil {
		t.Fatalf("opening the reference data: %v", err)
	}
	defer f.Close()

	var out []referencePattern
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		pattern, rx, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("malformed reference line: %q", line)
		}
		// The parser's regexp matches a whole path, and \x00 is its end
		// of string marker, which cannot appear in a path.
		re, err := regexp.Compile("^(?:" + rx + ")$")
		if err != nil {
			t.Fatalf("compiling the reference regexp for %q (%q): %v", pattern, rx, err)
		}
		out = append(out, referencePattern{pattern: pattern, regexp: re, source: rx})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading the reference data: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("the reference data is empty")
	}
	return out
}

// pathCorpus derives paths to test a pattern with, from the pattern itself, so
// that every pattern is exercised with paths that nearly match it as well as
// ones that do. A fixed list would only test the patterns someone thought of.
func pathCorpus(pattern string) []string {
	var expansions []string
	// Substitute each wildcard with several candidates, including the empty
	// string, which is the case a whole-component wildcard must reject.
	for _, sub := range []struct{ star, dstar, question string }{
		{"abc", "abc", "x"},
		{"", "", ""},
		{"a", "a/b", "y"},
		{"a.b", "a/b/c", "."},
		{"..", "..", "."},
	} {
		p := pattern
		p = strings.ReplaceAll(p, "**", "\x01")
		p = strings.ReplaceAll(p, "*", "\x02")
		p = strings.ReplaceAll(p, "?", "\x03")
		p = strings.ReplaceAll(p, "\x01", sub.dstar)
		p = strings.ReplaceAll(p, "\x02", sub.star)
		p = strings.ReplaceAll(p, "\x03", sub.question)
		expansions = append(expansions, p)
	}
	// Character classes and alternations are expanded before a rule is
	// stored, so a pattern containing one is skipped by the caller; the
	// substitutions above leave them alone.
	var out []string
	for _, p := range expansions {
		out = append(out, p)
		// Trailing slash present and absent, since that is how AppArmor
		// distinguishes a directory.
		if strings.HasSuffix(p, "/") {
			out = append(out, strings.TrimSuffix(p, "/"))
		} else {
			out = append(out, p+"/")
		}
		// One component deeper and one shallower.
		out = append(out, p+"/deeper")
		if i := strings.LastIndexByte(strings.TrimSuffix(p, "/"), '/'); i > 0 {
			out = append(out, p[:i])
		}
	}
	return out
}

// TestMatchPatternMatchesReference compares this implementation's matcher
// against apparmor_parser's compiled regexp for every pattern in the reference
// corpus. A disagreement is a rule that covers a different set of paths here
// than it does under a host kernel.
func TestMatchPatternMatchesReference(t *testing.T) {
	for _, ref := range loadReference(t) {
		if strings.ContainsAny(ref.pattern, "{}[]") {
			// Alternations and character classes are expanded by the
			// policy parser before a rule reaches the matcher.
			continue
		}
		for _, path := range pathCorpus(ref.pattern) {
			want := ref.regexp.MatchString(path)
			got := MatchPattern(ref.pattern, path)
			if got != want {
				t.Errorf("MatchPattern(%q, %q) = %t, want %t: apparmor_parser compiles it to %q",
					ref.pattern, path, got, want, ref.source)
			}
		}
	}
}

// TestDFAMatchesReference is TestMatchPatternMatchesReference for the compiled
// automaton, which translates a pattern separately and so can disagree on its
// own.
func TestDFAMatchesReference(t *testing.T) {
	for _, ref := range loadReference(t) {
		if strings.ContainsAny(ref.pattern, "{}[]") {
			continue
		}
		p := &Profile{Name: "p", Rules: []Rule{{Pattern: ref.pattern, Perms: Read}}}
		p.index()
		if p.dfa == nil {
			t.Errorf("pattern %q did not compile to an automaton", ref.pattern)
			continue
		}
		for _, path := range pathCorpus(ref.pattern) {
			want := ref.regexp.MatchString(path)
			a, ok := p.dfa.match(path)
			if !ok {
				t.Fatalf("the automaton declined to answer for %q", path)
			}
			if got := a.allowAny&Read != 0; got != want {
				t.Errorf("dfa.match(%q) with rule %q = %t, want %t: apparmor_parser compiles it to %q",
					path, ref.pattern, got, want, ref.source)
			}
		}
	}
}
