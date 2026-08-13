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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package boot

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/confine"
)

// A rule whose path holds an AppArmor variable is never seen by the
// matcher as it was written: this parser expands the variable first, and
// a multi-valued variable turns one rule into one rule per value. The
// reference test in pkg/sentry/confine therefore skips every pattern
// with a variable or an alternation in it, which leaves the expansion
// itself compared against nothing. Expansion is where a rule set
// quietly comes to cover more or less than the profile says: a value
// dropped from a multi-valued variable leaves a webroot unconfined, and
// an alternative dropped from a deny rule permits an access the host
// kernel refuses.
//
// This test covers what that one skips. testdata/apparmor_reference.tsv
// holds, for each such pattern of a real profile set, the single regexp
// apparmor_parser compiles the whole pattern to; the rules this parser
// produces for the pattern must match exactly the paths that regexp
// does. The file names the command it came from; regenerate it the same
// way when adding patterns.
const apparmorReferenceFile = "testdata/apparmor_reference.tsv"

// apparmorReferenceVars defines the variables the reference data was
// generated with: @{PROC} as tunables/proc defines it, and @{WWW_DIRS}
// as the profiles themselves do. It is policy text rather than a
// prepared tunables map so that the definitions reach the rules the way
// a real tunables file's do.
const apparmorReferenceVars = "@{PROC}=/proc/\n" +
	"@{WWW_DIRS} = /var/www/vhosts /mnt/nfs01/siteroots\n"

// apparmorReference is one pattern, that pattern with its variables
// replaced, and the regexp apparmor_parser compiles it to.
type apparmorReference struct {
	// pattern is the pattern as the profile writes it, variables and
	// alternations intact.
	pattern string

	// expanded is pattern with its variables replaced by an alternation
	// over their values, as apparmor_parser reports it.
	expanded string

	// regexp is what apparmor_parser compiles pattern to, anchored.
	regexp *regexp.Regexp

	// source is the regexp as the reference file spells it, for
	// failures to quote.
	source string
}

func loadAppArmorReference(t *testing.T) []apparmorReference {
	t.Helper()
	f, err := os.Open(apparmorReferenceFile)
	if err != nil {
		t.Fatalf("opening the reference data: %v", err)
	}
	defer f.Close()

	var out []apparmorReference
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("malformed reference line: %q", line)
		}
		// The parser's regexp matches a whole path, and \x00 is its
		// end of string marker, which cannot appear in a path.
		re, err := regexp.Compile("^(?:" + fields[2] + ")$")
		if err != nil {
			t.Fatalf("compiling the reference regexp for %q (%q): %v",
				fields[0], fields[2], err)
		}
		out = append(out, apparmorReference{
			pattern:  fields[0],
			expanded: fields[1],
			regexp:   re,
			source:   fields[2],
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading the reference data: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("the reference data is empty")
	}
	return out
}

// apparmorRulePatterns is the pattern of every rule the parser produces
// for a profile whose only rule is written with pattern.
func apparmorRulePatterns(t *testing.T, pattern string) []string {
	t.Helper()
	policy := &AppArmorPolicy{}
	tun := make(tunables)
	vars := strings.NewReader(apparmorReferenceVars)
	if err := ParseAppArmorProfiles(vars, "tunables", policy, tun); err != nil {
		t.Fatalf("parsing the variable definitions: %v", err)
	}
	text := strings.NewReader("profile ref {\n  " + pattern + " r,\n}\n")
	if err := ParseAppArmorProfiles(text, "ref", policy, tun); err != nil {
		t.Fatalf("parsing a profile holding %q: %v", pattern, err)
	}
	cp := policy.Rules["ref"]
	if cp == nil {
		return nil
	}
	var out []string
	for _, r := range cp.Rules {
		out = append(out, r.Pattern)
	}
	return out
}

// referenceAlternatives expands a pattern's brace alternations, one
// pattern per alternative. It is deliberately a second implementation
// rather than a call to expandAlternations: the paths a pattern is
// tested with must not come from the code under test, or an alternative
// that code drops would be missing from the paths too, and dropping it
// would go unnoticed.
func referenceAlternatives(pattern string) []string {
	open := strings.IndexByte(pattern, '{')
	if open < 0 {
		return []string{pattern}
	}
	depth := 0
	for i := open; i < len(pattern); i++ {
		switch pattern[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth != 0 {
				continue
			}
			var out []string
			for _, alt := range referenceCommas(pattern[open+1 : i]) {
				rest := pattern[:open] + alt + pattern[i+1:]
				out = append(out, referenceAlternatives(rest)...)
			}
			return out
		}
	}
	// Unbalanced brace: apparmor_parser matches it literally.
	return []string{pattern}
}

// referenceCommas splits the body of a brace expression on the commas
// that are not inside a nested brace expression.
func referenceCommas(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// apparmorPathCorpus derives paths to test a pattern with from the
// pattern itself, so that every pattern is exercised with paths that
// nearly match it as well as with ones that do. A fixed list would only
// test the patterns someone thought of. pattern must hold no
// alternation; the caller expands those first.
func apparmorPathCorpus(pattern string) []string {
	// The policy parser marks a brace-origin wildcard with a NUL byte so the
	// matcher can tell it from a top-level whole-component one. It is an
	// internal marker, not part of any path, so drop it before deriving
	// candidate paths.
	pattern = strings.ReplaceAll(pattern, "\x00", "")
	// Character classes are replaced first, both so that a class body
	// cannot be mistaken for a wildcard and because the rules of the
	// docker default policy are almost entirely classes: left in
	// place, they would only ever be tested with paths holding a
	// literal "[^1-9]".
	var b strings.Builder
	for i := 0; i < len(pattern); {
		if pattern[i] == '[' {
			if end := strings.IndexByte(pattern[i:], ']'); end > 0 {
				b.WriteString("\x04")
				i += end + 1
				continue
			}
		}
		b.WriteByte(pattern[i])
		i++
	}
	classless := b.String()

	var expansions []string
	// Substitute each wildcard with several candidates, including the
	// empty string, which is the case a whole-component wildcard must
	// reject. A class always stands for exactly one character, so its
	// candidates are single characters, some of them ones the classes
	// in the corpus exclude.
	for _, sub := range []struct{ star, dstar, question, class string }{
		{"abc", "abc", "x", "a"},
		{"", "", "", "1"},
		{"a", "a/b", "y", "s"},
		{"a.b", "a/b/c", ".", "0"},
		{"..", "..", ".", "9"},
	} {
		p := classless
		p = strings.ReplaceAll(p, "**", "\x01")
		p = strings.ReplaceAll(p, "*", "\x02")
		p = strings.ReplaceAll(p, "?", "\x03")
		p = strings.ReplaceAll(p, "\x01", sub.dstar)
		p = strings.ReplaceAll(p, "\x02", sub.star)
		p = strings.ReplaceAll(p, "\x03", sub.question)
		p = strings.ReplaceAll(p, "\x04", sub.class)
		expansions = append(expansions, p)
	}

	var out []string
	for _, p := range expansions {
		out = append(out, p)
		// Trailing slash present and absent, since that is how
		// AppArmor distinguishes a directory.
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

// TestAppArmorExpansionMatchesReference compares the rules this parser
// produces for a pattern against the regexp apparmor_parser compiles
// the same pattern to: a path is covered here if any one of the rules
// matches it, and there if the regexp does. A disagreement is a profile
// that confines a different set of paths in the sandbox than it does on
// a host kernel.
func TestAppArmorExpansionMatchesReference(t *testing.T) {
	for _, ref := range loadAppArmorReference(t) {
		rules := apparmorRulePatterns(t, ref.pattern)
		if len(rules) == 0 {
			t.Errorf("pattern %q produced no rule at all", ref.pattern)
			continue
		}
		// Paths are derived both from the rules produced here, which
		// catch a rule set covering paths the profile does not, and
		// from the alternatives apparmor_parser reported, which catch
		// one that misses paths the profile covers: an expansion that
		// was never produced.
		sources := make([]string, 0, len(rules)+4)
		sources = append(sources, rules...)
		sources = append(sources, referenceAlternatives(ref.expanded)...)
		var (
			paths []string
			seen  = make(map[string]bool)
		)
		for _, src := range sources {
			for _, path := range apparmorPathCorpus(src) {
				if seen[path] {
					continue
				}
				seen[path] = true
				paths = append(paths, path)
			}
		}

		var bad []string
		for _, path := range paths {
			want := ref.regexp.MatchString(path)
			got := false
			for _, p := range rules {
				if confine.MatchPattern(p, path) {
					got = true
					break
				}
			}
			if got != want {
				bad = append(bad, fmt.Sprintf(
					"%q: the rules say %t, apparmor_parser says %t",
					path, got, want))
			}
		}
		if len(bad) == 0 {
			continue
		}
		// A pattern that disagrees on one path usually disagrees on
		// several for the same reason, so only the first few are
		// named.
		shown := bad
		if len(shown) > 3 {
			shown = shown[:3]
		}
		t.Errorf("pattern %q expands to %q, which covers different"+
			" paths than the regexp apparmor_parser compiles it to,"+
			" %s; %d of %d paths disagree:\n\t%s",
			ref.pattern, rules, ref.source, len(bad), len(paths),
			strings.Join(shown, "\n\t"))
	}
}

// TestAppArmorExpansionRuleSet checks that a pattern expands to one rule
// per alternative apparmor_parser found in it, and to no others. The
// paths of the test above cannot see the difference between a rule that
// is missing and one that is present but never reached, and a
// multi-valued variable must yield a rule per value: a profile written
// with two siteroots that produces one rule leaves the other webroot
// with no rules at all.
func TestAppArmorExpansionRuleSet(t *testing.T) {
	for _, ref := range loadAppArmorReference(t) {
		got := apparmorRulePatterns(t, ref.pattern)
		// The brace-wildcard marker is an internal detail; the parser's
		// reported alternatives do not carry it, so compare without it.
		for i := range got {
			got[i] = strings.ReplaceAll(got[i], "\x00", "")
		}
		// apparmor_parser reports the pattern with its variables
		// already replaced and any doubled slash they introduced
		// already collapsed, so its alternatives are directly the
		// patterns the rules are expected to carry.
		want := referenceAlternatives(ref.expanded)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("pattern %q expands to rules %q, apparmor_parser expands it to %q",
				ref.pattern, got, want)
		}
	}
}
