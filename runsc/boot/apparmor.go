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

// This file derives in-sandbox confinement policy from AppArmor profile
// text, so that the profiles remain the single source of truth rather than
// having their contents restated as runsc flags.
//
// It is deliberately not a general AppArmor implementation. It extracts the
// two things the Sentry can enforce today:
//
//   - The mount points below which a confined task may only access files it
//     owns, derived from the literal prefixes of 'owner' file rules. AppArmor
//     'owner' rules cannot be enforced by the host kernel for a sandboxed
//     application, because the application's accesses are serviced by the
//     Sentry and never reach the host.
//
//   - The executables whose exec attaches a profile, derived from profile
//     names that are paths, as AppArmor does.
//
// Everything else in a profile is ignored here and must be enforced by the
// host profile applied to the Sentry and Gofer (--host-apparmor); see
// runsc/specutils/apparmor.go. Constructs that are ignored are logged, so
// that a profile is never silently reduced to something weaker than it
// looks.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"strconv"
)

// AppArmorPolicy is the confinement policy derived from a set of AppArmor
// profiles.
type AppArmorPolicy struct {
	// Profiles maps a profile name to its file rules, which the Sentry
	// evaluates for tasks that have entered that profile.
	Rules map[string]*confine.Profile

	// ExecAttach maps an executable path to the profile that a task enters
	// when it execs that path.
	ExecAttach map[string]string

	// Profiles are the names of every profile that was parsed.
	Profiles []string

	// Unenforced holds every line of policy that produced no in-sandbox
	// rule, with the file and profile it came from. A profile is only as
	// strong as what was understood of it, so nothing is dropped silently.
	Unenforced []UnenforcedLine
}

// merge adds to policy every profile of other that policy does not already
// define. A profile already defined is kept: replacing it would put tasks
// already running under it into a profile they were not confined by, and a
// container must not be able to weaken a profile another container is using.
func (p *AppArmorPolicy) merge(other *AppArmorPolicy) {
	for _, name := range other.Profiles {
		if !slices.Contains(p.Profiles, name) {
			p.Profiles = append(p.Profiles, name)
		}
	}
	for name, cp := range other.Rules {
		if p.Rules == nil {
			p.Rules = make(map[string]*confine.Profile)
		}
		if _, ok := p.Rules[name]; ok {
			log.Warningf("AppArmor profile %q is already defined; the definition just loaded is ignored", name)
			continue
		}
		p.Rules[name] = cp
	}
	for path, name := range other.ExecAttach {
		if p.ExecAttach == nil {
			p.ExecAttach = make(map[string]string)
		}
		if _, ok := p.ExecAttach[path]; ok {
			continue
		}
		p.ExecAttach[path] = name
	}
	p.Unenforced = append(p.Unenforced, other.Unenforced...)
}

// UnenforcedLine is a line of policy that in-sandbox enforcement does not
// implement.
type UnenforcedLine struct {
	// File is the profile or abstraction file the line came from.
	File string

	// Profile is the profile the line belongs to, empty at file scope.
	Profile string

	// Line is the policy text, trimmed.
	Line string
}

// varDefRE matches an AppArmor variable definition, e.g. "@{FOO} = /a /b" or
// "@{FOO}+=/c", as distinct from a rule whose path begins with a variable.
var varDefRE = regexp.MustCompile(`^@\{[A-Za-z_][A-Za-z0-9_]*\}\s*\+?=`)

// tunables holds AppArmor variable definitions (@{NAME}=value ...). A
// variable may have several values, in which case a rule mentioning it
// expands to one rule per value.
type tunables map[string][]string

// expand returns every expansion of s given the defined variables. Variables
// may refer to other variables, as AppArmor's tunables do.
// dedup returns values with duplicates removed, preserving order. A variable
// defined more than once with the same value would otherwise multiply every
// rule that mentions it by the number of definitions.
func dedup(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// normalizeSlashes collapses runs of '/' into one, as apparmor_parser does.
// Tunables conventionally end with a slash (@{run}=/run/, @{PROC}=/proc/), so a
// rule written "@{run}/nscd/socket" expands to "/run//nscd/socket" and would
// otherwise match nothing.
func normalizeSlashes(pattern string) string {
	if !strings.Contains(pattern, "//") {
		return pattern
	}
	// Slashes at the beginning of a path denote a POSIX namespace and are
	// left alone; only the rest are collapsed.
	lead := 0
	for lead < len(pattern) && pattern[lead] == '/' {
		lead++
	}
	if lead > 2 {
		lead = 1
	}
	var b strings.Builder
	b.Grow(len(pattern))
	b.WriteString(pattern[:lead])
	prevSlash := false
	for i := lead; i < len(pattern); i++ {
		c := pattern[i]
		if c == '/' && prevSlash {
			continue
		}
		prevSlash = c == '/'
		b.WriteByte(c)
	}
	return b.String()
}

// expandAlternations rewrites an AppArmor pattern's brace alternations into one
// pattern per alternative, so that matching never has to do it. Expanding at
// match time rebuilt the pattern for every alternative on every access, which
// dominated the cost of a permission check.
// braceWildcardMarker precedes a '*' or '**' that came from inside a brace
// alternation. apparmor_parser compiles such a wildcard to a bare star with no
// leading-component minimum, unlike a whole-component wildcard in the top-level
// skeleton: "/a/{,**}" is "/a/(|[^\x00]*)", where the "**" is bare, while
// "/a/**" is "/a/[^/\x00][^\x00]*". The marker records that origin so the
// matcher does not apply the minimum. It is NUL, which cannot appear in a path.
const braceWildcardMarker = "\x00"

// markBraceWildcards prefixes every '*'/'**' that lies inside a brace group with
// braceWildcardMarker, so that after the braces are expanded the matcher can
// still tell a brace-origin wildcard (bare) from a top-level whole-component one
// (which takes the minimum). Wildcards at brace depth zero are left untouched.
func markBraceWildcards(pattern string) string {
	if !strings.Contains(pattern, "{") {
		return pattern
	}
	var b strings.Builder
	b.Grow(len(pattern) + 4)
	depth := 0
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case '*':
			// Mark only the first star of a run, so "**" becomes one
			// marked token rather than two.
			if depth > 0 && (i == 0 || pattern[i-1] != '*') {
				b.WriteString(braceWildcardMarker)
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func expandAlternations(pattern string) []string {
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
				// An alternative may itself contain braces.
				out = append(out, expandAlternations(pattern[:i]+alt+pattern[j+1:])...)
				if len(out) >= maxExpansion {
					// The pattern may carry brace-wildcard markers
					// by this point; they are internal, so they
					// are not shown.
					log.Warningf("AppArmor: pattern %q expands to more than %d alternatives; keeping the first %d, the rest are not enforced", strings.ReplaceAll(pattern, braceWildcardMarker, ""), maxExpansion, maxExpansion)
					return out[:maxExpansion]
				}
			}
			return out
		}
	}
	// Unbalanced brace: matched literally, as AppArmor does.
	return []string{pattern}
}

// splitAlternatives splits the body of a brace expression on commas that are
// not inside a nested brace expression.
func splitAlternatives(s string) []string {
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

// maxExpansion bounds the rules one rule may expand into. A rule naming
// several multi-valued variables expands to their product, which is not
// bounded by the size of the policy.
const maxExpansion = 512

func (t tunables) expand(s string) []string {
	out := []string{s}
	// Expand repeatedly so that variables defined in terms of other
	// variables resolve. The bound prevents a cycle from looping forever.
	for range 8 {
		var next []string
		changed := false
		for _, cur := range out {
			start := strings.Index(cur, "@{")
			if start < 0 {
				next = append(next, cur)
				continue
			}
			end := strings.Index(cur[start:], "}")
			if end < 0 {
				next = append(next, cur)
				continue
			}
			end += start
			name := cur[start+2 : end]
			values, ok := t[name]
			if !ok {
				// Unknown variable: leave it alone, but do not
				// treat the rule as a usable path.
				next = append(next, cur)
				continue
			}
			changed = true
			for _, v := range values {
				next = append(next, cur[:start]+v+cur[end+1:])
			}
		}
		out = next
		if len(out) > maxExpansion {
			log.Warningf("AppArmor: %q expands to more than %d values; keeping the first %d, the rest are not enforced", s, maxExpansion, maxExpansion)
			out = out[:maxExpansion]
			break
		}
		if !changed {
			break
		}
	}
	return out
}

// literalPrefix returns the leading portion of an AppArmor path pattern that
// contains no glob metacharacters, trimmed to a directory boundary, plus
// whether a usable prefix was found. For example
// "/var/www/vhosts/?/?/*/**" yields "/var/www/vhosts".
func literalPrefix(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, "/") {
		return "", false
	}
	i := strings.IndexAny(pattern, "*?[{")
	if i < 0 {
		// No globbing: the rule names a single path. Use its directory,
		// since enforcement is applied to a subtree.
		return filepath.Clean(pattern), true
	}
	prefix := pattern[:i]
	if j := strings.LastIndex(prefix, "/"); j > 0 {
		prefix = prefix[:j]
	} else {
		// The glob begins at the root, e.g. "/*": too broad to be a
		// useful subtree.
		return "", false
	}
	return filepath.Clean(prefix), true
}

// parseFileRule parses one AppArmor file rule, expanding variables. A rule
// with a multi-valued variable yields one confine.Rule per expansion. It
// returns false for lines that are not file rules.
// ruleFields splits a rule into fields, keeping a double-quoted path with
// embedded spaces or tabs as one field. It reports false if a quote is
// unterminated.
func ruleFields(body string) ([]string, bool) {
	var (
		out   []string
		cur   strings.Builder
		quote bool
	)
	flush := func() {
		if cur.Len() != 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '"':
			quote = !quote
		case (c == ' ' || c == '\t') && !quote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	if quote {
		return nil, false
	}
	flush()
	return out, true
}

// execModeOf returns the transition a permission field's modifier letters ask
// for. AppArmor's uppercase forms additionally scrub the environment, which is
// not distinguished here.
func execModeOf(perms string) (confine.ExecMode, bool) {
	for _, c := range perms {
		switch c {
		case 'i':
			return confine.ExecInherit, false
		case 'p':
			return confine.ExecProfile, false
		case 'P':
			return confine.ExecProfile, true
		case 'c':
			return confine.ExecChild, false
		case 'C':
			return confine.ExecChild, true
		case 'u':
			return confine.ExecUnconfined, false
		case 'U':
			return confine.ExecUnconfined, true
		}
	}
	return confine.ExecDefault, false
}

func parseFileRule(line string, tun tunables) ([]confine.Rule, []confine.ExecRule, []confine.LinkRule, bool) {
	body := strings.TrimSuffix(strings.TrimSpace(line), ",")
	var owner, deny, audit bool
	for {
		switch {
		case strings.HasPrefix(body, "owner "):
			owner = true
			body = strings.TrimSpace(body[len("owner "):])
			continue
		case strings.HasPrefix(body, "deny "):
			deny = true
			body = strings.TrimSpace(body[len("deny "):])
			continue
		case strings.HasPrefix(body, "audit "):
			audit = true
			body = strings.TrimSpace(body[len("audit "):])
			continue
		case strings.HasPrefix(body, "allow "):
			body = strings.TrimSpace(body[len("allow "):])
			continue
		}
		break
	}
	// The "file" rule class. Bare "file" is every access to every path;
	// "file /p rw" is the same as "/p rw".
	if body == "file" {
		// apparmor_parser expands bare "file" to /{**,}, which matches "/"
		// itself: the compiled regex is /([^\x00]*|). "/**" alone does not,
		// because a whole-component wildcard needs at least one character
		// after the slash, so a profile built on bare "file" could not open
		// the root directory. Two patterns cover the same set of real paths.
		rules := []confine.Rule{{
			Pattern: "/**",
			Perms:   confine.ParsePerms("mrwlkix"),
			Owner:   owner,
			Deny:    deny,
			Audit:   audit,
		}, {
			Pattern: "/",
			Perms:   confine.ParsePerms("mrwlkix"),
			Owner:   owner,
			Deny:    deny,
			Audit:   audit,
		}}
		links := []confine.LinkRule{{
			Pattern: "/**",
			Target:  "/**",
			Subset:  true,
			Owner:   owner,
			Deny:    deny,
			Audit:   audit,
		}}
		if deny {
			return rules, nil, links, true
		}
		// "file" grants exec with no transition modifier.
		return rules, []confine.ExecRule{{Pattern: "/**"}}, links, true
	}
	if rest, ok := strings.CutPrefix(body, "file "); ok {
		body = strings.TrimSpace(rest)
	}
	// A rule may name a target: "/path Px -> profile" for an exec
	// transition, "/path l -> /target" for a link. The permissions are the
	// field before the arrow; reading the last field instead would take the
	// target's letters for permission characters, losing the real ones.
	var target string
	if before, after, ok := strings.Cut(body, "->"); ok {
		body = strings.TrimSpace(before)
		target = strings.Trim(strings.TrimSpace(after), `"`)
	}
	fields, ok := ruleFields(body)
	if !ok || len(fields) < 2 {
		return nil, nil, nil, false
	}
	permField := fields[len(fields)-1]
	perms := confine.ParsePerms(permField)
	if perms == 0 {
		return nil, nil, nil, false
	}
	var out []confine.Rule
	for _, expanded := range tun.expand(fields[0]) {
		if !strings.HasPrefix(expanded, "/") {
			continue
		}
		for _, pattern := range expandAlternations(markBraceWildcards(expanded)) {
			out = append(out, confine.Rule{
				Pattern: normalizeSlashes(pattern),
				Perms:   perms,
				Owner:   owner,
				Deny:    deny,
				Audit:   audit,
			})
		}
	}
	if len(out) == 0 {
		return nil, nil, nil, false
	}
	// The 'l' permission is a link rule: "/foo l," is
	// "link subset /foo -> /**,". A target may be named explicitly, as in
	// "/foo l -> /bar,".
	var linkRules []confine.LinkRule
	if perms&confine.Link != 0 {
		linkTarget := target
		if linkTarget == "" {
			linkTarget = "/**"
		}
		for _, r := range out {
			linkRules = append(linkRules, confine.LinkRule{
				Pattern: r.Pattern,
				Target:  linkTarget,
				Subset:  true,
				Owner:   owner,
				Deny:    deny,
				Audit:   audit,
			})
		}
	}
	// A rule that permits execution also decides the profile a task enters
	// when it execs a matching path. A deny rule grants nothing, so it
	// carries no transition.
	var execRules []confine.ExecRule
	if perms&confine.Exec != 0 && !deny {
		mode, scrub := execModeOf(permField)
		if mode == confine.ExecDefault && body != "file" && !strings.HasPrefix(body, "file ") {
			// "A bare 'x' is only allowed in rules with the deny
			// qualifier". Guessing a transition for one would be
			// inventing policy, so report it instead.
			return nil, nil, nil, false
		}
		for _, r := range out {
			execRules = append(execRules, confine.ExecRule{
				Pattern: r.Pattern,
				Mode:    mode,
				Target:  target,
				Scrub:   scrub,
			})
		}
	}
	return out, execRules, linkRules, true
}

// ParseAppArmorProfiles derives policy from the AppArmor profile text in r.
// name is used only for log messages.
func ParseAppArmorProfiles(r io.Reader, name string, policy *AppArmorPolicy, tun tunables) error {
	return parseAppArmorProfiles(hostPolicyFS{}, r, name, policy, tun, "", nil, 0, "")
}

// maxIncludeDepth bounds include nesting, so that a cycle the seen set does
// not catch cannot recurse without end.
const maxIncludeDepth = 16

// parseAppArmorProfiles is ParseAppArmorProfiles with the state needed to
// follow includes: dir is the policy directory that <...> includes resolve
// against, seen holds the files already parsed into a given profile, and
// profile is the profile an included file's bare rules belong to.
func parseAppArmorProfiles(pfs policyFS, r io.Reader, name string, policy *AppArmorPolicy, tun tunables, dir string, seen map[string]bool, depth int, profile string) error {
	var (
		scanner = bufio.NewScanner(r)
		ignored = make(map[string]int)
		// stack holds the enclosing profiles of the current one, for
		// policy that nests child profiles inside a profile.
		stack []string
	)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// "#include" is a directive, not a comment, and must be tested
		// for before comments are skipped.
		if len(line) == 0 || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#include")) {
			continue
		}
		// Variable definition: @{NAME} = /a /b. A line merely starting
		// with a variable reference is a rule, not a definition.
		if varDefRE.MatchString(line) {
			if eq := strings.Index(line, "="); eq > 0 {
				// "=" assigns, "+=" adds to an existing
				// definition. Assigning must replace: a
				// tunables file is read once per profile that
				// includes it, and appending there would grow
				// the variable without bound, multiplying the
				// rules every expansion produces.
				add := eq > 0 && line[eq-1] == '+'
				varName := strings.TrimSpace(line[:eq])
				varName = strings.TrimSuffix(strings.TrimPrefix(varName, "@{"), "}")
				varName = strings.TrimSuffix(strings.TrimSpace(varName), "+")
				varName = strings.TrimSuffix(strings.TrimSpace(varName), "}")
				varName = strings.TrimPrefix(varName, "@{")
				var values []string
				for _, v := range strings.Fields(line[eq+1:]) {
					values = append(values, tun.expand(v)...)
				}
				if add {
					values = append(tun[varName], values...)
				}
				tun[varName] = dedup(values)
			}
			continue
		}
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "profile" {
			stack = append(stack, profile)
			profile = strings.TrimSuffix(fields[1], "{")
			policy.Profiles = append(policy.Profiles, profile)
			// "The special @{profile_name} variable is automatically
			// set to the current profile's name."
			tun["profile_name"] = []string{profile}
			if hasComplainFlag(line) {
				// A complain profile logs what it would deny
				// and permits it. Record it now: the profile
				// may have no rules of its own.
				profileRules(policy, profile).Complain = true
			}
			if hasAuditFlag(line) {
				profileRules(policy, profile).Audit = true
			}
			if mode, sig, errno := profileModeFlags(line); mode != confine.ModeEnforce || sig != 0 || errno != 0 {
				cp := profileRules(policy, profile)
				cp.Mode = mode
				cp.KillSignal = sig
				cp.Error = errno
			}
			// A profile attaches on exec of the path it names. That is
			// the profile's own name when the name is a path
			// ("profile /bin/cagebash {"), or the attachment
			// specification that follows the name ("profile cage
			// /bin/cagebash {").
			attach := ""
			if strings.HasPrefix(profile, "/") {
				attach = profile
			} else if len(fields) >= 3 {
				if spec := strings.TrimSuffix(fields[2], "{"); strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "@{") {
					attach = spec
				}
			}
			if attach != "" {
				if policy.ExecAttach == nil {
					policy.ExecAttach = make(map[string]string)
				}
				// The attachment is one AARE expression, not a list, but
				// variables and alternations give it several values:
				// "profile cagebash /{usr/,}bin/cagebash" attaches both
				// /usr/bin/cagebash and /bin/cagebash on a real kernel,
				// and each value must enter the profile here too.
				for _, v := range tun.expand(attach) {
					for _, a := range expandAlternations(markBraceWildcards(v)) {
						a = strings.ReplaceAll(a, braceWildcardMarker, "")
						if strings.HasPrefix(a, "/") {
							policy.ExecAttach[a] = profile
						}
					}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "include") {
			if dir == "" {
				// No policy directory to resolve against.
				ignored["include"]++
				continue
			}
			if err := parseInclude(pfs, line, name, policy, tun, dir, seen, depth, profile); err != nil {
				return err
			}
			continue
		}
		// A rule may carry a trailing comment, which would otherwise be
		// taken for part of the rule: in abstractions/nss-systemd,
		// "@{run}/... rw,  # UNIX/glibc NSS" would be read as having
		// permissions "NSS".
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if len(line) == 0 {
				continue
			}
		}
		// A hat is a subprofile of the profile being parsed, named
		// "<profile>//^<hat>", and is the only kind of subprofile
		// aa_change_hat(3) may enter.
		if profile != "" {
			if hat, ok := hatDeclaration(line); ok {
				stack = append(stack, profile)
				profile = confine.HatName(profile, hat)
				policy.Profiles = append(policy.Profiles, profile)
				cp := profileRules(policy, profile)
				cp.IsHat = true
				if hasComplainFlag(line) {
					cp.Complain = true
				}
				if hasAuditFlag(line) {
					cp.Audit = true
				}
				continue
			}
		}
		// The end of a block. A profile may contain child profiles, so
		// the enclosing profile is restored rather than cleared: rules
		// after a child's closing brace belong to the parent again.
		if line == "}" {
			if len(stack) != 0 {
				profile = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			} else {
				profile = ""
			}
			continue
		}
		// Collect file rules of the current profile. A rule is
		// "[qualifiers] <path pattern> <perms>,".
		if profile == "" {
			// A rule outside any profile belongs to nothing and is
			// not enforced. Record it: dropping it silently is what
			// the Unenforced list exists to prevent.
			policy.Unenforced = append(policy.Unenforced, UnenforcedLine{
				File: name, Line: line,
			})
			continue
		}
		if rules, linkRules, ok := parseLinkRule(line, tun); ok {
			cp := profileRules(policy, profile)
			cp.Rules = append(cp.Rules, rules...)
			cp.LinkRules = append(cp.LinkRules, linkRules...)
			continue
		}
		if targets, ok := parseChangeProfileRule(line, tun); ok {
			cp := profileRules(policy, profile)
			cp.ChangeProfile = append(cp.ChangeProfile, targets...)
			continue
		}
		rule, execRules, linkRules, ok := parseFileRule(line, tun)
		if !ok {
			if kind := strings.Fields(line)[0]; strings.HasPrefix(kind, "/") || strings.HasPrefix(kind, "@{") {
				ignored["file rule (unparsed)"]++
			} else {
				ignored[strings.TrimSuffix(kind, ",")]++
			}
			policy.Unenforced = append(policy.Unenforced, UnenforcedLine{
				File: name, Profile: profile, Line: line,
			})
			continue
		}
		cp := profileRules(policy, profile)
		cp.Rules = append(cp.Rules, rule...)
		cp.ExecRules = append(cp.ExecRules, execRules...)
		cp.LinkRules = append(cp.LinkRules, linkRules...)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}

	if len(ignored) != 0 {
		var kinds []string
		for k, n := range ignored {
			kinds = append(kinds, fmt.Sprintf("%s x%d", k, n))
		}
		sort.Strings(kinds)
		log.Infof("AppArmor %s: rules not enforced in-sandbox (enforce them on the sentry/gofer with --host-apparmor instead): %s", name, strings.Join(kinds, ", "))
		for _, u := range policy.Unenforced {
			if u.File == name {
				log.Debugf("AppArmor %s: profile %q: not enforced in-sandbox: %s", u.File, u.Profile, u.Line)
			}
		}
	}
	return nil
}

// includeRE matches an include directive: "#include <abstractions/base>",
// "include \"tunables/global\"", or either with "if exists" before the path.
var includeRE = regexp.MustCompile(`^#?include\s+(if\s+exists\s+)?[<"]([^>"]+)[>"]`)

// parseInclude resolves an include directive and parses what it names. A
// <path> include resolves against the policy directory, as apparmor_parser
// resolves it against its include path. An include naming a directory pulls in
// every file in it, as AppArmor does.
func parseInclude(pfs policyFS, line, name string, policy *AppArmorPolicy, tun tunables, dir string, seen map[string]bool, depth int, profile string) error {
	m := includeRE.FindStringSubmatch(line)
	if m == nil {
		return fmt.Errorf("AppArmor %s: cannot parse include %q", name, line)
	}
	ifExists := m[1] != ""
	// An include naming an absolute path is used as given; a relative one
	// resolves against the policy directory, as apparmor_parser resolves it
	// against its include path.
	target := m[2]
	if filepath.IsAbs(target) {
		target = filepath.Clean(target)
	} else {
		target = filepath.Join(dir, filepath.Clean("/"+target))
	}
	if depth >= maxIncludeDepth {
		return fmt.Errorf("AppArmor %s: include of %q nested more than %d deep", name, m[2], maxIncludeDepth)
	}
	isDir, err := pfs.Stat(target)
	if err != nil {
		if pfs.IsNotExist(err) && ifExists {
			return nil
		}
		if pfs.IsNotExist(err) {
			// A missing include would silently drop the rules it was
			// meant to add, leaving a profile weaker than it reads.
			return fmt.Errorf("AppArmor %s: include %q: %w", name, m[2], err)
		}
		return err
	}
	if !isDir {
		return parseIncludeFile(pfs, target, policy, tun, dir, seen, depth+1, profile)
	}
	entries, err := pfs.ReadDir(target)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir || skipPolicyFile(e.Name) {
			continue
		}
		if err := parseIncludeFile(pfs, filepath.Join(target, e.Name), policy, tun, dir, seen, depth+1, profile); err != nil {
			return err
		}
	}
	return nil
}

// parseIncludeFile parses one included file, at most once per profile. The
// same abstraction included by several profiles must contribute its rules to
// each of them, so the profile is part of the key.
func parseIncludeFile(pfs policyFS, path string, policy *AppArmorPolicy, tun tunables, dir string, seen map[string]bool, depth int, profile string) error {
	key := profile + "\x00" + path
	if seen[key] {
		return nil
	}
	seen[key] = true
	f, err := pfs.Open(path)
	if err != nil {
		return fmt.Errorf("opening AppArmor include %q: %w", path, err)
	}
	defer f.Close()
	return parseAppArmorProfiles(pfs, f, path, policy, tun, dir, seen, depth, profile)
}

// flagsRE matches the flags of a profile declaration, e.g.
// "profile p flags=(complain, attach_disconnected) {".
var flagsRE = regexp.MustCompile(`flags\s*=\s*\(([^)]*)\)`)

// hasComplainFlag reports whether a profile declaration carries the complain
// flag, which makes the profile log what it would deny rather than deny it.
func hasComplainFlag(line string) bool {
	return hasProfileFlag(line, "complain")
}

// hasAuditFlag reports whether a profile declaration carries the audit flag,
// which "causes all actions whether allowed or denied to be logged".
func hasAuditFlag(line string) bool {
	return hasProfileFlag(line, "audit")
}

// profileModeFlags reads the enforcement mode, kill signal and error code a
// profile declaration's flags select.
func profileModeFlags(line string) (confine.ProfileMode, int32, int32) {
	mode := confine.ModeEnforce
	var killSignal, errno int32
	m := flagsRE.FindStringSubmatch(line)
	if m == nil {
		return mode, 0, 0
	}
	for _, f := range strings.Split(m[1], ",") {
		f = strings.TrimSpace(f)
		switch {
		case f == "enforce":
			mode = confine.ModeEnforce
		case f == "complain":
			mode = confine.ModeComplain
		case f == "kill":
			mode = confine.ModeKill
		case f == "default_allow":
			mode = confine.ModeDefaultAllow
		case f == "unconfined":
			mode = confine.ModeUnconfined
		case strings.HasPrefix(f, "kill.signal="):
			if sig, ok := signalNumber(strings.TrimPrefix(f, "kill.signal=")); ok {
				killSignal = sig
			}
		case strings.HasPrefix(f, "error="):
			if e, ok := errnoNumber(strings.TrimPrefix(f, "error=")); ok {
				errno = e
			}
		}
	}
	return mode, killSignal, errno
}

// signalNumber resolves a signal named in "kill.signal=", by number or by name
// with or without the SIG prefix.
func signalNumber(s string) (int32, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		if !linux.Signal(n).IsValid() {
			return 0, false
		}
		return int32(n), true
	}
	name := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(s), "SIG"))
	switch name {
	case "KILL":
		return int32(linux.SIGKILL), true
	case "TERM":
		return int32(linux.SIGTERM), true
	case "ABRT":
		return int32(linux.SIGABRT), true
	case "SEGV":
		return int32(linux.SIGSEGV), true
	case "QUIT":
		return int32(linux.SIGQUIT), true
	case "STOP":
		return int32(linux.SIGSTOP), true
	}
	return 0, false
}

// errnoNumber resolves an errno named in "error=", by number or by name.
func errnoNumber(s string) (int32, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		if !linux.Signal(n).IsValid() {
			return 0, false
		}
		return int32(n), true
	}
	switch strings.ToUpper(s) {
	case "EACCES":
		return int32(unix.EACCES), true
	case "EPERM":
		return int32(unix.EPERM), true
	case "ENOENT":
		return int32(unix.ENOENT), true
	case "EROFS":
		return int32(unix.EROFS), true
	case "EIO":
		return int32(unix.EIO), true
	}
	return 0, false
}

// hasProfileFlag reports whether a profile declaration carries a flag.
func hasProfileFlag(line, want string) bool {
	m := flagsRE.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	for _, f := range strings.Split(m[1], ",") {
		if strings.TrimSpace(f) == want {
			return true
		}
	}
	return false
}

// hatDeclaration returns the name of the hat a line declares, if it declares
// one. A hat is written "^name { ... }" or "hat name { ... }".
func hatDeclaration(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "^")
	if !ok {
		if rest, ok = strings.CutPrefix(line, "hat "); !ok {
			return "", false
		}
	}
	rest = strings.TrimSpace(rest)
	// The name runs to the flags, the brace, or the end of the line.
	if i := strings.IndexAny(rest, " \t{"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}

// profileRules returns the named profile's entry in policy, creating it if
// this is the first rule seen for it.
func profileRules(policy *AppArmorPolicy, profile string) *confine.Profile {
	if policy.Rules == nil {
		policy.Rules = make(map[string]*confine.Profile)
	}
	cp := policy.Rules[profile]
	if cp == nil {
		cp = &confine.Profile{Name: profile}
		policy.Rules[profile] = cp
	}
	return cp
}

// parseLinkRule parses "link [subset] /source -> /target,". apparmor.d(5)
// defines "l /foo" as shorthand for "link subset /foo -> /**", so a link rule
// grants 'l' on the source; the target is not otherwise mediated here, and the
// subset condition is applied by the same check the 'l' permission uses.
func parseLinkRule(line string, tun tunables) ([]confine.Rule, []confine.LinkRule, bool) {
	body := strings.TrimSuffix(strings.TrimSpace(line), ",")
	var deny, audit, owner bool
	for {
		switch {
		case strings.HasPrefix(body, "deny "):
			deny = true
			body = strings.TrimSpace(body[len("deny "):])
			continue
		case strings.HasPrefix(body, "audit "):
			audit = true
			body = strings.TrimSpace(body[len("audit "):])
			continue
		case strings.HasPrefix(body, "owner "):
			owner = true
			body = strings.TrimSpace(body[len("owner "):])
			continue
		case strings.HasPrefix(body, "allow "):
			body = strings.TrimSpace(body[len("allow "):])
			continue
		}
		break
	}
	rest, ok := strings.CutPrefix(body, "link ")
	if !ok {
		return nil, nil, false
	}
	rest = strings.TrimSpace(rest)
	// "subset" is a condition, not part of the path. Without it the link may
	// have permissions the file it points at does not.
	subset := false
	if after, ok := strings.CutPrefix(rest, "subset "); ok {
		rest = strings.TrimSpace(after)
		subset = true
	}
	source, targetField, ok := strings.Cut(rest, "->")
	if !ok {
		// A link rule without a target names only the source.
		source = rest
	}
	source = strings.Trim(strings.TrimSpace(source), `"`)
	if !strings.HasPrefix(source, "/") && !strings.HasPrefix(source, "@{") {
		return nil, nil, false
	}
	targets := []string{"/**"}
	if t := strings.Trim(strings.TrimSpace(targetField), `"`); t != "" {
		targets = nil
		for _, expanded := range tun.expand(t) {
			targets = append(targets, expandAlternations(markBraceWildcards(normalizeSlashes(expanded)))...)
		}
		if len(targets) == 0 {
			return nil, nil, false
		}
	}
	var (
		out       []confine.Rule
		linkRules []confine.LinkRule
	)
	for _, expanded := range tun.expand(source) {
		for _, pattern := range expandAlternations(markBraceWildcards(expanded)) {
			if !strings.HasPrefix(pattern, "/") {
				continue
			}
			pattern = normalizeSlashes(pattern)
			out = append(out, confine.Rule{
				Pattern: pattern,
				Perms:   confine.Link,
				Owner:   owner,
				Deny:    deny,
				Audit:   audit,
			})
			for _, t := range targets {
				linkRules = append(linkRules, confine.LinkRule{
					Pattern: pattern,
					Target:  t,
					Subset:  subset,
					Owner:   owner,
					Deny:    deny,
					Audit:   audit,
				})
			}
		}
	}
	return out, linkRules, len(out) != 0
}

// parseChangeProfileRule parses a change_profile rule into the patterns of the
// profiles it permits changing to. A bare "change_profile," permits any
// profile. An exec condition ("change_profile /bin/foo -> bar") is recorded
// with the rule, which then only permits the target on exec of a matching
// path.
func parseChangeProfileRule(line string, tun tunables) ([]confine.ChangeRule, bool) {
	body := strings.TrimSuffix(strings.TrimSpace(line), ",")
	var deny bool
	for {
		switch {
		case strings.HasPrefix(body, "audit "):
			body = strings.TrimSpace(body[len("audit "):])
			continue
		case strings.HasPrefix(body, "allow "):
			body = strings.TrimSpace(body[len("allow "):])
			continue
		case strings.HasPrefix(body, "deny "):
			deny = true
			body = strings.TrimSpace(body[len("deny "):])
			continue
		}
		break
	}
	if body != "change_profile" && !strings.HasPrefix(body, "change_profile ") {
		return nil, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(body, "change_profile"))
	if rest == "" {
		// No target names every profile: "change_profile," permits any
		// transition and "deny change_profile," refuses all of them.
		return []confine.ChangeRule{{Pattern: "**", Deny: deny}}, true
	}
	// The remainder is "[<exec condition>] -> <target>". The exec condition
	// restricts which executable the transition may accompany, and is
	// evaluated when the transition is applied at exec.
	execCond, target, ok := strings.Cut(rest, "->")
	if !ok {
		return nil, false
	}
	execCond = strings.Trim(strings.TrimSpace(execCond), `"`)
	target = strings.TrimSpace(target)
	// A target may be quoted, and may name a profile through a variable.
	target = strings.Trim(target, `"`)
	if target == "" {
		return nil, false
	}
	var out []confine.ChangeRule
	for _, pattern := range tun.expand(target) {
		out = append(out, confine.ChangeRule{Pattern: pattern, Deny: deny, Exec: execCond})
	}
	return out, len(out) != 0
}

// skippedSuffixes are the file names apparmor_parser itself ignores in a
// policy directory: package manager leftovers and editor backups. Parsing them
// would define profiles from stale text, and one broken leftover would
// otherwise fail the whole load.
var skippedSuffixes = []string{
	".dpkg-bak", ".dpkg-new", ".dpkg-old", ".dpkg-dist", ".dpkg-remove",
	".rpmsave", ".rpmnew", ".orig", ".rej", "~",
}

// skipPolicyFile reports whether a file in the policy directory is not policy.
func skipPolicyFile(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	for _, suffix := range skippedSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// policyFS is where profile text is read from. The host's filesystem and the
// container's are both possible sources; see --apparmor-policy-source.
type policyFS interface {
	// ReadDir returns the names of the entries of a directory, and whether
	// each is itself a directory.
	ReadDir(path string) ([]policyDirent, error)

	// Stat reports whether a path exists and whether it is a directory.
	Stat(path string) (isDir bool, err error)

	// Open opens a file for reading. The caller closes it.
	Open(path string) (io.ReadCloser, error)

	// IsNotExist reports whether an error from Stat or Open means the path
	// does not exist.
	IsNotExist(err error) bool
}

// policyDirent is one entry of a policy directory.
type policyDirent struct {
	Name  string
	IsDir bool
}

// hostPolicyFS reads policy from the host's filesystem.
type hostPolicyFS struct{}

// ReadDir implements policyFS.ReadDir.
func (hostPolicyFS) ReadDir(path string) ([]policyDirent, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]policyDirent, 0, len(entries))
	for _, e := range entries {
		out = append(out, policyDirent{Name: e.Name(), IsDir: e.IsDir()})
	}
	return out, nil
}

// Stat implements policyFS.Stat.
func (hostPolicyFS) Stat(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.IsDir(), nil
}

// Open implements policyFS.Open.
func (hostPolicyFS) Open(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// IsNotExist implements policyFS.IsNotExist.
func (hostPolicyFS) IsNotExist(err error) bool { return os.IsNotExist(err) }

// LoadAppArmorPolicyDir derives policy from every profile file in dir on the
// host's filesystem.
func LoadAppArmorPolicyDir(dir string) (*AppArmorPolicy, error) {
	return loadAppArmorPolicyDir(hostPolicyFS{}, dir)
}

func loadAppArmorPolicyDir(pfs policyFS, dir string) (*AppArmorPolicy, error) {
	entries, err := pfs.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading AppArmor profile directory %q: %w", dir, err)
	}
	policy := &AppArmorPolicy{}
	tun := make(tunables)
	// Included files are parsed once per profile that includes them.
	seen := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		if skipPolicyFile(e.Name) {
			log.Infof("AppArmor: skipping %q in the policy directory: not a profile", e.Name)
			continue
		}
		path := filepath.Join(dir, e.Name)
		f, err := pfs.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening AppArmor profile %q: %w", path, err)
		}
		err = parseAppArmorProfiles(pfs, f, e.Name, policy, tun, dir, seen, 0, "")
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	for name, cp := range policy.Rules {
		log.Infof("AppArmor profile %q: %d file rules enforced in-sandbox", name, len(cp.Rules))
	}
	log.Infof("AppArmor policy loaded from %q: profiles=%d with rules=%d exec-attached=%v", dir, len(policy.Profiles), len(policy.Rules), policy.ExecAttach)
	return policy, nil
}
