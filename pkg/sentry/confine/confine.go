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

// Package confine implements in-sandbox enforcement of AppArmor file rules.
//
// An application's system calls are serviced by the Sentry and never reach the
// host kernel, so host AppArmor cannot mediate them. The rules of the profile
// a task has entered are evaluated here instead, against the path the
// application sees.
//
// The model follows AppArmor's: a profile is an allow list, 'deny' rules take
// precedence over allow rules, and an 'owner' rule additionally requires that
// the accessing task's UID match the file's. Only file rules are evaluated
// here; other rule classes are enforced on the Sentry and Gofer by a host
// profile (--host-apparmor).
package confine

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Perm is a file permission that a rule may grant, mirroring the
// permission characters of an AppArmor file rule.
type Perm uint16

// Permissions that in-sandbox enforcement distinguishes. Rule characters that
// do not affect whether an access is permitted (such as 'i', 'u', 'U', 'p' and
// 'P', which select an exec transition) are parsed but do not appear here.
const (
	Read Perm = 1 << iota
	Write
	Exec
	Append
	Link
	Lock
	Mmap
)

// Rule is one file rule of a profile.
//
// +stateify savable
type Rule struct {
	// Pattern is the rule's path pattern, using AppArmor's glob syntax.
	Pattern string

	// Perms are the permissions the rule concerns.
	Perms Perm

	// Owner is true if the rule is qualified with 'owner', which requires
	// the accessing task to own the file.
	Owner bool

	// Deny is true if the rule is a 'deny' rule, which overrides allow
	// rules regardless of order.
	Deny bool
}

// ExecMode is the transition a file rule's exec modifier asks for when the rule
// permits executing a path.
type ExecMode int

const (
	// ExecDefault is an exec rule with no transition modifier, as a bare
	// "x" or the "file" rule class grants. The task enters the profile
	// named after the executable if the policy defines one, and keeps its
	// own otherwise.
	ExecDefault ExecMode = iota

	// ExecInherit is "ix": the task keeps the profile it is in.
	ExecInherit

	// ExecProfile is "px" or "Px": the task enters the named profile, or
	// the profile named after the executable if the rule names none. The
	// exec fails if that profile is not defined.
	ExecProfile

	// ExecChild is "cx" or "Cx": the task enters a profile of the current
	// profile's namespace, named "<current>//<target>".
	ExecChild

	// ExecUnconfined is "ux" or "Ux": the task runs unconfined. This is the
	// one way a confined task may leave its profile, and only because its
	// own profile asks for it.
	ExecUnconfined
)

// ExecRule is the exec transition of one file rule that permits execution.
//
// +stateify savable
type ExecRule struct {
	// Pattern matches the path being executed.
	Pattern string

	// Mode is the transition the rule asks for.
	Mode ExecMode

	// Target is the profile named after "->", empty if the rule names none.
	Target string
}

// ChangeRule is one change_profile rule: the pattern of the profiles it names
// and whether it denies them.
//
// +stateify savable
type ChangeRule struct {
	// Pattern matches the name of the profile being changed to.
	Pattern string

	// Deny makes the rule refuse the change. A matching deny rule
	// overrides any allow rule, as it does for file rules.
	Deny bool
}

// Profile is the set of file rules of one profile.
//
// +stateify savable
type Profile struct {
	// Name is the profile's name, as written in the policy.
	Name string

	// Rules are the profile's file rules.
	Rules []Rule

	// ChangeProfile are the profile's change_profile rules. A task may
	// change to a profile an allow rule matches and no deny rule matches.
	ChangeProfile []ChangeRule

	// ExecRules are the transitions of the profile's rules that permit
	// execution, which decide the profile a task enters when it execs.
	ExecRules []ExecRule

	// dfa is the profile's rules compiled into one automaton over the bytes
	// of a path, built when the policy is installed and immutable after
	// that. It is nil for a profile too large to compile, which is then
	// matched with byFirst and wild instead.
	dfa *dfa

	// byFirst indexes Rules by the first component of their pattern, and
	// wild holds the rules whose first component is itself a pattern. They
	// are only used when dfa is nil.
	byFirst map[string][]int32
	wild    []int32

	// Complain is set for a profile declared with the 'complain' flag. A
	// complain profile logs what it would have denied and permits it, so
	// that a profile can be developed against a real workload before it is
	// switched to enforcing.
	Complain bool
}

// policy holds the loaded profiles. It is written once during sandbox
// startup and read-only afterwards, but is guarded so that a restore or a
// future reload cannot race with an access.
var policy struct {
	mu sync.RWMutex
	// profiles maps a profile name to its rules.
	profiles map[string]*Profile
}

// SetPolicy installs the profiles that in-sandbox enforcement
// evaluates. It must be called before application tasks run.
func SetPolicy(profiles map[string]*Profile) {
	for _, p := range profiles {
		p.index()
	}
	policy.mu.Lock()
	defer policy.mu.Unlock()
	policy.profiles = profiles
}

// firstComponent returns the first component of an absolute path, and is the
// key rules are indexed by. "/usr/lib/libc.so" yields "usr".
func firstComponent(path string) string {
	if len(path) != 0 && path[0] == '/' {
		path = path[1:]
	}
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return path
}

// isLiteral reports whether s contains no pattern metacharacter, so that it
// can only match itself.
func isLiteral(s string) bool {
	return !strings.ContainsAny(s, "*?[{")
}

// index groups the profile's rules by the first component of their pattern, so
// that a check examines only the rules that could match rather than all of
// them. A profile of a few hundred rules is scanned on every file access, which
// is far too hot for a linear walk.
func (p *Profile) index() {
	p.dfa = compile(p.Name, p.Rules)
	p.byFirst = nil
	p.wild = nil
	for i := range p.Rules {
		first := firstComponent(p.Rules[i].Pattern)
		if !isLiteral(first) {
			// The first component itself is a pattern, so it may
			// match any path; these are checked for every access.
			p.wild = append(p.wild, int32(i))
			continue
		}
		if p.byFirst == nil {
			p.byFirst = make(map[string][]int32)
		}
		p.byFirst[first] = append(p.byFirst[first], int32(i))
	}
}

// CheckChangeProfile reports whether a task in profile from may change to
// profile to, as aa_change_profile(3) does. An unconfined task may enter any
// profile the policy defines; a confined one may only enter a profile matching
// one of its own profile's change_profile targets.
//
// The target must be a profile the policy defines. Entering an undefined
// profile would deny the task every access, which is not what a policy
// permitting the transition means.
func CheckChangeProfile(from, to string) error {
	if !HasProfile(to) {
		log.Warningf("confinement: profile %q denied change to %q: the policy does not define it", from, to)
		return linuxerr.EACCES
	}
	if from == "" {
		return nil
	}
	if from == to {
		// Changing to the profile already in force changes nothing, so
		// there is no transition to mediate.
		return nil
	}
	profile := profileFor(from)
	if profile == nil {
		log.Warningf("confinement: task in undefined profile %q denied change to %q", from, to)
		return linuxerr.EACCES
	}
	allowed := false
	for _, r := range profile.ChangeProfile {
		if !MatchPattern(r.Pattern, to) {
			continue
		}
		if r.Deny {
			// A matching deny rule overrides any allow rule,
			// wherever it appears in the profile.
			return profile.denyChange(to, fmt.Sprintf("deny change_profile rule %q", r.Pattern))
		}
		allowed = true
	}
	if !allowed {
		return profile.denyChange(to, "no change_profile rule allows it")
	}
	return nil
}

// denyChange logs a refused profile transition and returns the error to fail
// it with. A complain-mode profile logs and permits.
func (p *Profile) denyChange(to, why string) error {
	if p.Complain {
		log.Warningf("confinement: profile %q would have denied a change to %q (%s); permitted, profile is in complain mode", p.Name, to, why)
		return nil
	}
	log.Warningf("confinement: profile %q denied a change to %q (%s)", p.Name, to, why)
	return linuxerr.EACCES
}

// TransitionOnExec returns the confinement profile a task in profile from
// enters when it execs path, which may be from itself. An empty from is an
// unconfined task, and an empty result leaves the task unconfined.
//
// The profile's own exec rules decide the transition. Where several match, the
// most specific pattern wins, as it does in AppArmor; a rule that names a
// transition wins over one that does not. An error fails the exec, which is
// what a "px" rule naming a profile the policy does not define must do: running
// the program in the wrong profile is not a safe substitute.
func TransitionOnExec(from, path string) (string, error) {
	if from == "" {
		// An unconfined task enters the profile named after the
		// executable, if the policy defines one.
		if name, ok := auth.ExecConfinementProfile(path); ok {
			return name, nil
		}
		return "", nil
	}
	profile := profileFor(from)
	if profile == nil {
		// A task in a profile the policy does not define is denied
		// everything; it must not exec its way out of that.
		return from, nil
	}
	r := profile.execRuleFor(path)
	if r == nil {
		// No exec rule matched. The file check has already decided
		// whether the exec is permitted at all, so keep the profile.
		return from, nil
	}
	switch r.Mode {
	case ExecInherit:
		return from, nil
	case ExecUnconfined:
		// The only way out of a profile, and only because the profile
		// asks for it. Worth a log line either way.
		log.Infof("confinement: profile %q runs %q unconfined (rule %q)", from, path, r.Pattern)
		return "", nil
	case ExecProfile:
		target := r.Target
		if target == "" {
			target = path
		}
		if !HasProfile(target) {
			log.Warningf("confinement: profile %q denied exec of %q: its rule %q requires profile %q, which the policy does not define", from, path, r.Pattern, target)
			return "", linuxerr.EACCES
		}
		return target, nil
	case ExecChild:
		target := from + "//" + r.Target
		if !HasProfile(target) {
			log.Warningf("confinement: profile %q denied exec of %q: its rule %q requires child profile %q, which the policy does not define", from, path, r.Pattern, target)
			return "", linuxerr.EACCES
		}
		return target, nil
	default:
		// No modifier: enter the profile named after the executable if
		// there is one, which is what a path-named profile means, and
		// keep the current profile otherwise.
		if name, ok := auth.ExecConfinementProfile(path); ok {
			return name, nil
		}
		return from, nil
	}
}

// execRuleFor returns the exec rule of p that governs exec'ing path, or nil if
// none matches. The most specific pattern wins, and among equally specific ones
// a rule that names a transition wins over one that does not.
func (p *Profile) execRuleFor(path string) *ExecRule {
	var best *ExecRule
	for i := range p.ExecRules {
		r := &p.ExecRules[i]
		if !MatchPattern(r.Pattern, path) {
			continue
		}
		if best == nil {
			best = r
			continue
		}
		if len(r.Pattern) > len(best.Pattern) {
			best = r
			continue
		}
		if len(r.Pattern) == len(best.Pattern) && best.Mode == ExecDefault && r.Mode != ExecDefault {
			best = r
		}
	}
	return best
}

// HasProfile reports whether the policy defines the named profile. A task
// must not be put into a profile that is not defined: enforcement denies
// every access of a task in an undefined profile.
func HasProfile(name string) bool {
	return profileFor(name) != nil
}

// profileFor returns the rules of the named profile, or nil if the
// policy does not define it.
func profileFor(name string) *Profile {
	policy.mu.RLock()
	defer policy.mu.RUnlock()
	if policy.profiles == nil {
		return nil
	}
	return policy.profiles[name]
}

// permsFor maps an access to the permissions it requires.
func permsFor(ats vfs.AccessTypes, isDir bool) Perm {
	var p Perm
	if ats.MayRead() {
		p |= Read
	}
	if ats.MayWrite() {
		p |= Write
	}
	if ats.MayExec() && !isDir {
		// Traversing a directory is not mediated by AppArmor: access to
		// a path follows from a rule matching that path, not from rules
		// for its ancestors. gVisor checks MayExec on every directory it
		// walks, so requiring a permission here would deny paths the
		// profile allows. Listing a directory is a read and is mediated.
		p |= Exec
	}
	return p
}

// ParsePerms converts the permission characters of an AppArmor file
// rule into the permissions in-sandbox enforcement distinguishes. Characters
// that only select an exec transition are accepted and ignored.
func ParsePerms(s string) Perm {
	var p Perm
	for _, c := range s {
		switch c {
		case 'r':
			p |= Read
		case 'w':
			// AppArmor's 'w' grants appending as well.
			p |= Write | Append
		case 'a':
			p |= Append
		case 'x':
			p |= Exec
		case 'l':
			p |= Link
		case 'k':
			p |= Lock
		case 'm':
			p |= Mmap
		case 'i', 'u', 'U', 'p', 'P', 'c', 'C':
			// Exec transition modifiers; they qualify 'x' rather than
			// granting an access of their own.
		}
	}
	return p
}

// MatchPattern reports whether an AppArmor path pattern matches path.
//
// The supported syntax is AppArmor's: '?' matches one character other than
// '/', '*' matches any number of characters other than '/', '**' matches any
// number of characters including '/', '[...]' matches a character class, and
// '{a,b}' matches any of the comma-separated alternatives.
func MatchPattern(pattern, path string) bool {
	// Expand alternations first: {a,b}/c becomes a/c and b/c. Nested
	// alternations expand on subsequent passes.
	if i := strings.IndexByte(pattern, '{'); i >= 0 {
		depth := 0
		for j := i; j < len(pattern); j++ {
			switch pattern[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					for _, alt := range splitAlternatives(pattern[i+1 : j]) {
						if MatchPattern(pattern[:i]+alt+pattern[j+1:], path) {
							return true
						}
					}
					return false
				}
			}
		}
		// Unbalanced brace: treat literally.
	}
	return matchHere(pattern, path)
}

// splitAlternatives splits the body of an alternation on commas that are not
// inside a nested alternation.
func splitAlternatives(s string) []string {
	var (
		out   []string
		depth int
		start int
	)
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

// matchHere matches a pattern containing no alternations.
func matchHere(pattern, path string) bool {
	for len(pattern) != 0 {
		switch pattern[0] {
		case '*':
			if len(pattern) > 1 && pattern[1] == '*' {
				// '**' matches across '/'. Try every suffix,
				// shortest first.
				rest := pattern[2:]
				for i := 0; ; i++ {
					if matchHere(rest, path[i:]) {
						return true
					}
					if i >= len(path) {
						return false
					}
				}
			}
			// '*' matches within a path component.
			rest := pattern[1:]
			for i := 0; ; i++ {
				if matchHere(rest, path[i:]) {
					return true
				}
				if i >= len(path) || path[i] == '/' {
					return false
				}
			}
		case '?':
			if len(path) == 0 || path[0] == '/' {
				return false
			}
			pattern, path = pattern[1:], path[1:]
		case '[':
			end := strings.IndexByte(pattern, ']')
			if end < 0 {
				// Unbalanced: treat literally.
				if len(path) == 0 || path[0] != '[' {
					return false
				}
				pattern, path = pattern[1:], path[1:]
				continue
			}
			if len(path) == 0 || !matchClass(pattern[1:end], path[0]) {
				return false
			}
			pattern, path = pattern[end+1:], path[1:]
		default:
			if len(path) == 0 || path[0] != pattern[0] {
				return false
			}
			pattern, path = pattern[1:], path[1:]
		}
	}
	return len(path) == 0
}

// matchClass reports whether c is in the character class body (the text
// between '[' and ']'), supporting negation and ranges.
func matchClass(class string, c byte) bool {
	if c == '/' {
		// A character class never spans a path component, so it does not
		// match '/' even when negated, as in AppArmor.
		return false
	}
	negate := false
	if len(class) != 0 && (class[0] == '^' || class[0] == '!') {
		negate = true
		class = class[1:]
	}
	found := false
	for i := 0; i < len(class); i++ {
		if i+2 < len(class) && class[i+1] == '-' {
			if c >= class[i] && c <= class[i+2] {
				found = true
			}
			i += 2
			continue
		}
		if class[i] == c {
			found = true
		}
	}
	return found != negate
}

// Path builds the path of a file as the application sees it, from the path of
// the mount it lives in and the names of the file and its ancestors, ordered
// from the file up to the filesystem root. Directories are given the trailing
// slash AppArmor mediates them with, so that a rule written "/tmp/ rw" matches
// the directory and "/tmp/** rw" does not have to.
func Path(mountPath string, namesLeafFirst []string, isDir bool) string {
	var b strings.Builder
	if mountPath != "" && mountPath != "/" {
		b.WriteString(strings.TrimSuffix(mountPath, "/"))
	}
	for i := len(namesLeafFirst) - 1; i >= 0; i-- {
		if len(namesLeafFirst[i]) == 0 {
			continue
		}
		b.WriteByte('/')
		b.WriteString(namesLeafFirst[i])
	}
	if b.Len() == 0 {
		return "/"
	}
	if isDir {
		b.WriteByte('/')
	}
	return b.String()
}

// Check evaluates the rules of the profile the accessing task has
// entered against path. It returns nil if the access is permitted.
//
// path is the absolute path as the application sees it.
func Check(creds *auth.Credentials, path string, ats vfs.AccessTypes, mode linux.FileMode, kuid auth.KUID) error {
	want := permsFor(ats, mode.FileType() == linux.ModeDirectory)
	if want == 0 {
		return nil
	}
	return CheckPerms(creds, path, want, mode, kuid)
}

// CheckPerms evaluates the rules of the profile the accessing task has entered
// against path, for the permissions in want. It returns nil if all of them are
// granted. Callers that mediate an access which does not correspond to a
// vfs.AccessType, such as an executable mapping, use this directly.
func CheckPerms(creds *auth.Credentials, path string, want Perm, mode linux.FileMode, kuid auth.KUID) error {
	profile := profileFor(creds.ConfinementProfile)
	if profile == nil {
		// The task entered a profile the policy does not define. Deny,
		// rather than silently leaving it unconfined.
		log.Warningf("confinement: task in undefined profile %q denied access to %q", creds.ConfinementProfile, path)
		return linuxerr.EACCES
	}
	owned := kuid == creds.EffectiveKUID

	if d := profile.dfa; d != nil {
		a, ok := d.match(path)
		if !ok {
			// The automaton could not answer; fall through to
			// matching the rules one at a time.
			return profile.checkLinear(path, want, owned)
		}
		if a.deny&want != 0 {
			return profile.deny(permString(a.deny&want), path, "a deny rule")
		}
		granted := a.allowAny
		if owned {
			granted |= a.allowOwner
		}
		if missing := want & ^granted; missing != 0 {
			return profile.deny(permString(missing), path, fmt.Sprintf("no matching rule; owner=%t", owned))
		}
		return nil
	}

	return profile.checkLinear(path, want, owned)
}

// checkLinear evaluates path by matching the profile's rules, grouped by the
// first component of their pattern. It is the path taken when a profile has no
// compiled automaton.
func (profile *Profile) checkLinear(path string, want Perm, owned bool) error {
	var granted Perm
	for _, group := range [2][]int32{profile.byFirst[firstComponent(path)], profile.wild} {
		for _, i := range group {
			r := &profile.Rules[i]
			if r.Perms&want == 0 {
				continue
			}
			if !MatchPattern(r.Pattern, path) {
				continue
			}
			if r.Deny {
				// A matching deny rule overrides any allow
				// rule, wherever it appears in the profile.
				return profile.deny(permString(want), path, fmt.Sprintf("deny rule %q", r.Pattern))
			}
			if r.Owner && !owned {
				continue
			}
			granted |= r.Perms
		}
	}

	if missing := want & ^granted; missing != 0 {
		return profile.deny(permString(missing), path, fmt.Sprintf("no matching rule; owner=%t", owned))
	}
	return nil
}

// deny logs an access the profile does not permit and returns the error to
// fail it with. A complain-mode profile logs and permits, as it does on a host
// kernel.
func (p *Profile) deny(perms, path, why string) error {
	if p.Complain {
		log.Warningf("confinement: profile %q would have denied %s of %q (%s); permitted, profile is in complain mode", p.Name, perms, path, why)
		return nil
	}
	log.Warningf("confinement: profile %q denied %s of %q (%s)", p.Name, perms, path, why)
	return linuxerr.EACCES
}

// permString renders permissions for log messages.
func permString(p Perm) string {
	var b strings.Builder
	for _, e := range []struct {
		p Perm
		c byte
	}{
		{Read, 'r'},
		{Write, 'w'},
		{Append, 'a'},
		{Exec, 'x'},
		{Link, 'l'},
		{Lock, 'k'},
		{Mmap, 'm'},
	} {
		if p&e.p != 0 {
			b.WriteByte(e.c)
		}
	}
	return b.String()
}
