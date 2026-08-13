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
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
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

	// Audit is true if the rule is qualified with 'audit', which records
	// matching requests. A deny rule is otherwise silent: apparmor.d(5)
	// says such a request is "denied without logging. Can be combined with
	// 'audit' to enable logging."
	Audit bool
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

	// Scrub is set for the uppercase form of a transition modifier, which
	// apparmor.d(5) defines as invoking "the Linux Kernel's unsafe_exec
	// routines to scrub the environment, similar to setuid programs".
	Scrub bool
}

// ProfileMode is the enforcement mode a profile's flags select.
type ProfileMode int

const (
	// ModeEnforce denies what the profile does not permit. It is the
	// default.
	ModeEnforce ProfileMode = iota

	// ModeComplain permits what the profile does not and logs it.
	ModeComplain

	// ModeKill denies and terminates the task, from the 'kill' flag. The
	// denial returns a KillError, which the syscall layer turns into a
	// signal; see AsKillError and Task.confinementKill. Killing follows
	// auditing, as it does in Linux: a denial silenced by a deny rule does
	// not kill.
	ModeKill

	// ModeDefaultAllow permits anything no deny rule refuses, from the
	// 'default_allow' flag.
	ModeDefaultAllow

	// ModeUnconfined mediates nothing in the sandbox, from the 'unconfined'
	// flag. The profile the OCI spec named is still applied to the sentry
	// and gofer by the host, which is outside the sandbox and unaffected by
	// this.
	ModeUnconfined
)

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

	// Exec is the pattern of the executable the transition must accompany,
	// from "change_profile <exec> -> <target>". Empty when the rule names
	// none, in which case it applies to any transition.
	Exec string
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

	// LinkRules are the profile's link rules, which name the pairs of link
	// and target a hard link may be created between.
	LinkRules []LinkRule

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

	// IsHat is set for a subprofile declared as a hat ("^name { ... }" or
	// "hat name { ... }") rather than as a child profile. Only a hat may be
	// entered with aa_change_hat(3).
	IsHat bool

	// Mode is the enforcement mode the profile's flags select.
	Mode ProfileMode

	// KillSignal is the signal a 'kill' profile terminates a task with,
	// from "kill.signal=". Zero means SIGKILL.
	KillSignal int32

	// Error is the errno a violation returns, from "error=". Zero means
	// EACCES.
	Error int32

	// Audit is set for a profile declared with the 'audit' flag, which
	// "causes all actions whether allowed or denied to be logged". It also
	// makes a deny rule log, which is otherwise silent.
	Audit bool

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
		// Index only profiles that have not been published before. With
		// --apparmor-policy-source=container the policy is merged and
		// re-installed as each container starts, keeping the already
		// installed *Profile values, and tasks from earlier containers
		// are checking against those concurrently: re-indexing one
		// would race with its readers. A profile's rules never change
		// once installed, so there is nothing to re-index.
		if p.dfa == nil && p.byFirst == nil && p.wild == nil {
			p.index()
		}
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
func CheckChangeProfile(ctx context.Context, from, to string) error {
	return CheckChangeProfileOnExec(ctx, from, to, "")
}

// changeRecord is the record a refused profile transition produces. The name is
// the profile changing, as Linux reports the label in "profile" and the
// requested one in "target".
func changeRecord(ctx context.Context, op Op, to, execPath string) *Record {
	// With no exec, the kernel reports the target profile in both name and
	// target, as the captured change_profile records show.
	r := &Record{Op: op, Name: to, Target: to, ctx: ctx}
	if execPath != "" {
		r.Name = execPath
		r.Requested = Exec
	}
	return r
}

// CheckChangeProfileOnExec is CheckChangeProfile for a transition that
// accompanies an exec of execPath, which is what a rule's exec condition
// governs. An empty execPath means the transition is immediate, so a rule
// carrying an exec condition does not apply to it.
func CheckChangeProfileOnExec(ctx context.Context, from, to, execPath string) error {
	op := OpChangeProfile
	if execPath != "" {
		op = OpChangeOnexec
	}
	rec := changeRecord(ctx, op, to, execPath)
	if !HasProfile(to) {
		// The target is not a profile the policy defines, which Linux
		// reports with info="label not found".
		undefinedProfile(from).audit("DENIED", rec, 0)
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
		undefinedProfile(from).audit("DENIED", rec, 0)
		return linuxerr.EACCES
	}
	allowed := false
	for _, r := range profile.ChangeProfile {
		if !MatchPattern(r.Pattern, to) {
			continue
		}
		if r.Exec != "" && r.Exec != execPath {
			// The rule only governs a transition accompanying an
			// exec of a matching program.
			if execPath == "" || !MatchPattern(r.Exec, execPath) {
				continue
			}
		}
		if r.Deny {
			// A matching deny rule overrides any allow rule,
			// wherever it appears in the profile.
			return profile.denyChange(rec)
		}
		allowed = true
	}
	if !allowed {
		return profile.denyChange(rec)
	}
	return nil
}

// denyChange records a refused profile transition and returns the error to fail
// it with. A complain-mode profile records and permits.
func (p *Profile) denyChange(rec *Record) error {
	if p.Complain || p.Mode == ModeComplain {
		p.audit("ALLOWED", rec, 0)
		return nil
	}
	p.audit("DENIED", rec, 0)
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
func TransitionOnExec(ctx context.Context, from, path string) (string, bool, error) {
	if from == "" {
		// An unconfined task enters the profile named after the
		// executable, if the policy defines one.
		if name, ok := auth.ExecConfinementProfile(path); ok {
			return name, false, nil
		}
		return "", false, nil
	}
	profile := profileFor(from)
	if profile == nil {
		// A task in a profile the policy does not define is denied
		// everything; it must not exec its way out of that.
		return from, false, nil
	}
	r := profile.execRuleFor(path)
	if r == nil {
		// No exec rule matched. The file check has already decided
		// whether the exec is permitted at all, so keep the profile.
		return from, false, nil
	}
	switch r.Mode {
	case ExecInherit:
		return from, false, nil
	case ExecUnconfined:
		// The only way out of a profile, and only because the profile
		// asks for it. The kernel does not log it, so neither does this.
		return "", r.Scrub, nil
	case ExecProfile:
		target := r.Target
		if target == "" {
			target = path
		}
		if !HasProfile(target) {
			// The rule names a profile the policy does not define,
			// so there is nothing to transition into.
			execRecord(ctx, from, "DENIED", path, target)
			return "", false, linuxerr.EACCES
		}
		return target, r.Scrub, nil
	case ExecChild:
		target := from + "//" + r.Target
		if !HasProfile(target) {
			execRecord(ctx, from, "DENIED", path, target)
			return "", false, linuxerr.EACCES
		}
		return target, r.Scrub, nil
	default:
		// No modifier: enter the profile named after the executable if
		// there is one, which is what a path-named profile means, and
		// keep the current profile otherwise.
		if name, ok := auth.ExecConfinementProfile(path); ok {
			return name, false, nil
		}
		return from, false, nil
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

// sink, when set, receives each audit record. Where the records go is the
// operator's choice: by default the container's standard error, since a record
// is a fact about the workload and belongs where the workload's own diagnostics
// go rather than in a per-node log a cluster operator would have to log in to
// every node to read. See --apparmor-audit-target.
var sink atomic.Pointer[func(string)]

// SetAuditSink installs the function each audit record is written to. It is
// called during sandbox startup, before application tasks run. Records are
// dropped while no sink is installed.
func SetAuditSink(f func(record string)) {
	if f == nil {
		sink.Store(nil)
		return
	}
	sink.Store(&f)
}

// SetTestLogSink installs a sink for a test that asserts which records are
// produced. Passing nil removes it.
func SetTestLogSink(f func(record string)) {
	SetAuditSink(f)
}

// emit writes one audit record.
func emit(record string) {
	if f := sink.Load(); f != nil {
		(*f)(record)
	}
}

// execRecord writes the record for an exec transition, which names the program
// in "name" and the profile it moves to in "target".
func execRecord(ctx context.Context, from, kind, path, target string) {
	p := profileFor(from)
	if p == nil {
		p = undefinedProfile(from)
	}
	p.audit(kind, &Record{
		Op:        OpExec,
		Name:      path,
		Target:    target,
		Requested: Exec,
		ctx:       ctx,
	}, Exec)
}

// Op is the operation being mediated, which a record names as AppArmor does.
// The values are Linux's OP_* strings, so that a tool matching on
// operation="open" reads the same field it would from a host kernel.
type Op string

// The operations this implementation mediates. Linux defines more, for the rule
// classes that are not enforced in the sandbox.
const (
	OpOpen Op = "open"
	// OpGetattr is Linux's name for a metadata read. Nothing requests it:
	// reading metadata is not mediated, for the reasons recorded in the
	// filesystems' own comments and in the AppArmor documentation. It is kept
	// so that the operation names here stay the complete set Linux defines
	// for the file class, and so a future change that does mediate it reports
	// the name a host kernel would.
	OpGetattr       Op = "getattr"
	OpSetattr       Op = "setattr"
	OpChmod         Op = "chmod"
	OpChown         Op = "chown"
	OpTrunc         Op = "truncate"
	OpCreate        Op = "create"
	OpMkdir         Op = "mkdir"
	OpRmdir         Op = "rmdir"
	OpMknod         Op = "mknod"
	OpSymlink       Op = "symlink"
	OpUnlink        Op = "unlink"
	OpLink          Op = "link"
	OpRenameSrc     Op = "rename_src"
	OpRenameDest    Op = "rename_dest"
	OpFlock         Op = "file_lock"
	OpFmmap         Op = "file_mmap"
	OpFperm         Op = "file_perm"
	OpExec          Op = "exec"
	OpChangeHat     Op = "change_hat"
	OpChangeProfile Op = "change_profile"
	OpChangeOnexec  Op = "change_onexec"
)

// SetattrOp returns the operation a metadata change is, given the fields it
// changes. Linux hooks chmod, chown and truncate separately from the rest, so a
// record names the one the caller asked for.
func SetattrOp(mask uint32) Op {
	switch {
	case mask&linux.STATX_MODE != 0:
		return OpChmod
	case mask&(linux.STATX_UID|linux.STATX_GID) != 0:
		return OpChown
	case mask&linux.STATX_SIZE != 0:
		return OpTrunc
	default:
		return OpSetattr
	}
}

// Record identifies one mediated access, and holds everything an audit record
// says about it beyond the profile's decision.
type Record struct {
	// Op is the operation being mediated.
	Op Op

	// Name is the path being accessed, the "name" field of a record.
	Name string

	// Target is the second name a record carries, which is the file a link
	// points at or the profile an exec or change_profile moves to. It is
	// empty for an operation with only one.
	Target string

	// Requested is the permissions the operation asked for.
	Requested Perm

	// FsUID is the UID the access is made with, which "owner" rules and the
	// "fsuid" field refer to.
	FsUID auth.KUID

	// OwnerUID is the UID of the file, the "ouid" field.
	OwnerUID auth.KUID

	// ctx is the context the mediated operation runs in, used to resolve the
	// "pid" and "comm" fields. It is only consulted while formatting a
	// record, so a check that reports nothing does not pay for it. A nil ctx
	// omits those fields.
	ctx context.Context

	// revalidate, when set, returns a freshly fetched owner uid for the file.
	// The engine calls it at most once, and only when an owner-qualified rule
	// is the sole reason the access would be denied, to avoid denying against
	// a stale owner on a filesystem whose cached metadata can lag the remote
	// (a shared gofer mount, where another client's in-progress create is
	// briefly root-owned). This mirrors a real kernel refreshing attributes on
	// open. A nil revalidate, or one that returns an owner still not matching
	// the accessor, leaves the denial in place.
	revalidate func() auth.KUID
}

// reownedByFresh revalidates the file's owner and reports whether the accessor
// owns it after the refresh, recording the fresh owner for the audit either
// way. It returns false when no revalidation is available.
func (r *Record) reownedByFresh(creds *auth.Credentials) bool {
	if r.revalidate == nil {
		return false
	}
	fresh := r.revalidate()
	r.OwnerUID = fresh
	return fresh == creds.EffectiveKUID
}

// audit writes one AppArmor audit record.
//
// The fields, their order and which of them are optional are taken from the
// three functions Linux builds a file record out of, in the order they run:
//
//   - security/apparmor/audit.c:audit_pre(), which writes apparmor=, then
//     operation=, then class=, then info= followed by error= (error only ever
//     appears with info, which a plain denial does not set), then namespace=
//     and profile=, then name=.
//   - security/lsm_audit.c:dump_common_audit_data(), which writes
//     pid=%d comm=%s next, before any class-specific field.
//   - security/apparmor/file.c:file_audit_cb(), which writes requested_mask=,
//     denied_mask=, fsuid=, ouid= and last of all target=.
//
// Anything else, in any other order, is not what the tools that already parse
// these records expect: libapparmor's aa_parse_record, aa-logprof and the rest.
func (p *Profile) audit(kind string, r *Record, denied Perm) {
	if sink.Load() == nil {
		// Nothing will receive the record, so do not pay to format it:
		// formatting is an order of magnitude more expensive than the
		// check that produced it.
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "apparmor=%q operation=%q class=\"file\"", kind, string(r.Op))
	auditString(&b, "profile", p.Name)
	auditString(&b, "name", r.Name)
	// pid is the thread group ID, as task_tgid_nr(current) gives, and comm
	// is the thread's own name.
	if pid, comm, ok := taskInfoFor(r.ctx); ok {
		fmt.Fprintf(&b, " pid=%d", pid)
		auditString(&b, "comm", comm)
	}
	// file_audit_cb() prints the masks and uids only when the request has
	// file-permission bits: a change_profile record carries none of them.
	if r.Requested != 0 {
		fmt.Fprintf(&b, " requested_mask=%q", permString(r.Requested))
	}
	if denied != 0 {
		fmt.Fprintf(&b, " denied_mask=%q", permString(denied))
	}
	if r.Requested != 0 {
		fmt.Fprintf(&b, " fsuid=%d ouid=%d", r.FsUID, r.OwnerUID)
	}
	if r.Target != "" {
		auditString(&b, "target", r.Target)
	}
	emit(b.String())
}

// auditString writes one field whose value the kernel treats as untrusted,
// the way audit_log_untrustedstring() does: quoted when every byte is
// printable ASCII other than '"', and as bare uppercase hex otherwise. Paths
// with spaces appear hex-encoded in real logs, and the tools that parse these
// records (aa_parse_record and everything built on it) expect exactly that.
func auditString(b *strings.Builder, field, s string) {
	b.WriteByte(' ')
	b.WriteString(field)
	b.WriteByte('=')
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c < 0x21 || c > 0x7e {
			clean = false
			break
		}
	}
	if clean {
		b.WriteByte('"')
		b.WriteString(s)
		b.WriteByte('"')
		return
	}
	const hexdigits = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		b.WriteByte(hexdigits[s[i]>>4])
		b.WriteByte(hexdigits[s[i]&0xf])
	}
}

// taskInfoFn resolves the "pid" and "comm" fields of a record from the context
// the mediated operation runs in.
//
// It is a hook because those fields belong to a task, and this package cannot
// import the kernel package, which imports this one. The kernel installs it.
var taskInfoFn atomic.Pointer[func(context.Context) (int32, string, bool)]

// SetTaskInfoFunc installs the resolver for the "pid" and "comm" fields.
func SetTaskInfoFunc(f func(context.Context) (int32, string, bool)) {
	if f == nil {
		taskInfoFn.Store(nil)
		return
	}
	taskInfoFn.Store(&f)
}

func taskInfoFor(ctx context.Context) (int32, string, bool) {
	if ctx == nil {
		return 0, "", false
	}
	f := taskInfoFn.Load()
	if f == nil {
		return 0, "", false
	}
	return (*f)(ctx)
}

// StackSeparator joins the profiles of a stacked label, as AppArmor names one:
// "profileA//&profileB". Every profile in the stack must permit an access, so
// the label's permissions are the intersection of theirs.
const StackSeparator = "//&"

// SplitLabel returns the profiles of a label, which is one profile unless
// profiles have been stacked onto it.
func SplitLabel(label string) []string {
	if label == "" {
		return nil
	}
	return strings.Split(label, StackSeparator)
}

// StackLabel returns the label that results from stacking profile onto label.
// Stacking a profile already in the label leaves it unchanged.
func StackLabel(label, profile string) string {
	if label == "" {
		return profile
	}
	for _, p := range SplitLabel(label) {
		if p == profile {
			return label
		}
	}
	return label + StackSeparator + profile
}

// HatName returns the name of the hat hat within profile, which is how
// AppArmor names a subprofile: "<profile>//^<hat>".
func HatName(profile, hat string) string {
	return profile + "//^" + hat
}

// CheckChangeHat reports whether a task in profile from may enter the hat named
// hat, as aa_change_hat(3) does.
//
// Per aa_change_hat(2): ENOENT if "the specified subprofile does not exist in
// this profile but other hats are defined", and EPERM if the name is not a
// valid hat.
func CheckChangeHat(from, hat string) (string, error) {
	target := HatName(from, hat)
	rec := &Record{Op: OpChangeHat, Target: target}
	p := profileFor(target)
	if p == nil {
		if profileHasHats(from) {
			undefinedProfile(from).audit("DENIED", rec, 0)
			return "", linuxerr.ENOENT
		}
		undefinedProfile(from).audit("DENIED", rec, 0)
		return "", linuxerr.EPERM
	}
	if !p.IsHat {
		// A child profile is not a hat, so it is not enterable this way.
		undefinedProfile(from).audit("DENIED", rec, 0)
		return "", linuxerr.EPERM
	}
	return target, nil
}

// profileHasHats reports whether any hat is defined for a profile.
func profileHasHats(profile string) bool {
	policy.mu.RLock()
	defer policy.mu.RUnlock()
	prefix := profile + "//^"
	for name, p := range policy.profiles {
		if p.IsHat && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// HasPolicy reports whether any policy was installed, which is what decides
// whether anything is mediated in the sandbox at all.
func HasPolicy() bool {
	policy.mu.RLock()
	defer policy.mu.RUnlock()
	return len(policy.profiles) != 0
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
	if ats.MayWrite() && !isDir {
		// A directory's write permission is not mediated by AppArmor.
		// Creating, removing or renaming an entry is mediated by a rule
		// for that entry's own path, which the filesystem checks
		// separately; the write permission the kernel requires on the
		// directory holding it is a DAC rule with no AppArmor
		// equivalent. Requiring it here denied writes a profile allows,
		// such as creating a session file under a directory a profile
		// grants only read.
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

// Mediates reports whether an access with these types is mediated at all.
// Callers that must build a path before calling Check() use this to skip the
// path construction when the answer is already no, which on a directory walk
// is every traversal component.
func Mediates(ats vfs.AccessTypes, isDir bool) bool {
	return permsFor(ats, isDir) != 0
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
			// apparmor_parser maps 'w' to AA_MAY_WRITE|AA_MAY_APPEND,
			// which is why it rejects a rule carrying both: 'w'
			// already grants what 'a' does. An 'a' rule is the
			// narrower one, granting only an O_APPEND open.
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
	return matchFrom(pattern, path, false /* afterSlash */)
}

// matchFrom is matchHere, tracking whether the pattern byte before this point
// was a '/'. A wildcard that is a whole path component is compiled differently
// by apparmor_parser than one that is part of one, and that is the only thing
// the caller needs to know to tell them apart.
func matchFrom(pattern, path string, afterSlash bool) bool {
	for len(pattern) != 0 {
		switch pattern[0] {
		case '\x00':
			// A marker inserted by the policy parser: the wildcard it
			// precedes came from inside a brace alternation and is
			// bare, with no whole-component minimum. See
			// markBraceWildcards. Consume it and clear afterSlash so
			// the star below is not minimized.
			pattern, afterSlash = pattern[1:], false
			continue
		case '*':
			// Collapse a run of consecutive wildcards into one match.
			// "a**b" backtracks over every split, and two adjacent
			// runs backtrack multiplicatively, which is the O(len^k)
			// blowup a profile hits on the rule-walk fallback. A run
			// crosses '/' if any of its stars is a "**", and it keeps
			// the minimum of its first star; collapsing preserves the
			// meaning apparmor_parser gives, which treats "***" as one
			// wildcard region.
			doubled := false
			rest := pattern
			for len(rest) != 0 {
				if rest[0] == '*' {
					if len(rest) > 1 && rest[1] == '*' {
						doubled = true
						rest = rest[2:]
					} else {
						rest = rest[1:]
					}
					continue
				}
				if rest[0] == '\x00' {
					// A brace-origin marker between stars in a
					// run just marks the next star as bare; the
					// run's own minimum already accounts for that.
					rest = rest[1:]
					continue
				}
				break
			}
			// A whole-component wildcard requires at least one
			// character, so that "/dir/*" does not match "/dir/" and
			// "/dir/**" does not match "/dir/". apparmor_parser
			// compiles those to "[^/\x00][^/\x00]*" and
			// "[^/\x00][^\x00]*"; elsewhere, as in "*.php", the
			// star may match nothing.
			min := 0
			if afterSlash && (len(rest) == 0 || rest[0] == '/') {
				if len(path) == 0 || path[0] == '/' {
					return false
				}
				min = 1
			}
			if doubled {
				// '**' matches across '/'. Try every suffix,
				// shortest first.
				for i := min; ; i++ {
					if matchFrom(rest, path[i:], false) {
						return true
					}
					if i >= len(path) {
						return false
					}
				}
			}
			// '*' matches within a path component.
			for i := min; ; i++ {
				if matchFrom(rest, path[i:], false) {
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
			pattern, path, afterSlash = pattern[1:], path[1:], false
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
			pattern, path, afterSlash = pattern[end+1:], path[1:], false
		default:
			if len(path) == 0 || path[0] != pattern[0] {
				return false
			}
			afterSlash = pattern[0] == '/'
			pattern, path = pattern[1:], path[1:]
		}
	}
	return len(path) == 0
}

// matchClass reports whether c is in the character class body (the text
// between '[' and ']'), supporting negation and ranges.
// A character class matches whatever its set says, including '/'. Only '?' and
// '*' are restricted to a single path component: apparmor_parser compiles '?' to
// "[^/\x00]" but compiles "[^b]" to "[^b]" and "[abc]" to "[abc]", with no
// separator exclusion. Excluding '/' here made a negated class match fewer paths
// than a host kernel does, which matters most in a deny rule: the profile shape
// "deny @{PROC}/{[^1-9],[^1-9][^0-9][^0-9][^0-9]*}/** w" relies on a negated
// class spanning components, and refusing that let writes through that a host
// kernel refuses.
func matchClass(class string, c byte) bool {
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
func Check(ctx context.Context, creds *auth.Credentials, op Op, path string, ats vfs.AccessTypes, mode linux.FileMode, kuid auth.KUID) error {
	want := permsFor(ats, mode.FileType() == linux.ModeDirectory)
	if want == 0 {
		return nil
	}
	return CheckPerms(ctx, creds, op, path, want, mode, kuid)
}

// CheckRevalidating is Check with the owner revalidation of
// CheckOpenRevalidating.
func CheckRevalidating(ctx context.Context, creds *auth.Credentials, op Op, path string, ats vfs.AccessTypes, mode linux.FileMode, kuid auth.KUID, revalidate func() auth.KUID) error {
	want := permsFor(ats, mode.FileType() == linux.ModeDirectory)
	if want == 0 {
		return nil
	}
	return CheckPermsRevalidating(ctx, creds, op, path, want, mode, kuid, revalidate)
}

// undefinedProfile returns a stand-in for a profile the policy does not define,
// so that the denial it causes is still reported as a record naming it.
func undefinedProfile(name string) *Profile {
	return &Profile{Name: name}
}

// deniedPerms returns the permissions the profile's deny rules refuse for path,
// which is all that a default_allow profile consults, and which of them come
// from a rule that audits: a deny rule is silent otherwise, whichever mode the
// profile is in.
func (p *Profile) deniedPerms(path string) (denied, audited Perm) {
	if d := p.dfa; d != nil {
		if a, ok := d.match(path); ok {
			return a.deny, a.audit
		}
	}
	for _, group := range [2][]int32{p.byFirst[firstComponent(path)], p.wild} {
		for _, i := range group {
			r := &p.Rules[i]
			if !r.Deny || !MatchPattern(r.Pattern, path) {
				continue
			}
			denied |= r.Perms
			if r.Audit {
				audited |= r.Perms
			}
		}
	}
	return denied, audited
}

// GrantedPerms returns the permissions the profile grants for path, which is
// what a link's permissions must be a subset of.
func GrantedPerms(creds *auth.Credentials, path string, mode linux.FileMode, kuid auth.KUID) Perm {
	names := SplitLabel(creds.ConfinementProfile)
	if len(names) > 1 {
		// A stacked label grants the intersection.
		all := Perm(0)
		for i, name := range names {
			sub := auth.Credentials{ConfinementProfile: name, EffectiveKUID: creds.EffectiveKUID}
			p := GrantedPerms(&sub, path, mode, kuid)
			if i == 0 {
				all = p
				continue
			}
			all &= p
		}
		return all
	}
	profile := profileFor(creds.ConfinementProfile)
	if profile == nil {
		return 0
	}
	owned := kuid == creds.EffectiveKUID
	var granted, denied Perm
	for _, group := range [2][]int32{profile.byFirst[firstComponent(path)], profile.wild} {
		for _, i := range group {
			r := &profile.Rules[i]
			if !MatchPattern(r.Pattern, path) {
				continue
			}
			if r.Deny {
				denied |= r.Perms
				continue
			}
			if r.Owner && !owned {
				continue
			}
			granted |= r.Perms
		}
	}
	return granted & ^denied
}

// LinkRule is one link rule, which apparmor.d(5) describes as "permission to
// form a hard link as a link target pair": the link must match Pattern and the
// file it links to must match Target.
//
// The 'l' permission of a file rule is one of these too, with an implied
// subset condition and a target of "/**": the man page gives "/foo l," and
// "link subset /foo -> /**," as the same rule. Only the explicit "link" form
// can omit the subset condition and so permit a link with more permissions
// than the file it points at.
type LinkRule struct {
	// Pattern is the path of the new link.
	Pattern string

	// Target is the path of the file being linked to.
	Target string

	// Subset requires the link's permissions to be a subset of the
	// target's, from the 'subset' condition.
	Subset bool

	// Owner restricts the rule to a task that owns the file, from the
	// 'owner' conditional.
	Owner bool

	// Deny refuses the pair.
	Deny bool

	// Audit logs the rule's decision.
	Audit bool
}

// CheckLink evaluates creating a link at link to the file at target. Linux
// requires 'l' on the link's own name, then a link rule matching the pair, and
// then, if that rule carries the subset condition, that "the permissions to
// access the link file must be a subset of the profiles permissions to access
// the target file".
func CheckLink(ctx context.Context, creds *auth.Credentials, link, target string, mode linux.FileMode, kuid auth.KUID) error {
	rec := &Record{
		Op:        OpLink,
		Name:      link,
		Target:    target,
		Requested: Link,
		FsUID:     creds.EffectiveKUID,
		OwnerUID:  kuid,
		ctx:       ctx,
	}
	if err := checkRecord(creds, rec, mode, kuid); err != nil {
		return err
	}
	label := creds.ConfinementProfile
	for label != "" {
		name, rest, _ := strings.Cut(label, StackSeparator)
		if err := checkProfileLink(creds, name, rec, mode, kuid); err != nil {
			return err
		}
		label = rest
	}
	return nil
}

// checkProfileLink evaluates one profile's link rules.
func checkProfileLink(creds *auth.Credentials, name string, rec *Record, mode linux.FileMode, kuid auth.KUID) error {
	link, target := rec.Name, rec.Target
	profile := profileFor(name)
	if profile == nil {
		undefinedProfile(name).audit("DENIED", rec, Link)
		return linuxerr.EACCES
	}
	owned := kuid == creds.EffectiveKUID
	subset := false
	matched := false
	for i := range profile.LinkRules {
		r := &profile.LinkRules[i]
		if !MatchPattern(r.Pattern, link) || !MatchPattern(r.Target, target) {
			continue
		}
		if r.Deny {
			return profile.denyAudited(rec, Link, r.Audit || profile.Audit)
		}
		if r.Owner && !owned {
			continue
		}
		matched = true
		// A rule that does not require the subset settles it: the pair
		// is permitted outright.
		if !r.Subset {
			return nil
		}
		subset = true
	}
	if !matched {
		// 'l' on the link is not enough on its own: no rule names this
		// pair. A profile that grants 'l' always has a rule for it,
		// with a target of "/**".
		return profile.deny(rec, Link)
	}
	if !subset {
		return nil
	}
	// The subset is over the permissions the link would confer on the file;
	// 'l' is the permission to create the link and is not part of it, since
	// requiring it on the target would make every link impossible.
	linkPerms := GrantedPerms(creds, link, mode, kuid) & ^Link
	targetPerms := GrantedPerms(creds, target, mode, kuid)
	if extra := linkPerms & ^targetPerms; extra != 0 {
		// The subset condition failed: report the permissions the link
		// would have had beyond the target's.
		sub := *rec
		sub.Requested = extra
		return profile.deny(&sub, extra)
	}
	return nil
}

// PermsForOpen returns the permissions an open requests, as Linux's
// aa_map_file_to_perms() does:
//
//	if ((flags & O_APPEND) && (perms & MAY_WRITE))
//		perms = (perms & ~MAY_WRITE) | MAY_APPEND;
//	if (flags & O_TRUNC)
//		perms |= MAY_WRITE;
//
// An O_APPEND open therefore asks for 'a' in place of 'w', which is what makes
// an append-only rule append-only, and O_TRUNC asks for 'w' again, because
// truncating a file is not appending to it.
func PermsForOpen(ats vfs.AccessTypes, flags uint32, isDir bool) Perm {
	p := permsFor(ats, isDir)
	if flags&linux.O_APPEND != 0 && p&Write != 0 {
		p = (p & ^Write) | Append
	}
	if flags&linux.O_TRUNC != 0 {
		p |= Write
	}
	return p
}

// CheckOpen evaluates an open of path with the given flags. Callers that
// mediate an open use this rather than Check(), so that O_APPEND and O_TRUNC
// select the permissions AppArmor asks for.
func CheckOpen(ctx context.Context, creds *auth.Credentials, path string, ats vfs.AccessTypes, flags uint32, mode linux.FileMode, kuid auth.KUID) error {
	want := PermsForOpen(ats, flags, mode.FileType() == linux.ModeDirectory)
	return CheckPerms(ctx, creds, OpOpen, path, want, mode, kuid)
}

// CheckOpenRevalidating is CheckOpen for a filesystem whose cached owner can
// lag the remote, such as a shared gofer mount. revalidate returns a freshly
// fetched owner uid; the engine calls it only when an owner rule is the sole
// reason the open would be denied, so the common paths pay nothing for it. See
// Record.revalidate.
func CheckOpenRevalidating(ctx context.Context, creds *auth.Credentials, path string, ats vfs.AccessTypes, flags uint32, mode linux.FileMode, kuid auth.KUID, revalidate func() auth.KUID) error {
	want := PermsForOpen(ats, flags, mode.FileType() == linux.ModeDirectory)
	return checkRecord(creds, &Record{
		Op:         OpOpen,
		Name:       path,
		Requested:  want,
		FsUID:      creds.EffectiveKUID,
		OwnerUID:   kuid,
		ctx:        ctx,
		revalidate: revalidate,
	}, mode, kuid)
}

// CheckPermsRevalidating is CheckPerms with the owner revalidation of
// CheckOpenRevalidating.
func CheckPermsRevalidating(ctx context.Context, creds *auth.Credentials, op Op, path string, want Perm, mode linux.FileMode, kuid auth.KUID, revalidate func() auth.KUID) error {
	return checkRecord(creds, &Record{
		Op:         op,
		Name:       path,
		Requested:  want,
		FsUID:      creds.EffectiveKUID,
		OwnerUID:   kuid,
		ctx:        ctx,
		revalidate: revalidate,
	}, mode, kuid)
}

// CheckPerms evaluates the rules of the profile the accessing task has entered
// against path, for the permissions in want. It returns nil if all of them are
// granted. Callers that mediate an access which does not correspond to a
// vfs.AccessType, such as an executable mapping, use this directly.
func CheckPerms(ctx context.Context, creds *auth.Credentials, op Op, path string, want Perm, mode linux.FileMode, kuid auth.KUID) error {
	return checkRecord(creds, &Record{
		Op:        op,
		Name:      path,
		Requested: want,
		FsUID:     creds.EffectiveKUID,
		OwnerUID:  kuid,
		ctx:       ctx,
	}, mode, kuid)
}

// checkRecord evaluates an access whose record the caller has already built,
// which is how an operation with a target keeps it in the record it reports.
func checkRecord(creds *auth.Credentials, rec *Record, mode linux.FileMode, kuid auth.KUID) error {
	// Every profile of a stacked label must permit the access. The label is
	// walked with Cut rather than split into a slice: this is on every
	// mediated access, and an unstacked label, the common case, must not
	// allocate.
	label := creds.ConfinementProfile
	for label != "" {
		name, rest, _ := strings.Cut(label, StackSeparator)
		if err := checkProfilePerms(creds, name, rec, mode, kuid); err != nil {
			return err
		}
		label = rest
	}
	return nil
}

// checkProfilePerms evaluates one profile of a label.
func checkProfilePerms(creds *auth.Credentials, name string, rec *Record, mode linux.FileMode, kuid auth.KUID) error {
	path, want := rec.Name, rec.Requested
	profile := profileFor(name)
	if profile == nil {
		// The task entered a profile the policy does not define. Deny,
		// rather than silently leaving it unconfined.
		undefinedProfile(name).audit("DENIED", rec, want)
		return linuxerr.EACCES
	}
	switch profile.Mode {
	case ModeUnconfined:
		// "Allows unrestricted behavior": nothing is mediated in the
		// sandbox. Whatever profile the OCI spec named is still applied
		// to the sentry and gofer by the host.
		return nil
	case ModeDefaultAllow:
		// "Inverts logic to allow-by-default": only a deny rule refuses.
		denied, audited := profile.deniedPerms(path)
		if denied&want != 0 {
			return profile.denyAudited(rec, denied&want,
				audited&want != 0 || profile.Audit)
		}
		return nil
	}
	owned := kuid == creds.EffectiveKUID

	if d := profile.dfa; d != nil {
		a, ok := d.match(path)
		if !ok {
			// The automaton could not answer; fall through to
			// matching the rules one at a time.
			return profile.checkLinear(creds, rec, owned)
		}
		if a.deny&want != 0 {
			// A deny rule matched. The automaton records which
			// permissions the audited rules covered, but not which
			// rule they came from.
			return profile.denyAudited(rec, a.deny&want,
				a.audit&want != 0 || profile.Audit)
		}
		granted := a.allowAny
		if owned {
			granted |= a.allowOwner
		}
		if missing := want & ^granted; missing != 0 {
			// If the only thing between grant and deny is an owner rule
			// the file's owner failed to match, the owner may be stale;
			// revalidate it once before denying. See Record.revalidate.
			if !owned && missing&a.allowOwner != 0 && rec.reownedByFresh(creds) {
				granted |= a.allowOwner
				if want&^granted == 0 {
					profile.auditAllowed(rec, a.audit&want)
					return nil
				}
			}
			return profile.deny(rec, want&^granted)
		}
		profile.auditAllowed(rec, a.audit&want)
		return nil
	}

	return profile.checkLinear(creds, rec, owned)
}

// checkLinear evaluates path by matching the profile's rules, grouped by the
// first component of their pattern. It is the path taken when a profile has no
// compiled automaton.
func (profile *Profile) checkLinear(creds *auth.Credentials, rec *Record, owned bool) error {
	path, want := rec.Name, rec.Requested
	var granted, audited Perm
	// ownerGranted and ownerAudited accumulate what owner rules would grant if
	// the accessor owned the file, so that a denial resting solely on the
	// owner condition can be retried against a revalidated owner.
	var ownerGranted, ownerAudited Perm
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
				return profile.denyByRule(rec, r.Perms&want, r)
			}
			if r.Owner && !owned {
				ownerGranted |= r.Perms
				if r.Audit {
					ownerAudited |= r.Perms
				}
				continue
			}
			granted |= r.Perms
			if r.Audit {
				audited |= r.Perms
			}
		}
	}

	if missing := want & ^granted; missing != 0 {
		// The owner may be stale; revalidate it before denying on the owner
		// condition alone. See Record.revalidate.
		if !owned && missing&ownerGranted != 0 && rec.reownedByFresh(creds) {
			granted |= ownerGranted
			audited |= ownerAudited
			if want&^granted == 0 {
				profile.auditAllowed(rec, audited&want)
				return nil
			}
		}
		return profile.deny(rec, want&^granted)
	}
	profile.auditAllowed(rec, audited&want)
	return nil
}

// auditAllowed records an access the profile permitted, which apparmor.d(5) does
// for a rule carrying the 'audit' qualifier ("will force audit messages to be
// generated") and for every access of a profile declared with the 'audit' flag
// ("causes all actions whether allowed or denied to be logged"). An allowed
// access is otherwise silent.
func (p *Profile) auditAllowed(r *Record, audited Perm) {
	if audited == 0 && !p.Audit {
		return
	}
	rec := *r
	if !p.Audit {
		// Only the audited permissions are reported, as Linux masks the
		// request down to perms->audit.
		rec.Requested = audited
	}
	p.audit("AUDIT", &rec, 0)
}

// denyByRule refuses an access that an explicit deny rule matched. Such a
// denial is not recorded unless the rule also audits.
func (p *Profile) denyByRule(r *Record, denied Perm, rule *Rule) error {
	return p.denyAudited(r, denied, rule.Audit || p.Audit)
}

// denyAudited refuses an access that an explicit deny rule matched, recording it
// only if the denial is audited: apparmor.d(5) gives deny as denying "without
// logging", and a silenced denial does not kill either, because Linux decides
// to kill inside the audit path.
func (p *Profile) denyAudited(r *Record, denied Perm, audit bool) error {
	if p.Complain || p.Mode == ModeComplain {
		// A complain-mode profile permits the access, which Linux
		// records as ALLOWED rather than DENIED.
		if audit {
			p.audit("ALLOWED", r, denied)
		}
		return nil
	}
	err := p.violation(audit)
	if audit {
		kind := "DENIED"
		if _, kill := AsKillError(err); kill {
			kind = "KILLED"
		}
		p.audit(kind, r, denied)
	}
	return err
}

// KillError is returned for a violation of a profile in kill mode, which is
// "enforce mode plus signal termination on violation". The syscall layer
// terminates the task with Signal and reports Err to the caller.
type KillError struct {
	// Signal terminates the task. Zero means SIGKILL.
	Signal int32

	// Err is the error the violation would otherwise have returned.
	Err error
}

// Error implements error.Error.
func (e *KillError) Error() string {
	return e.Err.Error()
}

// Unwrap allows the underlying error to be matched, so that a caller which
// only reports errors behaves as it would for any other denial.
func (e *KillError) Unwrap() error {
	return e.Err
}

// AsKillError reports whether err is, or wraps, a violation of a profile in
// kill mode, in which case the task must be terminated with its signal.
func AsKillError(err error) (*KillError, bool) {
	var kill *KillError
	if errors.As(err, &kill) {
		return kill, true
	}
	return nil, false
}

// violation returns the error a denial fails with, which "error=" may override.
// A profile in kill mode wraps it so the syscall layer terminates the task, but
// only for a denial that is audited: Linux couples the two, because it decides
// to kill inside the audit path (aa_audit()), which a denial silenced by a deny
// rule never reaches (aa_audit_file() returns before calling it). A silent deny
// rule therefore denies without killing, and audited is what the caller has
// just decided to report.
func (p *Profile) violation(audited bool) error {
	err := error(linuxerr.EACCES)
	if p.Error != 0 {
		err = linuxerr.ErrorFromUnix(unix.Errno(p.Error))
	}
	if p.Mode == ModeKill && audited {
		return &KillError{Signal: p.KillSignal, Err: err}
	}
	return err
}

// deny records an access no rule permitted and returns the error to fail it
// with. Such a denial is always recorded, which is what makes it kill a task
// under a profile in kill mode. A complain-mode profile records and permits, as
// it does on a host kernel.
func (p *Profile) deny(r *Record, denied Perm) error {
	return p.denyAudited(r, denied, true)
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
