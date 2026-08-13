# AppArmor with gVisor

[TOC]

Under gVisor an application's system calls are serviced by the Sentry and never
reach the host kernel. A host AppArmor profile therefore cannot mediate what the
application does: there is no host system call to intercept. This has two
consequences, and gVisor addresses them separately.

*   The Sentry and Gofer *do* make host accesses on the application's behalf, so
    a host profile can confine those. That is `--host-apparmor`.

*   A profile's file rules describe the application's own view of the
    filesystem, so they can only be enforced inside the sandbox. That is
    `--apparmor-policy-source`.

## Confining the Sentry and Gofer (`--host-apparmor`)

With `--host-apparmor`, runsc applies the profile named in the OCI spec (which
Kubernetes populates from `securityContext.appArmorProfile`) to the Sentry and
Gofer processes.

```toml
[runsc_config]
  host-apparmor = "true"
```

Profiles are entered using AppArmor's `change_onexec` mechanism at runsc's
existing re-exec, which this flag forces. An in-place transition is not usable:
an AppArmor label lives in a task's credentials and the kernel only permits a
task to write its own procattr file, so a multithreaded process cannot
transition all of its threads.

Writing profiles for this mode differs from writing them for runc in three ways.

1.  **Paths are the confining process's, not the container's.** AppArmor
    resolves paths relative to the mount namespace root, not the process's
    chroot. The container's root filesystem is mounted at `/root` in the Gofer's
    mount namespace, so a container path `/etc/foo` is mediated as
    `/root/etc/foo`. A single profile can serve both runtimes by using a
    variable with both roots:

    ```
    @{PREFIX}=/ /root/
    ...
      @{PREFIX}etc/** r,
    ```

    AppArmor expands a multi-valued variable into one rule per value, so the
    rule permits `/etc/**` under runc and `/root/etc/**` under gVisor.

2.  **The profile must permit what the Sentry and Gofer need.** This is a
    superset of what the application needs. In particular, unix socket
    permissions are the union of a profile's `unix` rules, and anonymous sockets
    are mediated by them, so a profile that mentions `unix` at all must permit
    the Sentry/Gofer socketpair or the sandbox cannot start:

    ```
      unix (create, getattr, setattr, getopt, setopt, shutdown),
      unix (connect, send, receive) peer=(label=unconfined),
      unix (connect, send, receive) peer=(label=<this profile>),
      signal (receive) peer=unconfined,
    ```

3.  **`attach_disconnected` is generally required**, because the Gofer runs in a
    private mount namespace and AppArmor considers its paths disconnected from
    the namespace root.

Load new profiles in complain mode first and harvest what the sandbox actually
needs (`dmesg | grep -i apparmor | grep DENIED`) before switching to enforce.

## Confinement inside the sandbox (`--apparmor-policy-source`)

Some profile rules describe accesses that never reach the host at all. The
clearest example is `owner`:

```
  owner @{WWW_DIRS}/?/?/*/** rwkmlix,
```

For a runc container this restricts each process to files it owns, even when the
file's mode would permit others to read it. Under gVisor the access is serviced
by the Sentry, so the host kernel never sees it and the rule has no effect. The
Sentry enforces such rules itself, deriving them from the profiles so that the
profiles remain the single source of truth.

```toml
[runsc_config]
  apparmor-policy-source = "host"       # none (default), host, or container
  apparmor-policy-dir = "/etc/apparmor.d"
```

From the profiles, runsc derives:

*   the file rules of each profile, with their AppArmor globs (`*`, `**`, `?`,
    `[...]`, `{a,b}`) and their permission characters, after expanding variables
    such as `@{WWW_DIRS}`. A rule written with a variable that has several
    values yields one rule per value, as `apparmor_parser` does;

*   whether each rule is an `owner` rule, which additionally requires that the
    accessing task own the file, and whether it is a `deny` rule, which
    overrides any allow rule that also matches; and

*   the profiles each profile may change to, from its `change_profile` rules,
    including `deny` rules, which override any allow rule that also matches. A
    task may only enter a profile its own profile permits, so a confined task
    cannot reach a weaker one; an unconfined task may enter any profile; and no
    task may become unconfined; and

*   the executables whose exec attaches a profile, taken from profile names that
    are paths (`profile /bin/cagebash { ... }`), matching AppArmor's behavior.

`#include` directives are followed, resolved against the policy directory, so
that the abstractions a profile is built from (`abstractions/base` and the rest)
contribute their rules. An include naming a directory pulls in every file in it.
A missing include is an error rather than a silently weaker profile.

A profile is an allow list: an access with no matching allow rule is denied,
just as on a host kernel.

Every line of policy that produces no in-sandbox rule is recorded and logged at
startup, by kind at `Info` and line by line at `Debug`, so a profile is never
quietly reduced to something weaker than it appears. Check that list against a
profile before trusting it; enforce what is missing with `--host-apparmor` on
the Sentry and Gofer.

A profile's `flags=(...)` select what a denial does:

| flag | effect |
| --- | --- |
| `enforce` | deny the access. The default. |
| `complain` | permit the access and log what would have been denied, as on a host kernel, so a profile can be developed against a real workload before it is switched to enforcing |
| `kill` | deny the access *and* signal the offending task, which is how a profile makes a violation fatal instead of something an application can retry around. As on a host kernel, this follows auditing: a denial silenced by a plain `deny` rule denies without killing, while one with no matching rule, one from an `audit deny` rule, or any denial in a profile also flagged `audit` kills |
| `kill.signal=<sig>` | the signal `kill` sends, `SIGKILL` if unset. It is sent to the task that made the access, as Linux's AppArmor does, so the syscall still returns the denial and the signal is delivered before the task resumes |
| `default_allow` | permit anything no `deny` rule refuses, inverting the profile |
| `unconfined` | mediate nothing inside the sandbox |
| `error=<errno>` | the errno a denial returns instead of `EACCES` |
| `audit` | log every access the profile mediates, not only denials |

`complain` wins over `kill` where a profile carries both, so raising a profile's
flags never turns a development run fatal. These flags select one mode between
them, so a profile naming several takes the last.

### Audit records

A mediated access is reported in the format Linux's AppArmor produces. Records
go to the container's standard error by default, which is where a cluster's log
collection already reads a workload's diagnostics from and does not require
logging in to the node:

```toml
[runsc_config]
  apparmor-audit-target = "stderr"   # stderr (default), stdout, gvisor, or none
```

`stdout` writes them to the container's other stream, `gvisor` to the sentry log
(`gvisor.log`) for an operator who collects that instead, and `none` discards
them, which leaves enforcement on and reporting off.

```
apparmor="DENIED" operation="open" class="file" profile="docker-hosted" name="/etc/shadow" requested_mask="r" denied_mask="r" fsuid=33 ouid=0 error=-13
```

The fields and their order are `aa_audit_msg()`'s and `file_audit_cb()`'s, so
the tools that already parse AppArmor records read these: libapparmor's
`aa_parse_record`, and `aa-logprof` and `aa-genprof` on top of it.

*   `apparmor=` is `DENIED` for a refused access, `KILLED` when a `kill` profile
    also signals the task, `ALLOWED` for one a `complain` profile permitted, and
    `AUDIT` for one an `audit` rule or an `audit` profile permitted.
*   `operation=` is Linux's own name for the operation: `open`, `getattr`,
    `setattr`, `chmod`, `chown`, `truncate`, `create`, `mkdir`, `rmdir`,
    `mknod`, `symlink`, `unlink`, `link`, `rename_src`, `rename_dest`,
    `file_lock`, `file_mmap`, `exec`, `change_profile`, `change_onexec`,
    `change_hat`, or `file_perm` for a check that is none of those.
*   `name=` is the path, and `target=` the second one an operation has: the file
    a link points at, or the profile an exec or `change_profile` moves to.
*   `requested_mask=` and `denied_mask=` are permission characters.
*   `fsuid=` is the accessing task's UID, which `owner` rules compare against,
    and `ouid=` the file's owner. A denial of an `owner` rule is the case where
    the two differ.
*   `error=` is the negated errno the syscall returned, which `error=` in the
    profile's flags can change.

`pid=` and `comm=` are absent, since the engine is reached with a task's
credentials rather than the task.

### Entering a profile

The container's initial process starts in the profile the OCI spec names
(`spec.Process.apparmorProfile`, which is what a Kubernetes
`container.apparmor.security.beta.kubernetes.io` annotation or `securityContext`
sets), provided the loaded policy defines that profile. If the spec names no
profile, or names one the policy does not define, the process starts unconfined
and the reason is logged; confining a process in a profile with no rules would
deny every access it makes. A process exec'd into a running container starts in
the same profile as that container's initial process, so `kubectl exec` is not a
way around it.

From there an application enters a different profile in any of the ways it would
on a host kernel:

*   **`aa_change_profile(3)`**, which writes `changeprofile <name>` to
    `/proc/self/attr/current`. Apache's `suexec`, for instance, calls this
    before `execve` so each CGI process is confined. The Sentry implements this
    interface; as in Linux, a task may only write its own attributes, and the
    target must be one the current profile's `change_profile` rules permit. A
    `deny change_profile` rule refuses a target the profile would otherwise
    allow, and a rule carrying an exec condition
    (`change_profile /bin/foo -> bar`) permits the target only on exec of a
    matching path, not on a bare `changeprofile` write.

*   **`aa_change_onexec(3)`** (`stack`- and `exec`-prefixed writes to
    `/proc/self/attr/exec`), which arms a transition that takes effect at the
    next `execve` instead of immediately. The target is checked against the
    `change_profile` rules when it is armed and again when it is applied.

*   **`aa_change_hat(3)`**, which writes `changehat <token>^<hat>` to
    `/proc/self/attr/current` and enters a hat declared in the current profile
    (`^upload { ... }`). Writing the same magic token with an empty hat name
    returns to the profile; a wrong token is a violation, as on a host kernel.
    `aa_change_hatv(3)`'s list of candidate hats is supported, and the first
    one the profile declares is entered.

*   **stacking**, either `aa_change_profile(3)`'s `stack <name>` form or a
    `//&`-joined label. Every profile in a stacked label must permit an access,
    so a stack grants the intersection of its profiles and can only narrow what
    a task may do.

*   **exec**, where the transition is decided by the exec rules of the profile
    in force, as it is on a host kernel:

    | modifier | on exec of a matching path |
    | --- | --- |
    | none (a bare `x`, or `file,`) | enter the profile named after the executable if the policy defines one, otherwise keep the current profile |
    | `ix` | keep the current profile |
    | `px`, `Px` | enter the profile after `->`, or the one named after the executable; the exec fails if it is not defined |
    | `cx`, `Cx` | enter `<current>//<target>`; the exec fails if it is not defined |
    | `ux`, `Ux` | run unconfined |

    Where several rules match, the most specific pattern wins, so a rule for one
    path overrides the catch-all that `file,` produces. The uppercase forms
    (`Px`, `Cx`, `Ux`) scrub the environment, as they do on a host kernel: the
    exec is treated as a privilege-gaining one, so the loader strips
    `LD_PRELOAD` and its siblings the same way it does for a setuid binary.

Confinement is per task and lives in the task's credentials, so it is inherited
across `fork` and preserved across `execve`, including the setuid exec that
`suexec` performs. A confined task can only move along the edges its own profile
defines: the targets of its `change_profile` rules, and the transitions of its
exec rules. The single way to leave confinement is a `ux` or `Ux` exec rule,
which the profile has to ask for explicitly; it is logged when it happens.

A profile may also be attached by the path of the executable that enters it
(`profile /usr/sbin/httpd { ... }`, or the named form
`profile web /usr/sbin/httpd { ... }`), which is how a bare `x` rule finds the
profile to transition into.

### Host or container profiles

`apparmor-policy-source` selects where the profile text is read from. The choice
is a trust decision and therefore belongs to the node operator, not the
workload.

**`host`** reads the profiles from the node's filesystem, normally
`/etc/apparmor.d`. Policy stays under the operator's control, which is the point
of mandatory access control: a compromised image cannot weaken its own
confinement. This is the appropriate default, and it is also the mode to use
when the same profiles are shared with runc workloads on the node.

**`container`** reads the profiles from the container's own filesystem, so that
policy versions with the image, which is convenient when an image knows best how
its own processes should be confined. The trade-off is that the workload supplies
the policy that confines it, so a compromised or malicious image can ship
permissive profiles. Use it only where the image is as trusted as the node.

Policy that cannot be read leaves in-sandbox enforcement off for that container
rather than refusing to run it. An image that ships no policy directory is the
ordinary case, the pod's pause container among them, and a directory that fails
to parse is logged as a warning. A profile the spec names is then not enforced,
which is logged too. This differs from `host`, where a policy directory that
fails to load is fatal: there the operator supplies the policy and a silent
downgrade would hide their mistake, whereas here the image supplies it and can
already ship whatever it likes.

Because a container's filesystem is not reachable until its mount namespace
exists, this policy is read once per container, just before its initial process
runs, rather than once for the sandbox. Several containers may each contribute
profiles, and they are merged: a profile another container has already defined
is kept and the later definition is logged and ignored, so that one container
cannot redefine a profile another is running under. The policy is read with the
credentials that created the mount namespace, so a profile may deny the
container's own processes access to the policy it is derived from.

Note that neither mode depends on host AppArmor: the Sentry enforces the file
rules itself, so `--apparmor-policy-source=host` works on a node whose kernel
has AppArmor disabled, as long as the profile text is readable.

To offer both on one node, define two containerd runtime handlers with different
`ConfigPath` values and expose them as separate RuntimeClasses, so a pod selects
the behavior by the `runtimeClassName` it names, rather than by an annotation it
can set for itself.

### What is mediated

The `file` rule class is supported in both forms: bare `file,` is every access
to every path, and `file /p rw,` is the same rule as `/p rw,`.

Every permission character of the `file` rule class is mediated:

| character | what it permits |
| --- | --- |
| `r` | reading a file, and listing a directory |
| `w` | writing a file, and creating, deleting or renaming a path |
| `a` | appending to a file: an `O_APPEND` open. It is mutually exclusive with `w`, as on a host kernel, so a rule granting `a` does not grant a truncating or seeking write |
| `x` | executing a file, with the transition its modifier selects |
| `m` | mapping a file executably. A read-only or non-executable mapping does not need it, so `m` is what stops a task denied `x` from running a file's contents by mapping them instead |
| `l` | linking, as a link and target pair. `l` on the link is required, then a link rule naming the pair, and if that rule carries the `subset` condition, the link's permissions must be a subset of the target's. A bare `l` is itself such a rule, with subset implied and a target of `/**`, which is the equivalence the man page gives |
| `k` | locking, checked on `flock` and POSIX record locks |

The `owner` conditional restricts a rule to files whose UID matches the task's,
`deny` refuses what a broader rule would allow, and `audit` logs what a rule
permits.

Which permission an operation asks for follows Linux's own hooks:

| operation | permission |
| --- | --- |
| open | `r`, `w`, `x`, `m` as the flags ask for; `a` in place of `w` for `O_APPEND`, and `w` again for `O_TRUNC` |
| create, delete, rename | `w` on the entry's own path, not on the directory holding it. This includes creating a file with `O_CREAT`, which asks for `w` on the file being created |
| `chmod`, `chown`, `truncate`, `utimes` | `w`, which is what grants `AA_MAY_SETATTR`, `AA_MAY_CHMOD` and `AA_MAY_CHOWN` |
| `flock`, POSIX locks | `k` |
| executable `mmap`, and `mprotect` adding `PROT_EXEC` to a file mapping | `m`. A task cannot map a file without `PROT_EXEC`, needing no `m`, and then `mprotect` its contents executable |
| hard link | `l` on the new link, plus a link rule for the pair. Note `l` and not `w`: a profile grants a link by naming it in a link rule, not by making the path writable |

#### Pattern matching

Patterns are matched as `apparmor_parser` compiles them, not as the prose in
apparmor.d(5) reads. Three of its rules are easy to get wrong, and each one was:

*   A wildcard that is a **whole path component** matches at least one
    character. `apparmor_parser` compiles `/dir/*` to
    `/dir/[^/\x00][^/\x00]*` and `/dir/**` to `/dir/[^/\x00][^\x00]*`, so
    neither covers `/dir/` itself, and `/dir/**` does not match `/dir//sub`. A
    rule for the directory is written with the trailing slash.
*   A wildcard that is **part** of a component may match nothing: `*.php`
    compiles to `[^/\x00]*\.php`, which matches `.php`.
*   A wildcard **inside a brace alternation** is bare, with no minimum, wherever
    it sits: `/dir/{,**}` compiles to `/dir/(|[^\x00]*)`.
*   A **character class matches `/`**. Only `?` and `*` are confined to one
    component; `[^b]` compiles to `[^b]`, with no separator exclusion. This
    matters most in a deny rule: `deny @{PROC}/{[^1-9],[^1-9][^0-9][^0-9][^0-9]*}/** w`
    relies on a negated class spanning components, and a class that refused `/`
    would deny less than a host kernel does.

These are not asserted from reading; they are checked against the parser itself.
`pkg/sentry/confine/testdata/aare_reference.tsv` and
`runsc/boot/testdata/apparmor_reference.tsv` hold, for each pattern of a real
multi-tenant profile set, the regexp `apparmor_parser` compiles it to, captured
with:

```
apparmor_parser -QT --dump=rule-exprs <profile>
```

The tests over that data compare both the rule walk and the compiled automaton
against those regexps over a derived path corpus, including the empty-wildcard
case. Regenerate the data the same way when adding patterns; a disagreement means
a rule covers a different set of paths here than it does on a host kernel.

`access(2)` and `readlink(2)` are not in that table because Linux's AppArmor
does not hook them: it registers no `inode_permission`, `inode_readlink` or
`path_readlink` hook, so neither is a mediated operation, and requiring a
permission for either would deny what a host kernel permits. Reading a symlink
is therefore not mediated; the access it leads to is.

`stat(2)` and `lstat(2)` are not mediated either, and that is a deliberate
finding rather than an oversight. Linux registers an `inode_getattr` hook, so the
code exists to mediate them, but a real kernel does not deny a stat of a path
that no rule in the profile matches: with a production profile whose 487 compiled
rules contain nothing for the path,

```
aa-exec -p cageweb -- stat /var/www/vhosts/s/t/<site>
```

succeeds and audits nothing, and that profile has run for fifteen years without
producing such a denial. Mediating it here denied what a host kernel permits,
which broke a live workload; the mechanism by which the kernel permits it has not
been located in the source, so this is recorded as an unexplained difference
rather than a claim. If you need it, establish first what a host kernel actually
does with your profile.

A profile that wants to silence expected denials of the operations that *are*
mediated does it the way AppArmor intends, with a deny rule, which denies
"without logging":

```
  deny @{WWW_DIRS}/?/?/?* r,
  deny @{WWW_DIRS}/?/?/?*/ r,
```

Note `?*` rather than `*`: AARE's `*` matches the empty string too, so
`deny <dir>/* r,` also denies `<dir>` itself and breaks the listing the rule was
meant to keep working. The second rule is for the directory form of the path,
since a directory is matched with a trailing slash.

A directory is matched with a trailing slash, as AppArmor does it: "when
AppArmor looks up a directory the pathname being looked up will end with a
slash", so `mkdir /srv/x` is mediated as `/srv/x/` and only a rule ending in a
slash matches it.

Enforcement covers the mounts the Sentry serves from a Gofer, the overlays
layered on them, `erofs` image mounts, and `tmpfs` mounts.

That includes the
container's root filesystem, whether it is a Gofer mount, an overlay over one,
or an EROFS image, which is where a setuid binary shipped in the image would
live.

A `tmpfs` or `erofs` filesystem is only mediated when whoever mounted it said
where it is mounted. The mounts a container asks for always carry that path; the
ones the kernel creates for its own use do not, because no application can name
them. The SysV shared memory mount and the files backing shared anonymous
mappings are of the second kind, and are not mediated: there is no path for a
rule to match, and a fabricated one would match rules meant for unrelated
files.

### What is not supported

Everything below is a real gap, not a design choice. A profile that relies on
one of these is weaker under gVisor than it is under runc, so check your
profiles against this list.

**Filesystems with no enforcement.** `/proc` and `/sys` (kernfs), `devtmpfs`,
`devpts`, `cgroupfs` and the rest are not mediated, and a rule naming a path on
one of them has no effect. Their permission checks hang off the inode, which has
no path to match a rule against. In practice the DAC mode bits still apply, and
gVisor's `/proc` and `/sys` expose far less than a host kernel's; `hidepid` is
the setting that limits what a user sees of other processes.

**Operations.** Three of the hooks Linux registers have no counterpart here:

*   `file_permission`, which re-checks a read or write through an already-open
    file description when the task's label has changed since the open. A task
    that changes profile therefore keeps the file descriptions it opened under
    the old one.
*   `file_receive`, which mediates a file description passed over a unix socket
    against the receiving profile.
Extended attributes are *not* in that list: Linux's AppArmor registers no
`inode_getxattr`, `inode_setxattr`, `inode_listxattr` or `inode_removexattr`
hook, so leaving them unmediated is what a host kernel does.

**Rule classes.** Only `file` rules, `link` rules and `change_profile` are
derived from a profile. `network`, `capability`, `mount`, `umount`,
`pivot_root`, `ptrace`, `signal`, `unix`, `dbus`, `rlimit` and `userns` rules
are not enforced in-sandbox; they are logged at startup and must be enforced on
the Sentry and Gofer with `--host-apparmor`. `abi` declarations are ignored, and
a rule that spans several lines (`dbus` rules typically do) has each of its
lines reported separately.

**Profile flags.** `prompt`, `attach_disconnected`, `attach_disconnected.path=`,
`mediate_deleted`, `chroot_relative`, `debug` and `interruptible` are accepted
and ignored. The path ones do not translate: the Sentry builds the path from the
dentry chain rather than from a host `d_path` call, so the conditions those
flags exist to handle do not arise the same way. `prompt` has no counterpart
because there is no userspace agent inside the sandbox to answer a prompt, and
it degrades to `enforce` rather than to `complain`.

**Scoping.** Every profile in the policy directory is loaded into one set shared
by the whole sandbox, and with `--apparmor-policy-source=container` the sets of
every container are merged into it. The set is not scoped to what a given
container can reach, so a task may change to any profile its `change_profile`
rules match, including one a different container in the pod contributed.

**Auditing.** Records go where `--apparmor-audit-target` says rather than to the
host audit subsystem, so `dmesg | grep DENIED` will not show them and neither
will `aa-notify`, which reads the audit socket. They carry no `pid` or `comm`
field: the engine is reached with the accessing task's credentials rather than
the task itself.

### Differences from host AppArmor

These are behaviors that differ but are not gaps.

*   Directory traversal is not mediated, matching AppArmor: access to a path
    follows from a rule matching that path, not from rules for its ancestors.
    Listing a directory is a read and is mediated.
*   Listing a directory a profile allows reading shows the *names* of other
    users' files within it even when an `owner` rule denies their contents. An
    `owner` rule on a host kernel also hides the names.
*   A profile that names a path the policy does not define cannot be entered,
    and a task somehow in an undefined profile is denied every access, rather
    than being treated as unconfined.
*   A rule outside any profile is not enforced, since it belongs to no profile;
    it is recorded and logged like any other unenforced line. Child profiles
    nested in a profile are parsed, and rules after a child's closing brace
    belong to the parent again, but a child profile is entered only by naming it
    in a `change_profile` rule, not by AppArmor's `//` naming.
