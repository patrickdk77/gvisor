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

A profile declared `flags=(complain)` logs what it would have denied and permits
it, as it does on a host kernel, so a profile can be developed against a real
workload before it is switched to enforcing.

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

From there an application enters a different profile in either of the two ways
it would on a host kernel:

*   **`aa_change_profile(3)`**, which writes `changeprofile <name>` to
    `/proc/self/attr/current`. Apache's `suexec`, for instance, calls this
    before `execve` so each CGI process is confined. The Sentry implements this
    interface; as in Linux, a task may only write its own attributes, and the
    target must be one the current profile's `change_profile` rules permit.

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
    path overrides the catch-all that `file,` produces. `Px` and `Cx` also scrub
    the environment on a host kernel; that is not distinguished here.

Confinement is per task and lives in the task's credentials, so it is inherited
across `fork` and preserved across `execve`, including the setuid exec that
`suexec` performs. A confined task can only move along the edges its own profile
defines: the targets of its `change_profile` rules, and the transitions of its
exec rules. The single way to leave confinement is a `ux` or `Ux` exec rule,
which the profile has to ask for explicitly; it is logged when it happens.

`aa_change_onexec(3)` (`/proc/self/attr/exec`) is not implemented; writes fail
with `EOPNOTSUPP` rather than leaving the task silently unconfined.

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

Of the permission characters, `r`, `w` and `x` are mediated on file accesses,
and `m` is mediated on executable mappings, so that a task denied `x` on a file
it can write cannot run the file's contents by mapping them instead. `a` is
accepted and, as on a host kernel, is implied by `w`, but an append-only rule is
not distinguished from a writable one.

Enforcement covers the mounts the Sentry serves from a Gofer, the overlays
layered on them, `erofs` image mounts, and `tmpfs` mounts. That includes the
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

**Permissions.** `l` and `k` are parsed and ignored: creating a link still
requires `w` on the containing directory, and locking still requires the access
the file was opened with. `a` does not restrict a rule to appending.

**Operations.** Extended attributes are not mediated, so `SetXattrAt` and its
siblings ignore the profile entirely. Deleting or renaming a file is mediated by
`w` on its *directory*, not by a rule on the file's own path as AppArmor does,
so a profile that grants `w` on a directory but not on a file within it will
still permit that file's removal.

**Rule classes.** Only file rules and `change_profile` are derived from a
profile. `network`, `capability`, `mount`, `umount`, `pivot_root`, `ptrace`,
`signal`, `unix`, `dbus` and `rlimit` rules are not enforced in-sandbox; they
are logged at startup and must be enforced on the Sentry and Gofer with
`--host-apparmor`. `abi` declarations are ignored, and a rule that spans several
lines (`dbus` rules typically do) has each of its lines reported separately. A
`deny change_profile` rule carrying an exec condition
(`deny change_profile /bin/foo -> bar`) is reported as unenforced rather than
applied to every exec, which would deny more than the profile says.

**Profile flags.** Only `complain` is acted on. `attach_disconnected`,
`mediate_deleted`, `chroot_relative` and the rest are accepted and ignored,
because the Sentry builds the path from the dentry chain rather than from a host
`d_path` call, so the conditions those flags exist to handle do not arise the
same way.

**Transitions.** Profile stacking, hats (`change_hat`), `aa_change_onexec(3)`,
and named profile attachment (`profile foo /path { ... }`, as opposed to
`profile /path { ... }`) are not implemented. The environment is not scrubbed for
`Px` or `Cx`.

**Scoping.** Every profile in the policy directory is loaded into one set shared
by the whole sandbox, and with `--apparmor-policy-source=container` the sets of
every container are merged into it. The set is not scoped to what a given
container can reach, so a task may change to any profile its `change_profile`
rules match, including one a different container in the pod contributed.

**Auditing.** Denials are logged to the sandbox log, not to the host audit
subsystem, so `dmesg | grep DENIED` will not show them and neither will
`aa-notify`. The `audit` qualifier on a rule is accepted and has no additional
effect.

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
